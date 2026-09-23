package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/config"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/kafka"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/memory"
	productpostgres "github.com/dst-red-Wire/ecommerce-1/services/product/internal/infrastructure/postgres"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/outbox"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/security"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/telemetry"
	grpctransport "github.com/dst-red-Wire/ecommerce-1/services/product/internal/transport/grpc"
	resttransport "github.com/dst-red-Wire/ecommerce-1/services/product/internal/transport/rest"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("product service stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	runtimeConfig, err := config.Load()
	if err != nil {
		return err
	}
	shutdownTelemetry, err := telemetry.Setup(ctx)
	if err != nil {
		logger.Warn("telemetry initialization failed; business traffic remains enabled")
		shutdownTelemetry = func(context.Context) error { return nil }
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), runtimeConfig.ShutdownTimeout)
		defer cancel()
		if err := shutdownTelemetry(shutdownCtx); err != nil {
			logger.Error("telemetry shutdown failed", "error", err.Error())
		}
	}()

	store, readiness, closeStore, err := persistence(ctx, runtimeConfig)
	if err != nil {
		return err
	}
	defer closeStore()
	service := application.NewServiceWithOptions(store, application.Options{HomeSite: runtimeConfig.HomeSite})

	var applicationHandler http.Handler = resttransport.NewHandlerWithReadiness(service, readiness)
	var oidcAuthorizer *security.OIDCAuthorizer
	if runtimeConfig.Storage == "postgres" {
		authorizer, err := security.NewOIDCAuthorizer(ctx, runtimeConfig.OIDCIssuer, runtimeConfig.OIDCAudience)
		if err != nil {
			return err
		}
		oidcAuthorizer = authorizer
		applicationHandler = resttransport.NewHandlerWithAuthorizer(service, readiness, authorizer)
	}
	restHandler := otelhttp.NewHandler(requestLogger(logger, applicationHandler), "product.http")
	httpServer := &http.Server{
		Addr: runtimeConfig.HTTPAddr, Handler: restHandler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}

	grpcListener, err := net.Listen("tcp", runtimeConfig.GRPCAddr)
	if err != nil {
		return err
	}
	defer grpcListener.Close()
	grpcInterceptors := []googlegrpc.UnaryServerInterceptor{grpcLogger(logger)}
	if oidcAuthorizer != nil {
		grpcInterceptors = append(grpcInterceptors, security.GRPCMutationAuthorizer(oidcAuthorizer))
	}
	grpcServer := googlegrpc.NewServer(
		googlegrpc.StatsHandler(otelgrpc.NewServerHandler()),
		googlegrpc.ChainUnaryInterceptor(grpcInterceptors...),
	)
	productv1.RegisterProductServiceServer(grpcServer, grpctransport.NewServer(service))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("ecommerce.product.v1.ProductService", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	errCh := make(chan error, 3)
	go func() {
		logger.Info("HTTP server listening", "address", runtimeConfig.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("gRPC server listening", "address", runtimeConfig.GRPCAddr)
		if err := grpcServer.Serve(grpcListener); err != nil {
			errCh <- err
		}
	}()

	var closePublisher func()
	if runtimeConfig.Storage == "postgres" {
		producer, err := kafka.New(kafka.Config{
			Brokers: runtimeConfig.KafkaBrokers, Topic: runtimeConfig.KafkaTopic,
			ClientID: runtimeConfig.KafkaClientID, MaxRetries: runtimeConfig.KafkaMaxRetries,
			DeliveryTimeout: runtimeConfig.KafkaDeliveryTime,
			TLSCAFile:       runtimeConfig.KafkaTLSCAFile, TLSCertFile: runtimeConfig.KafkaTLSCertFile,
			TLSKeyFile: runtimeConfig.KafkaTLSKeyFile,
		})
		if err != nil {
			return err
		}
		closePublisher = producer.Close
		worker, err := outbox.NewWorker(store.(*productpostgres.Store), producer, logger, runtimeConfig.Outbox)
		if err != nil {
			producer.Close()
			return err
		}
		go func() {
			if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}
	if closePublisher != nil {
		defer closePublisher()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	healthServer.SetServingStatus("ecommerce.product.v1.ProductService", healthv1.HealthCheckResponse_NOT_SERVING)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), runtimeConfig.ShutdownTimeout)
	defer cancel()
	httpStopped := make(chan error, 1)
	go func() { httpStopped <- httpServer.Shutdown(shutdownCtx) }()
	stopGRPC(shutdownCtx, grpcServer)
	return <-httpStopped
}

type grpcStopper interface {
	GracefulStop()
	Stop()
}

func stopGRPC(ctx context.Context, server grpcStopper) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-ctx.Done():
		server.Stop()
		<-stopped
	}
}

func persistence(ctx context.Context, runtimeConfig config.Config) (application.Store, resttransport.Readiness, func(), error) {
	if runtimeConfig.Storage == "memory" {
		store := memory.NewStore()
		return store, nil, func() {}, nil
	}
	pool, err := pgxpool.New(ctx, runtimeConfig.DatabaseURL)
	if err != nil {
		return nil, nil, func() {}, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, func() {}, err
	}
	store := productpostgres.NewStore(pool)
	return store, store.Ready, pool.Close, nil
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		spanContext := trace.SpanContextFromContext(request.Context())
		logger.InfoContext(request.Context(), "HTTP request completed",
			"method", request.Method, "status", recorder.status, "duration_ms", time.Since(started).Milliseconds(),
			"request_id", recorder.Header().Get("X-Request-ID"), "trace_id", spanContext.TraceID().String(),
			"span_id", spanContext.SpanID().String(),
		)
	})
}

func grpcLogger(logger *slog.Logger) googlegrpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *googlegrpc.UnaryServerInfo, handler googlegrpc.UnaryHandler) (any, error) {
		started := time.Now()
		response, err := handler(ctx, request)
		spanContext := trace.SpanContextFromContext(ctx)
		logger.InfoContext(ctx, "gRPC request completed",
			"method", info.FullMethod, "status", status.Code(err).String(), "duration_ms", time.Since(started).Milliseconds(),
			"trace_id", spanContext.TraceID().String(), "span_id", spanContext.SpanID().String(),
		)
		return response, err
	}
}
