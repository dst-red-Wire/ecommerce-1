package security

import (
	"context"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type tokenAuthorizer interface {
	Authorize(context.Context, string) error
}

var grpcMutationMethods = map[string]struct{}{
	productv1.ProductService_CreateProduct_FullMethodName: {},
	productv1.ProductService_UpdateProduct_FullMethodName: {},
	productv1.ProductService_CreateSKU_FullMethodName:     {},
	productv1.ProductService_UpdateSKU_FullMethodName:     {},
}

// GRPCMutationAuthorizer applies the same OIDC authority as REST writes while
// leaving internal query RPCs available to read-only workloads.
func GRPCMutationAuthorizer(authorizer tokenAuthorizer) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		request any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, mutation := grpcMutationMethods[info.FullMethod]; !mutation {
			return handler(ctx, request)
		}
		values, _ := metadata.FromIncomingContext(ctx)
		if err := authorizer.Authorize(ctx, firstMetadata(values.Get("authorization"))); err != nil {
			return nil, status.Error(codes.Unauthenticated, "valid admin bearer token required")
		}
		return handler(ctx, request)
	}
}

func firstMetadata(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
