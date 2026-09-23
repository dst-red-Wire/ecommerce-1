package security

import (
	"context"
	"errors"
	"testing"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type stubAuthorizer struct {
	want   string
	called int
}

func (a *stubAuthorizer) Authorize(_ context.Context, authorization string) error {
	a.called++
	if authorization != a.want {
		return errors.New("unauthorized")
	}
	return nil
}

func TestGRPCMutationAuthorizerAllowsQueriesWithoutAdminToken(t *testing.T) {
	authorizer := &stubAuthorizer{want: "Bearer admin"}
	interceptor := GRPCMutationAuthorizer(authorizer)
	called := false
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: productv1.ProductService_GetProduct_FullMethodName,
	}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil || !called || authorizer.called != 0 {
		t.Fatalf("query authorization mismatch: called=%v auth_calls=%d err=%v", called, authorizer.called, err)
	}
}

func TestGRPCMutationAuthorizerRejectsMissingOrInvalidAdminToken(t *testing.T) {
	authorizer := &stubAuthorizer{want: "Bearer admin"}
	interceptor := GRPCMutationAuthorizer(authorizer)
	for _, ctx := range []context.Context{
		context.Background(),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer reader")),
	} {
		called := false
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: productv1.ProductService_CreateProduct_FullMethodName,
		}, func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		})
		if status.Code(err) != codes.Unauthenticated || called {
			t.Fatalf("mutation must fail closed: called=%v err=%v", called, err)
		}
	}
}

func TestGRPCMutationAuthorizerAcceptsAdminToken(t *testing.T) {
	authorizer := &stubAuthorizer{want: "Bearer admin"}
	interceptor := GRPCMutationAuthorizer(authorizer)
	ctx := metadata.NewIncomingContext(
		context.Background(), metadata.Pairs("authorization", "Bearer admin"),
	)
	called := false
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: productv1.ProductService_UpdateProduct_FullMethodName,
	}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil || !called || authorizer.called != 1 {
		t.Fatalf("authorized mutation mismatch: called=%v auth_calls=%d err=%v", called, authorizer.called, err)
	}
}
