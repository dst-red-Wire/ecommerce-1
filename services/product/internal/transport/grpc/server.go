package grpc

import (
	"context"
	"errors"
	"strings"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	productprotobuf "github.com/dst-red-Wire/ecommerce-1/services/product/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type Server struct {
	productv1.UnimplementedProductServiceServer
	service *application.Service
}

func NewServer(service *application.Service) *Server { return &Server{service: service} }

func (s *Server) ListProducts(ctx context.Context, request *productv1.ListProductsRequest) (*productv1.ListProductsResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit := int(request.GetLimit())
	if limit == 0 {
		limit = 20
	}
	var productStatus *domain.ProductStatus
	if request.GetStatus() != "" {
		value := domain.ProductStatus(request.GetStatus())
		productStatus = &value
	}
	items, more, err := s.service.ListProducts(ctx, productStatus, int(request.GetOffset()), limit)
	if err != nil {
		return nil, mapError(err)
	}
	response := &productv1.ListProductsResponse{HasMore: more, Items: make([]*productv1.Product, 0, len(items))}
	for _, item := range items {
		converted, err := productprotobuf.Product(item)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode product")
		}
		response.Items = append(response.Items, converted)
	}
	return response, nil
}

func (s *Server) GetProduct(ctx context.Context, request *productv1.GetProductRequest) (*productv1.GetProductResponse, error) {
	if request == nil || strings.TrimSpace(request.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "product id is required")
	}
	product, err := s.service.GetProduct(ctx, request.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.Product(product)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode product")
	}
	return &productv1.GetProductResponse{Product: converted}, nil
}

func (s *Server) CreateProduct(ctx context.Context, request *productv1.CreateProductRequest) (*productv1.CreateProductResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	var productStatus *domain.ProductStatus
	if request.GetStatus() != "" {
		value := domain.ProductStatus(request.GetStatus())
		productStatus = &value
	}
	product, replayed, err := s.service.CreateProduct(commandContext(ctx), request.GetIdempotencyKey(), application.CreateProductInput{
		Name: request.GetName(), Description: request.GetDescription(), Brand: request.GetBrand(),
		ManufacturerPartNumber: request.GetManufacturerPartNumber(), Status: productStatus,
		Attributes: attributes(request.GetAttributes()),
	})
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.Product(product)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode product")
	}
	return &productv1.CreateProductResponse{Product: converted, Replayed: replayed}, nil
}

func (s *Server) UpdateProduct(ctx context.Context, request *productv1.UpdateProductRequest) (*productv1.UpdateProductResponse, error) {
	if request == nil || strings.TrimSpace(request.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "product id is required")
	}
	var productStatus *domain.ProductStatus
	if request.Status != nil {
		value := domain.ProductStatus(request.GetStatus())
		productStatus = &value
	}
	product, replayed, err := s.service.UpdateProduct(commandContext(ctx), request.GetId(), request.GetIdempotencyKey(), request.GetIfMatch(), application.UpdateProductInput{
		Name: request.Name, Description: request.Description, Brand: request.Brand,
		ManufacturerPartNumber: request.ManufacturerPartNumber, Status: productStatus,
		Attributes: optionalAttributes(request.Attributes),
	})
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.Product(product)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode product")
	}
	return &productv1.UpdateProductResponse{Product: converted, Replayed: replayed}, nil
}

func (s *Server) ListSKUs(ctx context.Context, request *productv1.ListSKUsRequest) (*productv1.ListSKUsResponse, error) {
	if request == nil || strings.TrimSpace(request.GetProductId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "product id is required")
	}
	limit := int(request.GetLimit())
	if limit == 0 {
		limit = 20
	}
	items, more, err := s.service.ListSKUs(ctx, request.GetProductId(), int(request.GetOffset()), limit)
	if err != nil {
		return nil, mapError(err)
	}
	response := &productv1.ListSKUsResponse{HasMore: more, Items: make([]*productv1.SKU, 0, len(items))}
	for _, item := range items {
		converted, err := productprotobuf.SKU(item)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode SKU")
		}
		response.Items = append(response.Items, converted)
	}
	return response, nil
}

func (s *Server) GetSKU(ctx context.Context, request *productv1.GetSKURequest) (*productv1.GetSKUResponse, error) {
	if request == nil || strings.TrimSpace(request.GetProductId()) == "" || strings.TrimSpace(request.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "product id and SKU id are required")
	}
	sku, err := s.service.GetSKU(ctx, request.GetProductId(), request.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.SKU(sku)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode SKU")
	}
	return &productv1.GetSKUResponse{Sku: converted}, nil
}

func (s *Server) CreateSKU(ctx context.Context, request *productv1.CreateSKURequest) (*productv1.CreateSKUResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	var skuStatus *domain.SKUStatus
	if request.GetStatus() != "" {
		value := domain.SKUStatus(request.GetStatus())
		skuStatus = &value
	}
	sku, replayed, err := s.service.CreateSKU(commandContext(ctx), request.GetProductId(), request.GetIdempotencyKey(), application.CreateSKUInput{
		Code: request.GetCode(), GTIN: request.GetGtin(), Status: skuStatus,
		OptionValues: request.GetOptionValues(), Attributes: attributes(request.GetAttributes()),
	})
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.SKU(sku)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode SKU")
	}
	return &productv1.CreateSKUResponse{Sku: converted, Replayed: replayed}, nil
}

func (s *Server) UpdateSKU(ctx context.Context, request *productv1.UpdateSKURequest) (*productv1.UpdateSKUResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	var skuStatus *domain.SKUStatus
	if request.Status != nil {
		value := domain.SKUStatus(request.GetStatus())
		skuStatus = &value
	}
	sku, replayed, err := s.service.UpdateSKU(commandContext(ctx), request.GetProductId(), request.GetId(), request.GetIdempotencyKey(), request.GetIfMatch(), application.UpdateSKUInput{
		Code: request.Code, GTIN: request.Gtin, Status: skuStatus,
		OptionValues: optionalStringMap(request.OptionValues), Attributes: optionalAttributes(request.Attributes),
	})
	if err != nil {
		return nil, mapError(err)
	}
	converted, err := productprotobuf.SKU(sku)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode SKU")
	}
	return &productv1.UpdateSKUResponse{Sku: converted, Replayed: replayed}, nil
}

func commandContext(ctx context.Context) context.Context {
	values, _ := metadata.FromIncomingContext(ctx)
	return application.WithCommandMetadata(ctx, application.CommandMetadata{
		CorrelationID: first(values.Get("x-correlation-id")),
		CausationID:   first(values.Get("x-causation-id")),
	})
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func attributes(value *structpb.Struct) domain.AttributeMap {
	return productprotobuf.Attributes(value)
}

func optionalAttributes(value *structpb.Struct) domain.AttributeMap {
	if value == nil {
		return nil
	}
	return productprotobuf.Attributes(value)
}

func optionalStringMap(value *productv1.StringMap) map[string]string {
	if value == nil {
		return nil
	}
	if value.Values == nil {
		return map[string]string{}
	}
	return value.Values
}

func mapError(err error) error {
	switch {
	case errors.Is(err, application.ErrNotFound):
		return status.Error(codes.NotFound, "resource not found")
	case errors.Is(err, application.ErrConflict):
		return status.Error(codes.AlreadyExists, "command conflicts with existing state")
	case errors.Is(err, application.ErrPrecondition):
		return status.Error(codes.FailedPrecondition, "resource version does not match")
	case errors.Is(err, application.ErrValidation), errors.Is(err, application.ErrInvalidCursor), errors.Is(err, application.ErrInvalidIdempotency), errors.Is(err, application.ErrInvalidID):
		return status.Error(codes.InvalidArgument, "request validation failed")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
