package protobuf

import (
	"errors"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Product(value domain.Product) (*productv1.Product, error) {
	attributes, err := structpb.NewStruct(map[string]any(value.Attributes))
	if err != nil {
		return nil, err
	}
	return &productv1.Product{
		Id: value.ID, Name: value.Name, Description: value.Description, Brand: value.Brand,
		ManufacturerPartNumber: value.ManufacturerPartNumber, Status: string(value.Status),
		Attributes: attributes, CreatedAt: timestamppb.New(value.CreatedAt),
		UpdatedAt: timestamppb.New(value.UpdatedAt), Version: value.Version,
	}, nil
}

func SKU(value domain.SKU) (*productv1.SKU, error) {
	attributes, err := structpb.NewStruct(map[string]any(value.Attributes))
	if err != nil {
		return nil, err
	}
	return &productv1.SKU{
		Id: value.ID, ProductId: value.ProductID, Code: value.Code, Gtin: value.GTIN,
		Status: string(value.Status), OptionValues: cloneStrings(value.OptionValues),
		Attributes: attributes, CreatedAt: timestamppb.New(value.CreatedAt),
		UpdatedAt: timestamppb.New(value.UpdatedAt), Version: value.Version,
	}, nil
}

func Attributes(value *structpb.Struct) domain.AttributeMap {
	if value == nil {
		return domain.AttributeMap{}
	}
	return domain.AttributeMap(value.AsMap())
}

type EventEncoder struct{}

func (EventEncoder) Encode(event application.OutboxEvent) ([]byte, error) {
	envelope := &productv1.EventEnvelope{
		EventId: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		OccurredAtUtc: timestamppb.New(event.OccurredAtUTC), Producer: event.Producer,
		AggregateType: event.AggregateType, AggregateId: event.AggregateID,
		CorrelationId: event.CorrelationID, CausationId: event.CausationID, HomeSite: event.HomeSite,
	}
	switch {
	case event.Product != nil && event.SKU == nil:
		product, err := Product(*event.Product)
		if err != nil {
			return nil, err
		}
		envelope.Payload = &productv1.EventEnvelope_ProductChanged{
			ProductChanged: &productv1.ProductChanged{Product: product},
		}
	case event.SKU != nil && event.Product == nil:
		sku, err := SKU(*event.SKU)
		if err != nil {
			return nil, err
		}
		envelope.Payload = &productv1.EventEnvelope_SkuChanged{
			SkuChanged: &productv1.SKUChanged{Sku: sku},
		}
	default:
		return nil, errors.New("outbox event must contain exactly one payload")
	}
	return proto.Marshal(envelope)
}

func cloneStrings(input map[string]string) map[string]string {
	if input == nil {
		return map[string]string{}
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
