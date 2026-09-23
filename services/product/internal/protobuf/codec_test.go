package protobuf_test

import (
	"testing"
	"time"

	productv1 "github.com/dst-red-Wire/ecommerce-1/services/product/api/generated/product/v1"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
	productprotobuf "github.com/dst-red-Wire/ecommerce-1/services/product/internal/protobuf"
	"google.golang.org/protobuf/proto"
)

func TestEventEncoderProducesVersionedEnvelope(t *testing.T) {
	product := domain.Product{ID: "7d9c1df0-dc09-4cc8-bdf7-9e7cebe51480", Name: "Lamp", Status: domain.ProductStatusActive, Attributes: domain.AttributeMap{}, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC(), Version: 1}
	payload, err := (productprotobuf.EventEncoder{}).Encode(application.OutboxEvent{
		ID: "eec10b88-0109-4d2e-8ab3-5955808ef032", Type: "product.ProductCreated.v1", SchemaVersion: 1,
		OccurredAtUTC: time.Unix(1, 0).UTC(), Producer: "product", AggregateType: "product",
		AggregateID: product.ID, CorrelationID: "correlation", CausationID: "cause", HomeSite: "preprod", Product: &product,
	})
	if err != nil {
		t.Fatal(err)
	}
	var envelope productv1.EventEnvelope
	if err := proto.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.GetEventType() != "product.ProductCreated.v1" || envelope.GetProductChanged().GetProduct().GetId() != product.ID {
		t.Fatalf("unexpected envelope: %+v", &envelope)
	}
}
