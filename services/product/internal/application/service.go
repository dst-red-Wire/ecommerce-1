package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrPrecondition       = errors.New("precondition failed")
	ErrValidation         = errors.New("validation failed")
	ErrInvalidCursor      = errors.New("invalid cursor")
	ErrInvalidIdempotency = errors.New("invalid idempotency key")
)

type Repository interface {
	CreateProduct(context.Context, domain.Product) error
	GetProduct(context.Context, string) (domain.Product, error)
	UpdateProduct(context.Context, domain.Product, int64) (domain.Product, error)
	ListProducts(context.Context, *domain.ProductStatus, int, int) ([]domain.Product, bool, error)
	CreateSKU(context.Context, domain.SKU) error
	GetSKU(context.Context, string, string) (domain.SKU, error)
	UpdateSKU(context.Context, domain.SKU, int64) (domain.SKU, error)
	ListSKUs(context.Context, string, int, int) ([]domain.SKU, bool, error)
}

type CommandResult struct {
	Fingerprint string
	Product     *domain.Product
	SKU         *domain.SKU
}

type CommandJournal interface {
	Load(context.Context, string) (CommandResult, bool, error)
	Save(context.Context, string, CommandResult) error
}

type CreateProductInput struct {
	Name                   string
	Description            string
	Brand                  string
	ManufacturerPartNumber string
	Status                 *domain.ProductStatus
	Attributes             domain.AttributeMap
}

type UpdateProductInput struct {
	Name                   *string
	Description            *string
	Brand                  *string
	ManufacturerPartNumber *string
	Status                 *domain.ProductStatus
	Attributes             domain.AttributeMap
}

type CreateSKUInput struct {
	Code         string
	GTIN         string
	Status       *domain.SKUStatus
	OptionValues map[string]string
	Attributes   domain.AttributeMap
}

type UpdateSKUInput struct {
	Code         *string
	GTIN         *string
	Status       *domain.SKUStatus
	OptionValues map[string]string
	Attributes   domain.AttributeMap
}

type Service struct {
	repo    Repository
	journal CommandJournal
	now     func() time.Time
	newID   func() string
}

func NewService(repo Repository, journal CommandJournal) *Service {
	return &Service{repo: repo, journal: journal, now: func() time.Time { return time.Now().UTC() }, newID: newUUID}
}

func ETag(version int64) string { return fmt.Sprintf("\"v%d\"", version) }

func (s *Service) ListProducts(ctx context.Context, status *domain.ProductStatus, offset, limit int) ([]domain.Product, bool, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, false, ErrValidation
	}
	return s.repo.ListProducts(ctx, status, offset, limit)
}

func (s *Service) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	return s.repo.GetProduct(ctx, id)
}

func (s *Service) CreateProduct(ctx context.Context, key string, in CreateProductInput) (domain.Product, bool, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return domain.Product{}, false, err
	}
	if err := validateCreateProduct(in); err != nil {
		return domain.Product{}, false, err
	}
	fingerprint := hash(in)
	journalKey := "product:create:" + key
	if previous, ok, err := s.journal.Load(ctx, journalKey); err != nil {
		return domain.Product{}, false, err
	} else if ok {
		if previous.Fingerprint != fingerprint || previous.Product == nil {
			return domain.Product{}, false, ErrConflict
		}
		return *previous.Product, true, nil
	}

	now := s.now()
	status := domain.ProductStatusDraft
	if in.Status != nil {
		status = *in.Status
	}
	product := domain.Product{
		ID:                     s.newID(),
		Name:                   strings.TrimSpace(in.Name),
		Description:            in.Description,
		Brand:                  in.Brand,
		ManufacturerPartNumber: in.ManufacturerPartNumber,
		Status:                 status,
		Attributes:             copyAttributes(in.Attributes),
		CreatedAt:              now,
		UpdatedAt:              now,
		Version:                1,
	}
	if err := s.repo.CreateProduct(ctx, product); err != nil {
		return domain.Product{}, false, err
	}
	if err := s.journal.Save(ctx, journalKey, CommandResult{Fingerprint: fingerprint, Product: &product}); err != nil {
		return domain.Product{}, false, err
	}
	return product, false, nil
}

func (s *Service) UpdateProduct(ctx context.Context, id, key, ifMatch string, in UpdateProductInput) (domain.Product, bool, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return domain.Product{}, false, err
	}
	if err := validateUpdateProduct(in); err != nil {
		return domain.Product{}, false, err
	}
	fingerprint := hash(struct {
		ID      string
		IfMatch string
		Input   UpdateProductInput
	}{id, ifMatch, in})
	journalKey := "product:update:" + id + ":" + key
	if previous, ok, err := s.journal.Load(ctx, journalKey); err != nil {
		return domain.Product{}, false, err
	} else if ok {
		if previous.Fingerprint != fingerprint || previous.Product == nil {
			return domain.Product{}, false, ErrConflict
		}
		return *previous.Product, true, nil
	}

	current, err := s.repo.GetProduct(ctx, id)
	if err != nil {
		return domain.Product{}, false, err
	}
	if ifMatch != ETag(current.Version) {
		return domain.Product{}, false, ErrPrecondition
	}
	applyProductUpdate(&current, in)
	current.UpdatedAt = s.now()
	current.Version++
	updated, err := s.repo.UpdateProduct(ctx, current, current.Version-1)
	if err != nil {
		return domain.Product{}, false, err
	}
	if err := s.journal.Save(ctx, journalKey, CommandResult{Fingerprint: fingerprint, Product: &updated}); err != nil {
		return domain.Product{}, false, err
	}
	return updated, false, nil
}

func (s *Service) ListSKUs(ctx context.Context, productID string, offset, limit int) ([]domain.SKU, bool, error) {
	if _, err := s.repo.GetProduct(ctx, productID); err != nil {
		return nil, false, err
	}
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, false, ErrValidation
	}
	return s.repo.ListSKUs(ctx, productID, offset, limit)
}

func (s *Service) GetSKU(ctx context.Context, productID, skuID string) (domain.SKU, error) {
	return s.repo.GetSKU(ctx, productID, skuID)
}

func (s *Service) CreateSKU(ctx context.Context, productID, key string, in CreateSKUInput) (domain.SKU, bool, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return domain.SKU{}, false, err
	}
	if err := validateCreateSKU(in); err != nil {
		return domain.SKU{}, false, err
	}
	if _, err := s.repo.GetProduct(ctx, productID); err != nil {
		return domain.SKU{}, false, err
	}
	fingerprint := hash(in)
	journalKey := "sku:create:" + productID + ":" + key
	if previous, ok, err := s.journal.Load(ctx, journalKey); err != nil {
		return domain.SKU{}, false, err
	} else if ok {
		if previous.Fingerprint != fingerprint || previous.SKU == nil {
			return domain.SKU{}, false, ErrConflict
		}
		return *previous.SKU, true, nil
	}

	now := s.now()
	status := domain.SKUStatusActive
	if in.Status != nil {
		status = *in.Status
	}
	sku := domain.SKU{
		ID:           s.newID(),
		ProductID:    productID,
		Code:         strings.TrimSpace(in.Code),
		GTIN:         in.GTIN,
		Status:       status,
		OptionValues: copyStrings(in.OptionValues),
		Attributes:   copyAttributes(in.Attributes),
		CreatedAt:    now,
		UpdatedAt:    now,
		Version:      1,
	}
	if err := s.repo.CreateSKU(ctx, sku); err != nil {
		return domain.SKU{}, false, err
	}
	if err := s.journal.Save(ctx, journalKey, CommandResult{Fingerprint: fingerprint, SKU: &sku}); err != nil {
		return domain.SKU{}, false, err
	}
	return sku, false, nil
}

func (s *Service) UpdateSKU(ctx context.Context, productID, skuID, key, ifMatch string, in UpdateSKUInput) (domain.SKU, bool, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return domain.SKU{}, false, err
	}
	if err := validateUpdateSKU(in); err != nil {
		return domain.SKU{}, false, err
	}
	fingerprint := hash(struct {
		ProductID string
		SKUID     string
		IfMatch   string
		Input     UpdateSKUInput
	}{productID, skuID, ifMatch, in})
	journalKey := "sku:update:" + productID + ":" + skuID + ":" + key
	if previous, ok, err := s.journal.Load(ctx, journalKey); err != nil {
		return domain.SKU{}, false, err
	} else if ok {
		if previous.Fingerprint != fingerprint || previous.SKU == nil {
			return domain.SKU{}, false, ErrConflict
		}
		return *previous.SKU, true, nil
	}

	current, err := s.repo.GetSKU(ctx, productID, skuID)
	if err != nil {
		return domain.SKU{}, false, err
	}
	if ifMatch != ETag(current.Version) {
		return domain.SKU{}, false, ErrPrecondition
	}
	applySKUUpdate(&current, in)
	current.UpdatedAt = s.now()
	current.Version++
	updated, err := s.repo.UpdateSKU(ctx, current, current.Version-1)
	if err != nil {
		return domain.SKU{}, false, err
	}
	if err := s.journal.Save(ctx, journalKey, CommandResult{Fingerprint: fingerprint, SKU: &updated}); err != nil {
		return domain.SKU{}, false, err
	}
	return updated, false, nil
}

func validateIdempotencyKey(key string) error {
	if n := len(strings.TrimSpace(key)); n < 8 || n > 128 {
		return ErrInvalidIdempotency
	}
	return nil
}

func validateCreateProduct(in CreateProductInput) error {
	if n := len(strings.TrimSpace(in.Name)); n < 1 || n > 200 {
		return ErrValidation
	}
	if len(in.Description) > 10000 || len(in.Brand) > 200 || len(in.ManufacturerPartNumber) > 200 {
		return ErrValidation
	}
	if in.Status != nil && !validProductStatus(*in.Status) {
		return ErrValidation
	}
	return nil
}

func validateUpdateProduct(in UpdateProductInput) error {
	if in.Name == nil && in.Description == nil && in.Brand == nil && in.ManufacturerPartNumber == nil && in.Status == nil && in.Attributes == nil {
		return ErrValidation
	}
	if in.Name != nil {
		if n := len(strings.TrimSpace(*in.Name)); n < 1 || n > 200 {
			return ErrValidation
		}
	}
	if in.Description != nil && len(*in.Description) > 10000 {
		return ErrValidation
	}
	if in.Brand != nil && len(*in.Brand) > 200 {
		return ErrValidation
	}
	if in.ManufacturerPartNumber != nil && len(*in.ManufacturerPartNumber) > 200 {
		return ErrValidation
	}
	if in.Status != nil && !validProductStatus(*in.Status) {
		return ErrValidation
	}
	return nil
}

func validateCreateSKU(in CreateSKUInput) error {
	if n := len(strings.TrimSpace(in.Code)); n < 1 || n > 100 {
		return ErrValidation
	}
	if in.GTIN != "" && !validGTIN(in.GTIN) {
		return ErrValidation
	}
	if in.Status != nil && !validSKUStatus(*in.Status) {
		return ErrValidation
	}
	return nil
}

func validateUpdateSKU(in UpdateSKUInput) error {
	if in.Code == nil && in.GTIN == nil && in.Status == nil && in.OptionValues == nil && in.Attributes == nil {
		return ErrValidation
	}
	if in.Code != nil {
		if n := len(strings.TrimSpace(*in.Code)); n < 1 || n > 100 {
			return ErrValidation
		}
	}
	if in.GTIN != nil && *in.GTIN != "" && !validGTIN(*in.GTIN) {
		return ErrValidation
	}
	if in.Status != nil && !validSKUStatus(*in.Status) {
		return ErrValidation
	}
	return nil
}

func validProductStatus(v domain.ProductStatus) bool {
	return v == domain.ProductStatusDraft || v == domain.ProductStatusActive || v == domain.ProductStatusArchived
}

func validSKUStatus(v domain.SKUStatus) bool {
	return v == domain.SKUStatusActive || v == domain.SKUStatusInactive || v == domain.SKUStatusArchived
}

func validGTIN(value string) bool {
	if len(value) < 8 || len(value) > 14 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func applyProductUpdate(p *domain.Product, in UpdateProductInput) {
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	if in.Brand != nil {
		p.Brand = *in.Brand
	}
	if in.ManufacturerPartNumber != nil {
		p.ManufacturerPartNumber = *in.ManufacturerPartNumber
	}
	if in.Status != nil {
		p.Status = *in.Status
	}
	if in.Attributes != nil {
		p.Attributes = copyAttributes(in.Attributes)
	}
}

func applySKUUpdate(sku *domain.SKU, in UpdateSKUInput) {
	if in.Code != nil {
		sku.Code = strings.TrimSpace(*in.Code)
	}
	if in.GTIN != nil {
		sku.GTIN = *in.GTIN
	}
	if in.Status != nil {
		sku.Status = *in.Status
	}
	if in.OptionValues != nil {
		sku.OptionValues = copyStrings(in.OptionValues)
	}
	if in.Attributes != nil {
		sku.Attributes = copyAttributes(in.Attributes)
	}
}

func hash(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func copyAttributes(in domain.AttributeMap) domain.AttributeMap {
	if in == nil {
		return domain.AttributeMap{}
	}
	out := make(domain.AttributeMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStrings(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
