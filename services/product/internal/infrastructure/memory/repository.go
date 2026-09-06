package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
)

type Store struct {
	mu       sync.RWMutex
	products map[string]domain.Product
	skus     map[string]domain.SKU
	journal  map[string]application.CommandResult
}

func NewStore() *Store {
	return &Store{
		products: make(map[string]domain.Product),
		skus:     make(map[string]domain.SKU),
		journal:  make(map[string]application.CommandResult),
	}
}

func (s *Store) CreateProduct(_ context.Context, product domain.Product) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.products[product.ID]; exists {
		return application.ErrConflict
	}
	s.products[product.ID] = cloneProduct(product)
	return nil
}

func (s *Store) GetProduct(_ context.Context, id string) (domain.Product, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	product, ok := s.products[id]
	if !ok {
		return domain.Product{}, application.ErrNotFound
	}
	return cloneProduct(product), nil
}

func (s *Store) UpdateProduct(_ context.Context, product domain.Product, expectedVersion int64) (domain.Product, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.products[product.ID]
	if !ok {
		return domain.Product{}, application.ErrNotFound
	}
	if current.Version != expectedVersion {
		return domain.Product{}, application.ErrPrecondition
	}
	s.products[product.ID] = cloneProduct(product)
	return cloneProduct(product), nil
}

func (s *Store) ListProducts(_ context.Context, status *domain.ProductStatus, offset, limit int) ([]domain.Product, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Product, 0, len(s.products))
	for _, product := range s.products {
		if status != nil && product.Status != *status {
			continue
		}
		items = append(items, cloneProduct(product))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if offset >= len(items) {
		return []domain.Product{}, false, nil
	}
	end := offset + limit
	more := false
	if end < len(items) {
		more = true
	} else {
		end = len(items)
	}
	return items[offset:end], more, nil
}

func (s *Store) CreateSKU(_ context.Context, sku domain.SKU) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.skus[sku.ID]; exists {
		return application.ErrConflict
	}
	for _, existing := range s.skus {
		if existing.Code == sku.Code {
			return application.ErrConflict
		}
	}
	s.skus[sku.ID] = cloneSKU(sku)
	return nil
}

func (s *Store) GetSKU(_ context.Context, productID, skuID string) (domain.SKU, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sku, ok := s.skus[skuID]
	if !ok || sku.ProductID != productID {
		return domain.SKU{}, application.ErrNotFound
	}
	return cloneSKU(sku), nil
}

func (s *Store) UpdateSKU(_ context.Context, sku domain.SKU, expectedVersion int64) (domain.SKU, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.skus[sku.ID]
	if !ok || current.ProductID != sku.ProductID {
		return domain.SKU{}, application.ErrNotFound
	}
	if current.Version != expectedVersion {
		return domain.SKU{}, application.ErrPrecondition
	}
	for id, existing := range s.skus {
		if id != sku.ID && existing.Code == sku.Code {
			return domain.SKU{}, application.ErrConflict
		}
	}
	s.skus[sku.ID] = cloneSKU(sku)
	return cloneSKU(sku), nil
}

func (s *Store) ListSKUs(_ context.Context, productID string, offset, limit int) ([]domain.SKU, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.SKU, 0)
	for _, sku := range s.skus {
		if sku.ProductID == productID {
			items = append(items, cloneSKU(sku))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if offset >= len(items) {
		return []domain.SKU{}, false, nil
	}
	end := offset + limit
	more := false
	if end < len(items) {
		more = true
	} else {
		end = len(items)
	}
	return items[offset:end], more, nil
}

func (s *Store) Load(_ context.Context, key string) (application.CommandResult, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, ok := s.journal[key]
	if !ok {
		return application.CommandResult{}, false, nil
	}
	return cloneCommandResult(result), true, nil
}

func (s *Store) Save(_ context.Context, key string, result application.CommandResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, exists := s.journal[key]; exists {
		if previous.Fingerprint != result.Fingerprint {
			return application.ErrConflict
		}
		return nil
	}
	s.journal[key] = cloneCommandResult(result)
	return nil
}

func cloneProduct(in domain.Product) domain.Product {
	out := in
	out.Attributes = cloneAttributes(in.Attributes)
	return out
}

func cloneSKU(in domain.SKU) domain.SKU {
	out := in
	out.Attributes = cloneAttributes(in.Attributes)
	out.OptionValues = make(map[string]string, len(in.OptionValues))
	for key, value := range in.OptionValues {
		out.OptionValues[key] = value
	}
	return out
}

func cloneAttributes(in domain.AttributeMap) domain.AttributeMap {
	out := make(domain.AttributeMap, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneCommandResult(in application.CommandResult) application.CommandResult {
	out := application.CommandResult{Fingerprint: in.Fingerprint}
	if in.Product != nil {
		product := cloneProduct(*in.Product)
		out.Product = &product
	}
	if in.SKU != nil {
		sku := cloneSKU(*in.SKU)
		out.SKU = &sku
	}
	return out
}
