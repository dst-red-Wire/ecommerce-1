package domain

import "time"

type ProductStatus string

const (
	ProductStatusDraft    ProductStatus = "draft"
	ProductStatusActive   ProductStatus = "active"
	ProductStatusArchived ProductStatus = "archived"
)

type SKUStatus string

const (
	SKUStatusActive   SKUStatus = "active"
	SKUStatusInactive SKUStatus = "inactive"
	SKUStatusArchived SKUStatus = "archived"
)

type AttributeMap map[string]any

type Product struct {
	ID                     string        `json:"id"`
	Name                   string        `json:"name"`
	Description            string        `json:"description,omitempty"`
	Brand                  string        `json:"brand,omitempty"`
	ManufacturerPartNumber string        `json:"manufacturerPartNumber,omitempty"`
	Status                 ProductStatus `json:"status"`
	Attributes             AttributeMap  `json:"attributes"`
	CreatedAt              time.Time     `json:"createdAt"`
	UpdatedAt              time.Time     `json:"updatedAt"`
	Version                int64         `json:"version"`
}

type SKU struct {
	ID           string            `json:"id"`
	ProductID    string            `json:"productId"`
	Code         string            `json:"code"`
	GTIN         string            `json:"gtin,omitempty"`
	Status       SKUStatus         `json:"status"`
	OptionValues map[string]string `json:"optionValues"`
	Attributes   AttributeMap      `json:"attributes"`
	CreatedAt    time.Time         `json:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
	Version      int64             `json:"version"`
}
