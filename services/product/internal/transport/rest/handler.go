package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/application"
	"github.com/dst-red-Wire/ecommerce-1/services/product/internal/domain"
)

type Readiness func(context.Context) error

type Handler struct {
	service   *application.Service
	readiness Readiness
}

func NewHandler(service *application.Service) *Handler {
	return NewHandlerWithReadiness(service, nil)
}

func NewHandlerWithReadiness(service *application.Service, readiness Readiness) *Handler {
	return &Handler{service: service, readiness: readiness}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set("X-Request-ID", requestID)

	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet {
			problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" {
		if r.Method != http.MethodGet {
			problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
			return
		}
		if h.readiness != nil && h.readiness(r.Context()) != nil {
			problem(w, requestID, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Service unavailable", "")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if !authorized(r) {
		problem(w, requestID, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized", "Bearer token required")
		return
	}

	parts := pathParts(r.URL.Path)
	if len(parts) < 2 || parts[0] != "v1" || parts[1] != "products" {
		problem(w, requestID, http.StatusNotFound, "NOT_FOUND", "Not found", "")
		return
	}

	switch {
	case len(parts) == 2:
		h.products(w, r, requestID)
	case len(parts) == 3:
		h.product(w, r, requestID, parts[2])
	case len(parts) == 4 && parts[3] == "skus":
		h.skus(w, r, requestID, parts[2])
	case len(parts) == 5 && parts[3] == "skus":
		h.sku(w, r, requestID, parts[2], parts[4])
	default:
		problem(w, requestID, http.StatusNotFound, "NOT_FOUND", "Not found", "")
	}
}

func (h *Handler) products(w http.ResponseWriter, r *http.Request, requestID string) {
	switch r.Method {
	case http.MethodGet:
		limit, offset, err := pagination(r)
		if err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_PAGINATION", "Invalid pagination", err.Error())
			return
		}
		var status *domain.ProductStatus
		if raw := r.URL.Query().Get("status"); raw != "" {
			value := domain.ProductStatus(raw)
			if value != domain.ProductStatusDraft && value != domain.ProductStatusActive && value != domain.ProductStatusArchived {
				problem(w, requestID, http.StatusBadRequest, "INVALID_STATUS", "Invalid status", "status must be draft, active, or archived")
				return
			}
			status = &value
		}
		items, more, err := h.service.ListProducts(r.Context(), status, offset, limit)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		response := productListResponse{Items: items}
		if more {
			response.NextCursor = encodeCursor(offset + limit)
		}
		jsonResponse(w, http.StatusOK, response)
	case http.MethodPost:
		var body createProductRequest
		if err := decodeJSON(r, &body); err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON", err.Error())
			return
		}
		product, _, err := h.service.CreateProduct(r.Context(), r.Header.Get("Idempotency-Key"), body.toApplication())
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(product.Version))
		jsonResponse(w, http.StatusCreated, product)
	default:
		problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
	}
}

func (h *Handler) product(w http.ResponseWriter, r *http.Request, requestID, productID string) {
	switch r.Method {
	case http.MethodGet:
		product, err := h.service.GetProduct(r.Context(), productID)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(product.Version))
		jsonResponse(w, http.StatusOK, product)
	case http.MethodPatch:
		var body updateProductRequest
		if err := decodeJSON(r, &body); err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON", err.Error())
			return
		}
		product, _, err := h.service.UpdateProduct(r.Context(), productID, r.Header.Get("Idempotency-Key"), r.Header.Get("If-Match"), body.toApplication())
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(product.Version))
		jsonResponse(w, http.StatusOK, product)
	default:
		problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
	}
}

func (h *Handler) skus(w http.ResponseWriter, r *http.Request, requestID, productID string) {
	switch r.Method {
	case http.MethodGet:
		limit, offset, err := pagination(r)
		if err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_PAGINATION", "Invalid pagination", err.Error())
			return
		}
		items, more, err := h.service.ListSKUs(r.Context(), productID, offset, limit)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		response := skuListResponse{Items: items}
		if more {
			response.NextCursor = encodeCursor(offset + limit)
		}
		jsonResponse(w, http.StatusOK, response)
	case http.MethodPost:
		var body createSKURequest
		if err := decodeJSON(r, &body); err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON", err.Error())
			return
		}
		sku, _, err := h.service.CreateSKU(r.Context(), productID, r.Header.Get("Idempotency-Key"), body.toApplication())
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(sku.Version))
		jsonResponse(w, http.StatusCreated, sku)
	default:
		problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
	}
}

func (h *Handler) sku(w http.ResponseWriter, r *http.Request, requestID, productID, skuID string) {
	switch r.Method {
	case http.MethodGet:
		sku, err := h.service.GetSKU(r.Context(), productID, skuID)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(sku.Version))
		jsonResponse(w, http.StatusOK, sku)
	case http.MethodPatch:
		var body updateSKURequest
		if err := decodeJSON(r, &body); err != nil {
			problem(w, requestID, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON", err.Error())
			return
		}
		sku, _, err := h.service.UpdateSKU(r.Context(), productID, skuID, r.Header.Get("Idempotency-Key"), r.Header.Get("If-Match"), body.toApplication())
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.Header().Set("ETag", application.ETag(sku.Version))
		jsonResponse(w, http.StatusOK, sku)
	default:
		problem(w, requestID, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", "")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, application.ErrNotFound):
		problem(w, requestID, http.StatusNotFound, "NOT_FOUND", "Not found", "")
	case errors.Is(err, application.ErrConflict):
		problem(w, requestID, http.StatusConflict, "CONFLICT", "Conflict", "")
	case errors.Is(err, application.ErrPrecondition):
		problem(w, requestID, http.StatusPreconditionFailed, "PRECONDITION_FAILED", "Precondition failed", "If-Match does not match current version")
	case errors.Is(err, application.ErrInvalidIdempotency):
		problem(w, requestID, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", "Invalid idempotency key", "Idempotency-Key must contain 8 to 128 characters")
	case errors.Is(err, application.ErrValidation):
		problem(w, requestID, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "Validation failed", "")
	default:
		problem(w, requestID, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error", "")
	}
}

type createProductRequest struct {
	Name                   string                `json:"name"`
	Description            string                `json:"description,omitempty"`
	Brand                  string                `json:"brand,omitempty"`
	ManufacturerPartNumber string                `json:"manufacturerPartNumber,omitempty"`
	Status                 *domain.ProductStatus `json:"status,omitempty"`
	Attributes             domain.AttributeMap   `json:"attributes,omitempty"`
}

func (r createProductRequest) toApplication() application.CreateProductInput {
	return application.CreateProductInput{
		Name: r.Name, Description: r.Description, Brand: r.Brand,
		ManufacturerPartNumber: r.ManufacturerPartNumber, Status: r.Status, Attributes: r.Attributes,
	}
}

type updateProductRequest struct {
	Name                   *string               `json:"name,omitempty"`
	Description            *string               `json:"description,omitempty"`
	Brand                  *string               `json:"brand,omitempty"`
	ManufacturerPartNumber *string               `json:"manufacturerPartNumber,omitempty"`
	Status                 *domain.ProductStatus `json:"status,omitempty"`
	Attributes             domain.AttributeMap   `json:"attributes,omitempty"`
}

func (r updateProductRequest) toApplication() application.UpdateProductInput {
	return application.UpdateProductInput{
		Name: r.Name, Description: r.Description, Brand: r.Brand,
		ManufacturerPartNumber: r.ManufacturerPartNumber, Status: r.Status, Attributes: r.Attributes,
	}
}

type createSKURequest struct {
	Code         string              `json:"code"`
	GTIN         string              `json:"gtin,omitempty"`
	Status       *domain.SKUStatus   `json:"status,omitempty"`
	OptionValues map[string]string   `json:"optionValues,omitempty"`
	Attributes   domain.AttributeMap `json:"attributes,omitempty"`
}

func (r createSKURequest) toApplication() application.CreateSKUInput {
	return application.CreateSKUInput{Code: r.Code, GTIN: r.GTIN, Status: r.Status, OptionValues: r.OptionValues, Attributes: r.Attributes}
}

type updateSKURequest struct {
	Code         *string             `json:"code,omitempty"`
	GTIN         *string             `json:"gtin,omitempty"`
	Status       *domain.SKUStatus   `json:"status,omitempty"`
	OptionValues map[string]string   `json:"optionValues,omitempty"`
	Attributes   domain.AttributeMap `json:"attributes,omitempty"`
}

func (r updateSKURequest) toApplication() application.UpdateSKUInput {
	return application.UpdateSKUInput{Code: r.Code, GTIN: r.GTIN, Status: r.Status, OptionValues: r.OptionValues, Attributes: r.Attributes}
}

type productListResponse struct {
	Items      []domain.Product `json:"items"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

type skuListResponse struct {
	Items      []domain.SKU `json:"items"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

type problemBody struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

func problem(w http.ResponseWriter, requestID string, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemBody{Type: "about:blank", Title: title, Status: status, Detail: detail, Code: code, RequestID: requestID})
}

func jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return err
	}
	return nil
}

func pagination(r *http.Request) (int, int, error) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, 0, errors.New("limit must be an integer from 1 to 100")
		}
		limit = parsed
	}
	offset := 0
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return 0, 0, errors.New("cursor is invalid")
		}
		parsed, err := strconv.Atoi(string(decoded))
		if err != nil || parsed < 0 {
			return 0, 0, errors.New("cursor is invalid")
		}
		offset = parsed
	}
	return limit, offset, nil
}

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func pathParts(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func authorized(r *http.Request) bool {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")) != ""
}

func requestID(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		return value
	}
	return fmt.Sprintf("req-%d", requestCounter())
}

var counter atomic.Uint64

func requestCounter() uint64 { return counter.Add(1) }
