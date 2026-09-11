package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

type App struct {
	Name  string
	Admin bool
}
type page struct {
	Title, Name, Body string
	Admin             bool
}

var layout = template.Must(template.New("layout").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}} · {{.Name}}</title><link rel="stylesheet" href="/assets/site.css"><script defer src="/assets/htmx.min.js"></script></head><body><nav><a href="/">{{.Name}}</a>{{if .Admin}}<a href="/products">Products</a><a href="/orders">Orders</a><a href="/stocks">Stocks</a>{{else}}<a href="/catalog">Catalog</a><a href="/cart">Cart</a>{{end}}</nav><main id="content"><h1>{{.Title}}</h1><div class="card">{{.Body}}</div></main></body></html>`))

func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
func (a App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /assets/site.css", asset("text/css; charset=utf-8", css))
	m.HandleFunc("GET /assets/htmx.min.js", asset("text/javascript; charset=utf-8", htmx))
	m.HandleFunc("GET /", a.route)
	m.HandleFunc("GET /catalog", a.route)
	m.HandleFunc("GET /products/{id}", a.route)
	m.HandleFunc("POST /cart/items", a.route)
	m.HandleFunc("GET /cart", a.route)
	m.HandleFunc("GET /products", a.route)
	m.HandleFunc("POST /products/{id}/stock", a.route)
	m.HandleFunc("GET /orders", a.route)
	m.HandleFunc("GET /stocks", a.route)
	m.HandleFunc("GET /error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	return security(m)
}
func asset(ct, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", ct); fmt.Fprint(w, body) }
}
func (a App) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/products/" {
		http.NotFound(w, r)
		return
	}
	title, body, ok := a.content(p)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method == "POST" {
		if p == "/cart/items" {
			if r.Header.Get("HX-Request") == "true" {
				fmt.Fprint(w, `<aside id="cart-count">1 item</aside>`)
				return
			}
			http.Redirect(w, r, "/cart", http.StatusSeeOther)
			return
		}
		if strings.HasSuffix(p, "/stock") {
			if r.Header.Get("HX-Request") == "true" {
				fmt.Fprint(w, `<span class="stock">Stock updated</span>`)
				return
			}
			http.Redirect(w, r, "/stocks", http.StatusSeeOther)
			return
		}
	}
	if r.Header.Get("HX-Request") == "true" {
		fmt.Fprintf(w, `<section class="card"><h2>%s</h2><p>%s</p></section>`, template.HTMLEscapeString(title), template.HTMLEscapeString(body))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = layout.Execute(w, page{title, a.Name, body, a.Admin})
}
func (a App) content(p string) (string, string, bool) {
	if a.Admin {
		switch p {
		case "/":
			return "Dashboard", "Operations overview", true
		case "/products":
			return "Products", "Manage catalog products", true
		case "/orders":
			return "Orders", "Manage customer orders", true
		case "/stocks":
			return "Stocks", "Manage inventory levels", true
		}
		if strings.HasPrefix(p, "/products/") && strings.HasSuffix(p, "/stock") {
			return "Stock", "Update inventory", true
		}
		return "", "", false
	}
	switch {
	case p == "/":
		return "Welcome", "Discover the storefront", true
	case p == "/catalog":
		return "Catalog", "Browse products", true
	case strings.HasPrefix(p, "/products/"):
		return "Product", "Product details", true
	case p == "/cart" || p == "/cart/items":
		return "Cart", "Your shopping cart", true
	}
	return "", "", false
}
