// Package docs serves the OpenAPI spec and a Swagger UI page.
package docs

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var spec []byte

// Swagger UI assets come from a pinned CDN version and are checked with
// Subresource Integrity, so a tampered CDN file is refused by the browser.
const (
	cdnBase   = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/"
	cssSRI    = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"
	bundleSRI = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
)

const page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IAM engine API</title>
  <link rel="stylesheet" href="` + cdnBase + `swagger-ui.css" integrity="` + cssSRI + `" crossorigin="anonymous">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="` + cdnBase + `swagger-ui-bundle.js" integrity="` + bundleSRI + `" crossorigin="anonymous"></script>
  <script src="/docs/init.js"></script>
</body>
</html>`

// persistAuthorization is off: the API key stays in memory only and is not
// written to localStorage, where any script on this origin could read it.
const initJS = `window.ui = SwaggerUIBundle({
  url: "/docs/openapi.yaml",
  dom_id: "#swagger-ui",
  persistAuthorization: false,
  tryItOutEnabled: true,
  displayRequestDuration: true
});`

const csp = "default-src 'self'; script-src 'self' " + cdnBase + "; style-src 'self' " + cdnBase +
	" 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Register mounts /docs, /docs/init.js and /docs/openapi.yaml on mux.
func Register(mux interface {
	Get(pattern string, h http.HandlerFunc)
}) {
	mux.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	mux.Get("/docs/init.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(initJS))
	})
	mux.Get("/docs/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(spec)
	})
}
