package panel

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web
var webFS embed.FS

//go:embed install.sh
var installScript []byte

// webHandler 提供内嵌的单页应用(hash 路由,无需回退到 index.html)。
func webHandler() http.Handler {
	sub, _ := fs.Sub(webFS, "web")
	fsrv := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		fsrv.ServeHTTP(w, r)
	})
}
