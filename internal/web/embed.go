// Package web serves the embedded admin UI (built from web/ into
// internal/web/dist by `make web`).
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The directory holds an empty .gitkeep in git. The embed needs the
// directory to exist in a fresh checkout, and the placeholder is empty so
// that a UI build, which empties the directory and puts it back, leaves
// the working tree clean — a release refuses to run against a dirty one.
//
//go:embed all:dist
var dist embed.FS

// Handler serves hashed assets immutably and falls back to index.html for
// client-side routes. API paths are excluded so a typo returns 404 JSON
// rather than the SPA shell.
func Handler() http.HandlerFunc {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FS(sub)
	fileServer := http.FileServer(files)
	_, uiErr := fs.Stat(sub, "index.html")
	return func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		if uiErr != nil {
			http.Error(w, "supermcp UI is not built into this binary (run make web before go build)", http.StatusNotFound)
			return
		}
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/mcp") || strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/oauth/") {
			http.NotFound(w, r)
			return
		}
		if f, err := files.Open(p); err == nil {
			_ = f.Close()
			if strings.HasPrefix(p, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	}
}
