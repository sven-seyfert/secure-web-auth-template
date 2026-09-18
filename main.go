package main

import (
	"log"
	"net/http"

	"github.com/sven-seyfert/secure-web-auth-template/internal/api"
)

// main starts the HTTP server and registers all API routes.
func main() {
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	staticFileServer := http.FileServer(http.Dir("./web"))
	mux.Handle("/", staticFileServer)
	server := newHTTPServer(api.WithSecurityHeaders(mux))

	log.Printf("server listening on http://localhost:8080")

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("listen and serve failed: %v", err)
		return
	}
}

// newHTTPServer configures the application HTTP server with production-style timeouts and limits.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}
