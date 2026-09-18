package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sven-seyfert/secure-web-auth-template/internal/api"
	"github.com/sven-seyfert/secure-web-auth-template/internal/storage"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

// main starts the HTTP server, registers the API routes, and serves the static web assets.
func main() {
	dbPath := filepath.Join(utils.ProjectRoot(), "db", "store.db")
	if err := storage.Init(dbPath); err != nil {
		log.Fatalf("initialize sqlite store: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	staticFileServer := http.FileServer(http.Dir(filepath.Join(utils.ProjectRoot(), "web")))
	mux.Handle("/", staticFileServer)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	const shutdownTimeout = 10 * time.Second

	server := newHTTPServer(api.WithSecurityHeaders(mux))

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

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
