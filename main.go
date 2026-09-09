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

	log.Printf("server listening on http://localhost:8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen and serve failed: %v", err)
	}
}
