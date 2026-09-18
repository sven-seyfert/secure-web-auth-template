package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sven-seyfert/secure-web-auth-template/internal/storage"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrSessionExpired = errors.New("session expired")
	ErrCSRFExpired    = errors.New("csrf token expired")
)

// Authorize validates the session cookie and CSRF header for the request.
func Authorize(req *http.Request) error {
	username := strings.TrimSpace(req.FormValue("username"))
	if username == "" {
		return ErrUnauthorized
	}

	if err := utils.ValidateUsername(username, utils.MinCredentialLength); err != nil {
		return ErrUnauthorized
	}

	user, exists, err := storage.GetUser(username)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}

	if !exists {
		return ErrUnauthorized
	}

	if user.IsSessionExpired() {
		return ErrSessionExpired
	}

	sessionCookie, err := req.Cookie(SessionCookieName(username))
	if err != nil || strings.TrimSpace(sessionCookie.Value) == "" {
		return ErrUnauthorized
	}

	if sessionCookie.Value != user.SessionToken {
		return ErrUnauthorized
	}

	if user.IsCSRFExpired() {
		return ErrCSRFExpired
	}

	csrfToken := req.Header.Get("X-Csrf-Token")
	if csrfToken == "" || csrfToken != user.CSRFToken {
		return ErrUnauthorized
	}

	return nil
}

// RequireAuth wraps a handler and rejects unauthorized requests.
func RequireAuth(nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		if err := Authorize(request); err != nil {
			http.Error(responseWriter, err.Error(), http.StatusUnauthorized)
			return
		}

		nextHandler(responseWriter, request)
	}
}
