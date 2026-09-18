package auth

import (
	"errors"
	"net/http"

	"github.com/sven-seyfert/secure-web-auth-template/internal/store"
)

// ErrUnauthorized signals that a request lacks valid auth data.
var ErrUnauthorized = errors.New("unauthorized")

// Authorize validates the session cookie and CSRF token for the request.
func Authorize(req *http.Request) error {
	username := req.FormValue("username")
	user, exists := store.Users[username]
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
		return ErrUnauthorized
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
			http.Error(responseWriter, "unauthorized", http.StatusUnauthorized)
			return
		}

		nextHandler(responseWriter, request)
	}
}
