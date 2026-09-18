package auth

import (
	"net/http"
	"time"

	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

// SessionCookieName returns the cookie name for a username-bound session token.
func SessionCookieName(username string) string {
	return "session_token_" + username
}

// CSRFTokenCookieName returns the cookie name for a username-bound CSRF token.
func CSRFTokenCookieName(username string) string {
	return "csrf_token_" + username
}

// IssueSessionTokens creates a fresh random session token and CSRF token pair for a new login.
func IssueSessionTokens() (string, string, error) {
	const length = 32

	sessionToken, err := utils.GenerateToken(length)
	if err != nil {
		return "", "", err
	}

	csrfToken, err := utils.GenerateToken(length)
	if err != nil {
		return "", "", err
	}

	return sessionToken, csrfToken, nil
}

// SetSessionCookies stores the session and CSRF values as username-scoped cookies.
func SetSessionCookies(writer http.ResponseWriter, username, sessionToken, csrfToken string) {
	now := time.Now()

	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName(username),
		Value:    sessionToken,
		Expires:  now.Add(utils.SessionTimeout),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})

	http.SetCookie(writer, &http.Cookie{ //nolint:gosec
		Name:     CSRFTokenCookieName(username),
		Value:    csrfToken,
		Expires:  now.Add(utils.SessionTimeout),
		Path:     "/",
		HttpOnly: false, // It's intended to be accessible via JavaScript for CSRF protection.
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})
}

// ClearSessionCookies removes the active session cookies for a user by expiring them immediately.
func ClearSessionCookies(writer http.ResponseWriter, username string) {
	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName(username),
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})

	http.SetCookie(writer, &http.Cookie{ //nolint:gosec
		Name:     CSRFTokenCookieName(username),
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: false, // It's intended to be accessible via JavaScript for CSRF protection.
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})
}
