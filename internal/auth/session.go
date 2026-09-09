package auth

import (
	"net/http"
	"time"

	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

// IssueSessionTokens creates a session token and CSRF token pair.
func IssueSessionTokens() (string, string, error) {
	sessionToken, err := utils.GenerateToken(32)
	if err != nil {
		return "", "", err
	}

	csrfToken, err := utils.GenerateToken(32)
	if err != nil {
		return "", "", err
	}

	return sessionToken, csrfToken, nil
}

// SetSessionCookies stores the current session token and CSRF token as cookies.
func SetSessionCookies(writer http.ResponseWriter, sessionToken, csrfToken string) {
	http.SetCookie(writer, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(5 * time.Minute),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(5 * time.Minute),
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookies removes the active session cookies by expiring them immediately.
func ClearSessionCookies(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(writer, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}
