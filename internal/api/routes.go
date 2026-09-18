package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sven-seyfert/secure-web-auth-template/internal/auth"
	"github.com/sven-seyfert/secure-web-auth-template/internal/store"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, nil)) //nolint:gochecknoglobals

// RegisterRoutes registers all API routes on the provided mux.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/register", requirePostMethod(handleRegister))
	mux.HandleFunc("/v1/login", requirePostMethod(handleLogin))
	mux.HandleFunc("/v1/protected", requirePostMethod(requireAuthJSON(handleProtected)))
	mux.HandleFunc("/v1/logout", requirePostMethod(requireAuthJSON(handleLogout)))
}

// WithSecurityHeaders applies a restrictive browser security header set to all requests.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		contentSecurityPolicy := strings.Join([]string{
			"default-src 'self'",
			"base-uri 'self'",
			"object-src 'none'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"script-src 'self'",
			"style-src 'self'",
			"img-src 'self' data:",
			"connect-src 'self'",
		}, "; ")

		writer.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(writer, request)
	})
}

// requirePostMethod ensures the request uses POST before calling the next handler.
func requirePostMethod(nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			writeErrorJSON(writer, http.StatusMethodNotAllowed, "invalid request method")
			return
		}

		nextHandler(writer, req)
}
}

// requireAuthJSON ensures the request is authenticated before calling the next handler.
func requireAuthJSON(nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		if err := auth.Authorize(request); err != nil {
			writeErrorJSON(responseWriter, http.StatusUnauthorized, err.Error())
			return
		}

		nextHandler(responseWriter, request)
	}
}

// requireMethod ensures the request uses the expected HTTP method before calling the next handler.
func requireMethod(expectedMethod string, nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.Method != expectedMethod {
			writeErrorJSON(responseWriter, http.StatusMethodNotAllowed, "invalid request method")
			return
		}

		nextHandler(responseWriter, request)
	}
}

// writeJSON encodes a payload as JSON and writes it to the response.
func writeJSON(writer http.ResponseWriter, statusCode int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)

	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		logger.Error("encode JSON response", "error", err)
	}
}

// writeErrorJSON writes a JSON error payload to the response.
func writeErrorJSON(writer http.ResponseWriter, statusCode int, message string) {
	writeJSON(writer, statusCode, map[string]string{"error": message})
}

// readCredentials trims the username for normalization and returns the password unchanged,
// because leading/trailing spaces are part of the actual password value.
func readCredentials(req *http.Request) (string, string) {
	username := strings.TrimSpace(req.FormValue("username"))
	password := req.FormValue("password")

	return username, password
}

// requireFormFields validates that the given form fields are present and not empty.
func requireFormFields(req *http.Request, fieldNames ...string) error {
	for _, fieldName := range fieldNames {
		if strings.TrimSpace(req.FormValue(fieldName)) == "" {
			return fmt.Errorf("%s is required", fieldName)
		}
	}

	return nil
}

// handleRegister creates a new user account.
func handleRegister(writer http.ResponseWriter, req *http.Request) {
	username, password := readCredentials(req)

	if err := requireFormFields(req, "username", "password"); err != nil {
		writeErrorJSON(writer, http.StatusBadRequest, err.Error())
		return
	}

	if err := utils.ValidateCredentials(username, password); err != nil {
		writeErrorJSON(writer, http.StatusBadRequest, err.Error())
		return
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		logger.ErrorContext(req.Context(), "hash password error", "error", err)
		writeErrorJSON(writer, http.StatusInternalServerError, "could not create user")
		return
	}

	store.Users[username] = store.User{
		HashedPassword: hashedPassword,
	}

	writeJSON(writer, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("User %q registered successfully.", username),
	})
}

// handleLogin validates credentials, creates session data, and responds with success.
func handleLogin(writer http.ResponseWriter, req *http.Request) {
	username, password := readCredentials(req)

	if err := requireFormFields(req, "username", "password"); err != nil {
		writeErrorJSON(writer, http.StatusBadRequest, err.Error())
		return
	}

	if err := utils.ValidateCredentials(username, password); err != nil {
		writeErrorJSON(writer, http.StatusBadRequest, err.Error())
		return
	}

	if !exists {
		writeErrorJSON(writer, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if user.SessionToken != "" || user.CSRFToken != "" {
		writeJSON(writer, http.StatusConflict, map[string]string{
			"message": fmt.Sprintf("User %q is already logged in.", username),
		})
		return
	}

	if !utils.CheckPasswordHash(password, user.HashedPassword) {
		writeErrorJSON(writer, http.StatusUnauthorized, "invalid username or password")
		return
	}

	sessionToken, csrfToken, err := auth.IssueSessionTokens()
	if err != nil {
		logger.ErrorContext(req.Context(), "create login tokens error", "error", err)
		writeErrorJSON(writer, http.StatusInternalServerError, "could not create session")

		return
	}

	auth.SetSessionCookies(writer, sessionToken, csrfToken)

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	store.Users[username] = user

	writeJSON(writer, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Login successful for user %q.", username),
	})
}

// handleProtected confirms that the request passed authentication and CSRF validation.
func handleProtected(writer http.ResponseWriter, req *http.Request) {
	username := strings.TrimSpace(req.FormValue("username"))

	if err := utils.ValidateUsername(username, utils.MinCredentialLength); err != nil {
		writeErrorJSON(writer, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("CSRF validation successful. Welcome, %q.", username),
	})
}

// handleLogout clears the active session cookies and resets the stored session data.
func handleLogout(writer http.ResponseWriter, req *http.Request) {
	auth.ClearSessionCookies(writer)

	username := strings.TrimSpace(req.FormValue("username"))

	if err := utils.ValidateUsername(username, utils.MinCredentialLength); err != nil {
		writeErrorJSON(writer, http.StatusUnauthorized, auth.ErrUnauthorized.Error())
		return
	}

	if !exists {
		writeErrorJSON(writer, http.StatusNotFound, "user not found")
		return
	}

	user.SessionToken = ""
	user.CSRFToken = ""
	store.Users[username] = user

	writeJSON(writer, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Logout successful for user %q.", username),
	})
}
