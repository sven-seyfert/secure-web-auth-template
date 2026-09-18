package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/sven-seyfert/secure-web-auth-template/internal/auth"
	"github.com/sven-seyfert/secure-web-auth-template/internal/store"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

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
		log.Printf("encode JSON response: %v", err)
	}
}

// writeErrorJSON writes a JSON error payload to the response.
func writeErrorJSON(writer http.ResponseWriter, statusCode int, message string) {
	writeJSON(writer, statusCode, map[string]string{"error": message})
}

// readCredentials trims and returns the username and password from the request form.
func readCredentials(req *http.Request) (string, string) {
	username := strings.TrimSpace(req.FormValue("username"))
	password := strings.TrimSpace(req.FormValue("password"))

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

	if len(username) < 8 || len(password) < 8 {
		writeErrorJSON(writer, http.StatusBadRequest, "username and password must be at least 8 characters long")
		return
	}

	if _, exists := store.Users[username]; exists {
		writeErrorJSON(writer, http.StatusConflict, "user already exists")
		return
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		log.Printf("hash password error: %v", err)
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

	user, exists := store.Users[username]
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
		log.Printf("create login tokens error: %v", err)
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

	writeJSON(writer, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("CSRF validation successful. Welcome, %q.", username),
	})
}

// handleLogout clears the active session cookies and resets the stored session data.
func handleLogout(writer http.ResponseWriter, req *http.Request) {
	auth.ClearSessionCookies(writer)

	username := strings.TrimSpace(req.FormValue("username"))
	user, exists := store.Users[username]
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
