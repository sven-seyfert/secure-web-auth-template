package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sven-seyfert/secure-web-auth-template/internal/store"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

func seedUserWithPassword(t *testing.T, username, password string) {
	t.Helper()

	hash, err := utils.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	store.Users[username] = store.User{HashedPassword: hash}
}

func TestHandleRegisterRequiresUsernameAndPassword(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=&password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.Code)
	}

	if body := resp.Body.String(); !strings.Contains(body, "required") {
		t.Fatalf("expected required-field error, got %q", body)
	}
}

func TestHandleLoginRequiresUsernameAndPassword(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=alice"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleLogin(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.Code)
	}

	if body := resp.Body.String(); !strings.Contains(body, "required") {
		t.Fatalf("expected required-field error, got %q", body)
	}
}

func TestHandleRegisterRejectsShortCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=short&password=short"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.Code)
	}

	if body := resp.Body.String(); !strings.Contains(body, "at least 8 characters") {
		t.Fatalf("expected standardized length error, got %q", body)
	}
}

func TestHandleRegisterCreatesUserAccount(t *testing.T) {
	store.Users = map[string]store.User{}

	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=alice1234&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}
	if _, exists := store.Users["alice1234"]; !exists {
		t.Fatal("expected user to be created")
	}
}

func TestHandleRegisterRejectsDuplicateUsers(t *testing.T) {
	store.Users = map[string]store.User{}
	seedUserWithPassword(t, "alice1234", "supersecret")

	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=alice1234&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusConflict, resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "already exists") {
		t.Fatalf("expected duplicate-user error, got %s", resp.Body.String())
	}
}

func TestHandleLoginCreatesSessionCookies(t *testing.T) {
	store.Users = map[string]store.User{}
	seedUserWithPassword(t, "alice1234", "supersecret")

	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=alice1234&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleLogin(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}

	cookies := resp.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	user := store.Users["alice1234"]
	if user.SessionToken == "" || user.CSRFToken == "" {
		t.Fatalf("expected session tokens to be set for logged-in user, got %#v", user)
	}
}

func TestHandleLoginRejectsAlreadyLoggedInUser(t *testing.T) {
	store.Users = map[string]store.User{}
	hash, err := utils.HashPassword("supersecret")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	store.Users["alice1234"] = store.User{
		HashedPassword: hash,
		SessionToken:   "existing-session",
		CSRFToken:      "existing-csrf",
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=alice1234&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "existing-csrf")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "existing-session"})
	resp := httptest.NewRecorder()

	handleLogin(resp, req)

	if resp.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusConflict, resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "already logged in") {
		t.Fatalf("expected already-logged-in message, got %s", resp.Body.String())
	}
	if store.Users["alice1234"].SessionToken != "existing-session" || store.Users["alice1234"].CSRFToken != "existing-csrf" {
		t.Fatalf("expected existing session to remain unchanged, got %#v", store.Users["alice1234"])
	}
}

func TestRequireAuthJSONAllowsProtectedRouteWithValidSession(t *testing.T) {
	store.Users = map[string]store.User{}
	store.Users["alice1234"] = store.User{
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
		HashedPassword: "hashed-password",
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleProtected)(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "CSRF validation successful") {
		t.Fatalf("expected successful protected response, got %s", resp.Body.String())
	}
}

func TestRequireAuthJSONRejectsUnauthorizedUsers(t *testing.T) {
	store.Users = map[string]store.User{}
	store.Users["alice1234"] = store.User{SessionToken: "session-token", CSRFToken: "csrf-token"}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "wrong-csrf")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleProtected)(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusUnauthorized, resp.Code, resp.Body.String())
	}
}

func TestHandleLogoutClearsSessionState(t *testing.T) {
	store.Users = map[string]store.User{}
	store.Users["alice1234"] = store.User{
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
		HashedPassword: "hashed-password",
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/logout", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleLogout)(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}
	user := store.Users["alice1234"]
	if user.SessionToken != "" || user.CSRFToken != "" {
		t.Fatalf("expected session tokens to be cleared after logout, got %#v", user)
	}
}
