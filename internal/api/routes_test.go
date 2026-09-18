package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sven-seyfert/secure-web-auth-template/internal/storage"
	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

func initTestStore(t *testing.T) {
	t.Helper()

	if err := storage.Init(filepath.Join(t.TempDir(), "store.db")); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})
}

func seedUserWithPassword(t *testing.T, username string) {
	t.Helper()

	hash, err := utils.HashPassword("supersecret")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if err := storage.CreateUser(storage.User{Username: username, HashedPassword: hash}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}
}

func TestSecurityHeadersAreApplied(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()

	WithSecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { //nolint:revive
		writer.WriteHeader(http.StatusOK)
	})).ServeHTTP(resp, req)

	for key, expected := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	} {
		if got := resp.Header().Get(key); got != expected {
			t.Fatalf("expected %s=%q, got %q", key, expected, got)
		}
	}

	csp := resp.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("expected a restrictive CSP, got %q", csp)
	}
}

func TestHandleRegisterRequiresUsernameAndPassword(t *testing.T) {
	initTestStore(t)

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
	initTestStore(t)

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

func TestHandleLoginRejectsUnsafeUsername(t *testing.T) {
	initTestStore(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=<script>alert(1)</script>&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleLogin(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusBadRequest, resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !strings.Contains(body, "unsupported characters") {
		t.Fatalf("expected unsafe username rejection, got %q", body)
	}
}

func TestHandleRegisterRejectsShortCredentials(t *testing.T) {
	initTestStore(t)

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

func TestHandleRegisterRejectsUnsafeUsername(t *testing.T) {
	initTestStore(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=<script>alert(1)</script>&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusBadRequest, resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !strings.Contains(body, "unsupported characters") {
		t.Fatalf("expected unsafe username rejection, got %q", body)
	}
}

func TestHandleRegisterRejectsLongUsername(t *testing.T) {
	initTestStore(t)

	longUsername := strings.Repeat("a", 33)
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username="+longUsername+"&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusBadRequest, resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !strings.Contains(body, "at most 32") {
		t.Fatalf("expected username length rejection, got %q", body)
	}
}

func TestHandleRegisterCreatesUserAccount(t *testing.T) {
	initTestStore(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=alice1234&password=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}

	if _, exists, err := storage.GetUser("alice1234"); err != nil || !exists {
		t.Fatalf("expected user to be created, err=%v exists=%v", err, exists)
	}
}

func TestHandleRegisterPreservesPasswordWhitespace(t *testing.T) {
	initTestStore(t)

	password := "  supersecret  "
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader("username=alice1234&password="+url.QueryEscape(password)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	handleRegister(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=alice1234&password="+url.QueryEscape(password)))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp := httptest.NewRecorder()

	handleLogin(loginResp, loginReq)

	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, loginResp.Code, loginResp.Body.String())
	}
}

func TestHandleRegisterRejectsDuplicateUsers(t *testing.T) {
	initTestStore(t)
	seedUserWithPassword(t, "alice1234")

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
	initTestStore(t)
	seedUserWithPassword(t, "alice1234")

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

	user, exists, err := storage.GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to exist after login")
	}
	if user.SessionToken == "" || user.CSRFToken == "" {
		t.Fatalf("expected session tokens to be set for logged-in user, got %#v", user)
	}
}

func TestHandleLoginRejectsAlreadyLoggedInUser(t *testing.T) {
	initTestStore(t)
	if err := storage.CreateUser(storage.User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
		SessionToken:   "existing-session",
		CSRFToken:      "existing-csrf",
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
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

	user, exists, err := storage.GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to still exist")
	}
	if user.SessionToken != "existing-session" || user.CSRFToken != "existing-csrf" {
		t.Fatalf("expected existing session to remain unchanged, got %#v", user)
	}
}

func TestHandleLoginAllowsDifferentUsersToLogInIndependently(t *testing.T) {
	initTestStore(t)
	seedUserWithPassword(t, "alice1234")
	seedUserWithPassword(t, "bob43210")

	aliceReq := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=alice1234&password=supersecret"))
	aliceReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	aliceResp := httptest.NewRecorder()
	handleLogin(aliceResp, aliceReq)
	if aliceResp.Code != http.StatusOK {
		t.Fatalf("expected alice login to succeed, got %d: %s", aliceResp.Code, aliceResp.Body.String())
	}

	bobReq := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader("username=bob43210&password=supersecret"))
	bobReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bobResp := httptest.NewRecorder()
	handleLogin(bobResp, bobReq)
	if bobResp.Code != http.StatusOK {
		t.Fatalf("expected bob login to succeed, got %d: %s", bobResp.Code, bobResp.Body.String())
	}

	aliceUser, exists, err := storage.GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser(alice1234) returned error: %v", err)
	}
	if !exists || aliceUser.SessionToken == "" || aliceUser.CSRFToken == "" {
		t.Fatalf("expected alice to remain logged in, got %#v", aliceUser)
	}

	bobUser, exists, err := storage.GetUser("bob43210")
	if err != nil {
		t.Fatalf("GetUser(bob43210) returned error: %v", err)
	}
	if !exists || bobUser.SessionToken == "" || bobUser.CSRFToken == "" {
		t.Fatalf("expected bob to log in successfully, got %#v", bobUser)
	}
}

func TestRequireAuthJSONAllowsProtectedRouteWithValidSession(t *testing.T) {
	initTestStore(t)
	if err := storage.CreateUser(storage.User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
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
	initTestStore(t)
	if err := storage.CreateUser(storage.User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "wrong-csrf")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleProtected)(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusUnauthorized, resp.Code, resp.Body.String())
	}
}

func TestHandleLogoutClearsSessionState(t *testing.T) {
	initTestStore(t)
	if err := storage.CreateUser(storage.User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/logout", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleLogout)(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusOK, resp.Code, resp.Body.String())
	}

	user, exists, err := storage.GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to still exist after logout")
	}
	if user.SessionToken != "" || user.CSRFToken != "" {
		t.Fatalf("expected session tokens to be cleared after logout, got %#v", user)
	}
}

func TestHandleLogoutRejectsStaleUsernameWhenCookieDoesNotMatch(t *testing.T) {
	initTestStore(t)
	if err := storage.CreateUser(storage.User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
		SessionToken:   "session-token",
		CSRFToken:      "csrf-token",
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/logout", strings.NewReader("username=wrong-user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
	resp := httptest.NewRecorder()

	requireAuthJSON(handleLogout)(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d; body=%s", http.StatusUnauthorized, resp.Code, resp.Body.String())
	}

	user, exists, err := storage.GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to still exist after stale username logout attempt")
	}
	if user.SessionToken != "session-token" || user.CSRFToken != "csrf-token" {
		t.Fatalf("expected session tokens to remain unchanged, got %#v", user)
	}
}
