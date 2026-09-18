package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestAuthorizeAcceptsValidSessionAndCSRF(t *testing.T) {
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

	if err := Authorize(req); err != nil {
		t.Fatalf("Authorize returned error for valid request: %v", err)
	}
}

func TestAuthorizeRejectsMissingUser(t *testing.T) {
	initTestStore(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=missing-user"))
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_missing-user", Value: "session-token"})

	if err := Authorize(req); err == nil {
		t.Fatal("expected missing user to be rejected")
	}
}

func TestAuthorizeRejectsExpiredSessionOrCSRF(t *testing.T) {
	initTestStore(t)
	expired := time.Now().Add(-1 * time.Minute).In(time.Local).Truncate(time.Second)
	if err := storage.CreateUser(storage.User{
		Username:         "alice1234",
		HashedPassword:   "hashed-password",
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: expired,
		CSRFExpiresAt:    expired,
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})

	if err := Authorize(req); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected expired session error, got: %v", err)
	}
}

func TestAuthorizeRejectsExpiredSessionWhenCookieIsMissing(t *testing.T) {
	initTestStore(t)
	expired := time.Now().Add(-1 * time.Minute).In(time.Local).Truncate(time.Second)
	if err := storage.CreateUser(storage.User{
		Username:         "alice1234",
		HashedPassword:   "hashed-password",
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: expired,
		CSRFExpiresAt:    time.Now().Add(utils.SessionTimeout).In(time.Local).Truncate(time.Second),
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := Authorize(req); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected expired session even without cookie, got: %v", err)
	}
}

func TestAuthorizeRejectsExpiredCSRFToken(t *testing.T) {
	initTestStore(t)
	expiresAt := time.Now().Add(utils.SessionTimeout).In(time.Local).Truncate(time.Second)
	if err := storage.CreateUser(storage.User{
		Username:         "alice1234",
		HashedPassword:   "hashed-password",
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: expiresAt,
		CSRFExpiresAt:    time.Now().Add(-1 * time.Minute).In(time.Local).Truncate(time.Second),
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Csrf-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})

	if err := Authorize(req); !errors.Is(err, ErrCSRFExpired) {
		t.Fatalf("expected expired CSRF error, got: %v", err)
	}
}

func TestAuthorizeRejectsExpiredCSRFWhenHeaderIsMissing(t *testing.T) {
	initTestStore(t)
	expiresAt := time.Now().Add(utils.SessionTimeout).In(time.Local).Truncate(time.Second)
	if err := storage.CreateUser(storage.User{
		Username:         "alice1234",
		HashedPassword:   "hashed-password",
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: expiresAt,
		CSRFExpiresAt:    time.Now().Add(-1 * time.Minute).In(time.Local).Truncate(time.Second),
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})

	if err := Authorize(req); !errors.Is(err, ErrCSRFExpired) {
		t.Fatalf("expected expired CSRF even without header, got: %v", err)
	}
}

func TestAuthorizeRejectsInvalidSessionOrCSRF(t *testing.T) {
	initTestStore(t)
	expiresAt := time.Now().Add(utils.SessionTimeout).In(time.Local).Truncate(time.Second)
	if err := storage.CreateUser(storage.User{
		Username:         "alice1234",
		HashedPassword:   "hashed-password",
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: expiresAt,
		CSRFExpiresAt:    expiresAt,
	}); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	tests := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{
			name: "missing session cookie",
			prepare: func(req *http.Request) {
				req.Header.Set("X-Csrf-Token", "csrf-token")
			},
		},
		{
			name: "invalid session value",
			prepare: func(req *http.Request) {
				req.Header.Set("X-Csrf-Token", "csrf-token")
				req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "wrong-session"})
			},
		},
		{
			name: "missing CSRF header",
			prepare: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
			},
		},
		{
			name: "invalid CSRF value",
			prepare: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token_alice1234", Value: "session-token"})
				req.Header.Set("X-Csrf-Token", "wrong-csrf")
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			testCase.prepare(req)

			if err := Authorize(req); err == nil {
				t.Fatalf("expected invalid request to be rejected for %s", testCase.name)
			}
		})
	}
}
