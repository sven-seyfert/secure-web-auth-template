package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sven-seyfert/secure-web-auth-template/internal/store"
)

func resetUsers() {
	store.Users = map[string]store.User{}
}

func TestAuthorizeAcceptsValidSessionAndCSRF(t *testing.T) {
	resetUsers()
	store.Users["alice1234"] = store.User{
		SessionToken: "session-token",
		CSRFToken:    "csrf-token",
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})

	if err := Authorize(req); err != nil {
		t.Fatalf("Authorize returned error for valid request: %v", err)
	}
}

func TestAuthorizeRejectsMissingUser(t *testing.T) {
	resetUsers()

	req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=missing-user"))
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})

	if err := Authorize(req); err == nil {
		t.Fatal("expected missing user to be rejected")
	}
}

func TestAuthorizeRejectsInvalidSessionOrCSRF(t *testing.T) {
	resetUsers()
	store.Users["alice1234"] = store.User{
		SessionToken: "session-token",
		CSRFToken:    "csrf-token",
	}

	tests := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{
			name: "missing session cookie",
			prepare: func(req *http.Request) {
				req.Header.Set("X-CSRF-Token", "csrf-token")
			},
		},
		{
			name: "invalid session value",
			prepare: func(req *http.Request) {
				req.Header.Set("X-CSRF-Token", "csrf-token")
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "wrong-session"})
			},
		},
		{
			name: "missing CSRF header",
			prepare: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})
			},
		},
		{
			name: "invalid CSRF value",
			prepare: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "session-token"})
				req.Header.Set("X-CSRF-Token", "wrong-csrf")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/protected", strings.NewReader("username=alice1234"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tc.prepare(req)

			if err := Authorize(req); err == nil {
				t.Fatalf("expected invalid request to be rejected for %s", tc.name)
			}
		})
	}
}
