package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetSessionCookiesSetsSecurityDefaults(t *testing.T) {
	resp := httptest.NewRecorder()

	SetSessionCookies(resp, "session-token", "csrf-token")
	cookies := resp.Result().Cookies()

	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	for _, cookie := range cookies {
		if cookie.Path != "/" {
			t.Fatalf("expected cookie path %q, got %q", "/", cookie.Path)
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("expected SameSite %v, got %v", http.SameSiteLaxMode, cookie.SameSite)
		}
	}
}
