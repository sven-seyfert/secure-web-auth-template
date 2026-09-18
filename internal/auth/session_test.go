package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetSessionCookiesSetsSecurityDefaults(t *testing.T) {
	resp := httptest.NewRecorder()

	SetSessionCookies(resp, "alice1234", "session-token", "csrf-token")
	cookies := resp.Result().Cookies()

	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	seenNames := map[string]bool{}
	for _, cookie := range cookies {
		seenNames[cookie.Name] = true
		if cookie.Path != "/" {
			t.Fatalf("expected cookie path %q, got %q", "/", cookie.Path)
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("expected SameSite %v, got %v", http.SameSiteLaxMode, cookie.SameSite)
		}
	}

	if !seenNames["session_token_alice1234"] {
		t.Fatalf("expected session cookie for alice1234 to be set, got %#v", seenNames)
	}
	if !seenNames["csrf_token_alice1234"] {
		t.Fatalf("expected csrf cookie for alice1234 to be set, got %#v", seenNames)
	}
}
