package utils

import (
	"strings"
	"testing"
)

func TestHashPasswordAndCheckPasswordHash(t *testing.T) {
	password := "supersecret123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty password hash")
	}
	if !CheckPasswordHash(password, hash) {
		t.Fatal("expected password hash to match original password")
	}
	if CheckPasswordHash("wrong-password", hash) {
		t.Fatal("expected password mismatch to fail")
	}
}

func TestGenerateTokenProducesValidToken(t *testing.T) {
	token, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("expected generated token to be non-empty")
	}
	if strings.TrimSpace(token) != token {
		t.Fatalf("expected generated token to not contain surrounding whitespace, got %q", token)
	}
	if len(token) < 32 {
		t.Fatalf("expected generated token to be sufficiently long, got length %d with value %q", len(token), token)
	}
}

func TestGenerateTokenRejectsZeroLength(t *testing.T) {
	if _, err := GenerateToken(0); err == nil {
		t.Fatal("expected GenerateToken to reject zero length")
	}
}
