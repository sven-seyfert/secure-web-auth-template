package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"
)

func TestSQLiteStoresUserPersistently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	if err := Init(path); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	user := User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
	}

	if err := CreateUser(user); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	storedUser, exists, err := GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to exist in the database")
	}
	if storedUser.HashedPassword != "hashed-password" {
		t.Fatalf("expected stored password to match, got %q", storedUser.HashedPassword)
	}
}

func TestSQLiteRejectsDuplicateUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	if err := Init(path); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	user := User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
	}

	if err := CreateUser(user); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	if err := CreateUser(user); err == nil {
		t.Fatal("expected duplicate username registration to fail")
	}
}

func TestSQLiteStoresSessionTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	if err := Init(path); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	user := User{
		Username:       "alice1234",
		HashedPassword: "hashed-password",
	}

	if err := CreateUser(user); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	expiresAt := time.Now().Add(utils.SessionTimeout).In(time.Local).Truncate(time.Second)
	if err := SetSession("alice1234", "session-token", "csrf-token", expiresAt, expiresAt); err != nil {
		t.Fatalf("SetSession returned error: %v", err)
	}

	storedUser, exists, err := GetUser("alice1234")
	if err != nil {
		t.Fatalf("GetUser returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected user to exist after setting session tokens")
	}
	if storedUser.SessionToken != "session-token" || storedUser.CSRFToken != "csrf-token" {
		t.Fatalf("expected session tokens to be persisted, got %#v", storedUser)
	}
	if !storedUser.SessionExpiresAt.Equal(expiresAt) || !storedUser.CSRFExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected session expiry timestamps to be persisted, got %#v", storedUser)
	}
}
