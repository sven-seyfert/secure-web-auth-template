package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ProjectRoot returns the repository root based on the location of this file.
func ProjectRoot() string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}

	return filepath.Dir(filepath.Dir(filepath.Dir(currentFile)))
}

// HashPassword returns a bcrypt hash for the provided plaintext password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate password hash: %w", err)
	}

	return string(hashedBytes), nil
}

// CheckPasswordHash compares a plaintext password against a bcrypt hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidateUsername ensures the username satisfies the app's safe input policy.
func ValidateUsername(username string, minLength int) error {
	trimmedUsername := strings.TrimSpace(username)
	if trimmedUsername == "" {
		return errors.New("username is required")
	}

	if len(trimmedUsername) < minLength {
		return fmt.Errorf("username must be at least %d characters long", minLength)
	}

	if len(trimmedUsername) > MaxUsernameLength {
		return fmt.Errorf("username must be at most %d characters long", MaxUsernameLength)
	}

	if !usernamePattern.MatchString(trimmedUsername) {
		return errors.New("username contains unsupported characters")
	}

	return nil
}

// ValidatePassword ensures the password satisfies the app's minimum length policy.
func ValidatePassword(password string, minLength int) error {
	if password == "" {
		return errors.New("password is required")
	}

	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}

	return nil
}

// ValidateCredentials validates the username and password using the shared credential policy.
func ValidateCredentials(username, password string) error {
	if err := ValidateUsername(username, MinCredentialLength); err != nil {
		return err
	}

	if err := ValidatePassword(password, MinCredentialLength); err != nil {
		return err
	}

	return nil
}

// GenerateToken generates a cryptographically random token with the requested byte length.
func GenerateToken(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("token length must be greater than zero")
	}

	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}
