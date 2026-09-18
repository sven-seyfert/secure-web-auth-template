package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

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
		return "", fmt.Errorf("password must not be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate password hash: %w", err)
	}

	return string(hashedBytes), nil
}

// CheckPasswordHash compares a plaintext password to a bcrypt hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken generates a cryptographically random token with the requested length.
func GenerateToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be greater than zero")
	}

	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}
