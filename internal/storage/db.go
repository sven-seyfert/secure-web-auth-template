package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sven-seyfert/secure-web-auth-template/internal/utils"

	_ "modernc.org/sqlite" // Initialize SQLite driver.
)

// User represents a persisted account together with its current login metadata and expiry timestamps.
type User struct {
	Username         string
	HashedPassword   string
	SessionToken     string
	CSRFToken        string
	SessionExpiresAt time.Time
	CSRFExpiresAt    time.Time
}

// HasSessionData reports whether the user has any stored login values available.
func (u User) HasSessionData() bool {
	return strings.TrimSpace(u.SessionToken) != "" || strings.TrimSpace(u.CSRFToken) != ""
}

// IsSessionExpired reports whether the stored session expiry timestamp has passed.
func (u User) IsSessionExpired() bool {
	return !u.SessionExpiresAt.IsZero() && !time.Now().In(time.Local).Before(u.SessionExpiresAt.In(time.Local))
}

// IsCSRFExpired reports whether the stored CSRF expiry timestamp has passed.
func (u User) IsCSRFExpired() bool {
	return !u.CSRFExpiresAt.IsZero() && !time.Now().In(time.Local).Before(u.CSRFExpiresAt.In(time.Local))
}

// IsLoggedIn reports whether the user currently has active session and CSRF data.
func (u User) IsLoggedIn() bool {
	return u.HasSessionData() && !u.IsSessionExpired() && !u.IsCSRFExpired()
}

var (
	ErrUserExists             = errors.New("user already exists")
	ErrDatabaseNotInitialized = errors.New("database not initialized")

	database *sql.DB //nolint:gochecknoglobals
)

// formatExpiry converts a local time value into RFC3339 for SQLite persistence.
func formatExpiry(value time.Time) string {
	if value.IsZero() {
		return ""
	}

	return value.In(time.Local).Format(time.RFC3339)
}

// parseExpiry decodes a stored RFC3339 timestamp back into a local time value.
func parseExpiry(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, err
	}

	return parsed.In(time.Local), nil
}

// Close releases the active SQLite database connection.
func Close() error {
	if database == nil {
		return nil
	}

	err := database.Close()
	database = nil

	return err
}

// Init opens the SQLite database and creates the required users table.
func Init(dbPath string) error {
	if database != nil {
		if err := Close(); err != nil {
			return fmt.Errorf("close existing sqlite database: %w", err)
		}
	}

	if strings.TrimSpace(dbPath) == "" {
		dbPath = filepath.Join(utils.ProjectRoot(), "db", "store.db")
	}

	directory := filepath.Dir(dbPath)
	if directory != "." && directory != "" && directory != string(filepath.Separator) {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return fmt.Errorf("create sqlite directory: %w", err)
		}
	}

	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite database: %w", err)
	}

	if err := sqlDB.PingContext(context.Background()); err != nil {
		_ = sqlDB.Close()
		return fmt.Errorf("ping sqlite database: %w", err)
	}

	if _, err := sqlDB.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			hashed_password TEXT NOT NULL,
			session_token TEXT,
			csrf_token TEXT,
			session_expires_at TEXT,
			csrf_expires_at TEXT
		);`); err != nil {
		_ = sqlDB.Close()
		return fmt.Errorf("create sqlite schema: %w", err)
	}

	database = sqlDB

	return nil
}

// ensureDB checks whether the SQLite database connection is initialized.
func ensureDB() error {
	if database == nil {
		return ErrDatabaseNotInitialized
	}

	return nil
}

// CreateUser inserts a new user into the SQLite database if the username is still free.
func CreateUser(user User) error {
	if err := ensureDB(); err != nil {
		return err
	}

	if strings.TrimSpace(user.Username) == "" {
		return errors.New("username is required")
	}

	if _, err := database.ExecContext(context.Background(), `
		INSERT INTO users (username, hashed_password, session_token, csrf_token, session_expires_at, csrf_expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, user.Username, user.HashedPassword, user.SessionToken, user.CSRFToken, formatExpiry(user.SessionExpiresAt), formatExpiry(user.CSRFExpiresAt)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserExists
		}

		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

// getUserByQuery loads a single user using the provided SQL query and lookup value.
func getUserByQuery(query string, value any, notFoundErrFmt string) (User, bool, error) {
	if err := ensureDB(); err != nil {
		return User{}, false, err
	}

	row := database.QueryRowContext(context.Background(), query, value)

	var user User
	var sessionExpiresAtText, csrfExpiresAtText sql.NullString

	if err := row.Scan(
		&user.Username,
		&user.HashedPassword,
		&user.SessionToken,
		&user.CSRFToken,
		&sessionExpiresAtText,
		&csrfExpiresAtText,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}

		if notFoundErrFmt != "" {
			return User{}, false, fmt.Errorf(notFoundErrFmt, err)
		}

		return User{}, false, fmt.Errorf("get user: %w", err)
	}

	parsedSessionExpiresAt, err := parseExpiry(sessionExpiresAtText.String)
	if err != nil {
		return User{}, false, fmt.Errorf("parse session expiry time: %w", err)
	}
	user.SessionExpiresAt = parsedSessionExpiresAt

	parsedCSRFExpiresAt, err := parseExpiry(csrfExpiresAtText.String)
	if err != nil {
		return User{}, false, fmt.Errorf("parse csrf expiry time: %w", err)
	}
	user.CSRFExpiresAt = parsedCSRFExpiresAt

	return user, true, nil
}

// GetUser loads a single user by username from SQLite.
func GetUser(username string) (User, bool, error) {
	return getUserByQuery(`
		SELECT username, hashed_password, session_token, csrf_token, session_expires_at, csrf_expires_at
		FROM users
		WHERE username = ?
	`, username, "get user: %w")
}

// GetUserBySessionToken loads a single user by the active session token from SQLite.
func GetUserBySessionToken(sessionToken string) (User, bool, error) {
	return getUserByQuery(`
		SELECT username, hashed_password, session_token, csrf_token, session_expires_at, csrf_expires_at
		FROM users
		WHERE session_token = ?
	`, sessionToken, "get user by session token: %w")
}

// SetSession updates the stored session and CSRF expiry timestamps for a user.
func SetSession(username, sessionToken, csrfToken string, sessionExpiresAt, csrfExpiresAt time.Time) error {
	if err := ensureDB(); err != nil {
		return err
	}

	result, err := database.ExecContext(context.Background(), `
		UPDATE users
		SET session_token = ?, csrf_token = ?, session_expires_at = ?, csrf_expires_at = ?
		WHERE username = ?
	`, sessionToken, csrfToken, formatExpiry(sessionExpiresAt), formatExpiry(csrfExpiresAt), username)
	if err != nil {
		return fmt.Errorf("set session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check session update: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// ClearSession removes the active session tokens for a user.
func ClearSession(username string) error {
	if err := ensureDB(); err != nil {
		return err
	}

	result, err := database.ExecContext(context.Background(), `
		UPDATE users
		SET session_token = '', csrf_token = '', session_expires_at = '', csrf_expires_at = ''
		WHERE username = ?
	`, username)
	if err != nil {
		return fmt.Errorf("clear session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check session clear: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}
