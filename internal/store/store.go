package store

// User represents a stored account and its active session state.
type User struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

// Users stores account data keyed by username.
var Users = map[string]User{}
