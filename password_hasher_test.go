package auth

import (
	"testing"
)

func TestNewBcryptHasher(t *testing.T) {
	h := NewBcryptHasher()
	if h == nil {
		t.Fatal("NewBcryptHasher() returned nil")
	}
	if h.cost == 0 {
		t.Error("expected non-zero cost")
	}
}

func TestBcryptHasher_Hash(t *testing.T) {
	h := NewBcryptHasher()
	password := "mySecretPassword123"

	hash, err := h.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if hash == "" {
		t.Error("Hash() returned empty string")
	}
	if hash == password {
		t.Error("Hash() returned plaintext password")
	}
}

func TestBcryptHasher_Hash_EmptyPassword(t *testing.T) {
	h := NewBcryptHasher()
	hash, err := h.Hash("")
	if err != nil {
		t.Fatalf("Hash() with empty password error = %v", err)
	}
	if hash == "" {
		t.Error("Hash() returned empty string for empty password")
	}
}

func TestBcryptHasher_Hash_DeterministicOutput(t *testing.T) {
	h := NewBcryptHasher()
	password := "testPassword"

	hash1, err1 := h.Hash(password)
	hash2, err2 := h.Hash(password)
	if err1 != nil || err2 != nil {
		t.Fatalf("Hash() errors: %v, %v", err1, err2)
	}
	// bcrypt produces different hashes each time (salted)
	if hash1 == hash2 {
		t.Error("expected different hashes for same password (bcrypt uses salt)")
	}
}

func TestBcryptHasher_Verify_CorrectPassword(t *testing.T) {
	h := NewBcryptHasher()
	password := "correctPassword"

	hash, err := h.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if !h.Verify(password, hash) {
		t.Error("Verify() should return true for correct password")
	}
}

func TestBcryptHasher_Verify_WrongPassword(t *testing.T) {
	h := NewBcryptHasher()
	password := "correctPassword"
	wrongPassword := "wrongPassword"

	hash, err := h.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if h.Verify(wrongPassword, hash) {
		t.Error("Verify() should return false for wrong password")
	}
}

func TestBcryptHasher_Verify_EmptyPassword(t *testing.T) {
	h := NewBcryptHasher()
	hash, err := h.Hash("somePassword")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if h.Verify("", hash) {
		t.Error("Verify() should return false for empty password against non-empty hash")
	}
}

func TestBcryptHasher_Verify_InvalidHash(t *testing.T) {
	h := NewBcryptHasher()
	// Invalid bcrypt hash format
	invalidHash := "not-a-valid-bcrypt-hash"
	if h.Verify("password", invalidHash) {
		t.Error("Verify() should return false for invalid hash")
	}
}

func TestBcryptHasher_Verify_EmptyHash(t *testing.T) {
	h := NewBcryptHasher()
	if h.Verify("password", "") {
		t.Error("Verify() should return false for empty hash")
	}
}
