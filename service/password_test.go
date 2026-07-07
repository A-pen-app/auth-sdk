package service

import (
	"errors"
	"testing"

	e "github.com/A-pen-app/errors"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("secret123", 10)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(hash, "secret123"); err != nil {
		t.Fatalf("VerifyPassword should succeed: %v", err)
	}
}

func TestVerifyPasswordMismatch(t *testing.T) {
	hash, err := HashPassword("secret123", 10)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(hash, "wrong"); err == nil {
		t.Fatal("VerifyPassword should fail on mismatch")
	}
}

func TestHashPasswordInvalidCost(t *testing.T) {
	_, err := HashPassword("secret123", 100)
	if err == nil {
		t.Fatal("HashPassword should fail with invalid cost")
	}
}

func TestPasswordPolicyValidate(t *testing.T) {
	p := DefaultPasswordPolicy()

	valid := []string{
		"Secret123",            // typical
		"Secret12",             // exactly 8 chars
		"Abcdefghijklmno123XY", // exactly 20 chars
	}
	for _, pw := range valid {
		if err := p.Validate(pw); err != nil {
			t.Errorf("Validate(%q) should pass, got %v", pw, err)
		}
	}

	invalid := []struct {
		name string
		pw   string
	}{
		{"empty", ""},
		{"too short", "Abc123"},                  // 6 chars
		{"too long", "Abcdefghijklmno123XYZ"},     // 21 chars
		{"no upper", "secret123"},
		{"no lower", "SECRET123"},
		{"no digit", "SecretPwd"},
	}
	for _, tc := range invalid {
		err := p.Validate(tc.pw)
		if err == nil {
			t.Errorf("Validate(%q) [%s] should fail", tc.pw, tc.name)
			continue
		}
		if !errors.Is(err, e.ErrorWrongParams) {
			t.Errorf("Validate(%q) [%s] should return ErrorWrongParams, got %v", tc.pw, tc.name, err)
		}
	}
}

// TestPasswordPolicyByteLimit guards the bcrypt 72-byte hard limit: a password
// can pass the character-count check yet exceed 72 bytes via multi-byte runes,
// which would otherwise fail inside bcrypt as a 500. Validate must reject it 400.
func TestPasswordPolicyByteLimit(t *testing.T) {
	// A policy loose enough on char count that only the byte guard can catch it.
	p := PasswordPolicy{MinLength: 8, MaxLength: 50}

	tooLong := "😈😈😈😈😈😈😈😈😈😈😈😈😈😈😈😈😈😈😈" // 19 emojis = 76 bytes, 19 runes
	err := p.Validate(tooLong)
	if err == nil {
		t.Fatalf("Validate(%q) should fail due to 72-byte bcrypt limit", tooLong)
	}
	if !errors.Is(err, e.ErrorWrongParams) {
		t.Errorf("Validate should return ErrorWrongParams, got %v", err)
	}
}
