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
