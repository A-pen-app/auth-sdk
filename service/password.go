package service

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	e "github.com/A-pen-app/errors"
	"golang.org/x/crypto/bcrypt"
)

// PasswordPolicy defines the rules a plaintext password must satisfy before it
// is hashed and stored. Use DefaultPasswordPolicy for the recommended settings;
// override per service via WithPasswordPolicy.
type PasswordPolicy struct {
	MinLength    int // minimum length, counted in characters (runes)
	MaxLength    int // maximum length, counted in characters (runes)
	RequireUpper bool
	RequireLower bool
	RequireDigit bool
}

// DefaultPasswordPolicy: 8–20 characters, must contain an uppercase letter, a
// lowercase letter, and a digit. 20 chars stays well under bcrypt's 72-byte
// input limit, so there is no silent truncation.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:    8,
		MaxLength:    20,
		RequireUpper: true,
		RequireLower: true,
		RequireDigit: true,
	}
}

// Validate reports whether password satisfies the policy. Every failure is a
// WRONG_PARAMETER error (mapped to HTTP 400 by callers), never a 500.
func (p PasswordPolicy) Validate(password string) error {
	n := utf8.RuneCountInString(password)
	if n < p.MinLength {
		return fmt.Errorf("%w: password must be at least %d characters", e.ErrorWrongParams, p.MinLength)
	}
	if p.MaxLength > 0 && n > p.MaxLength {
		return fmt.Errorf("%w: password must be at most %d characters", e.ErrorWrongParams, p.MaxLength)
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if p.RequireUpper && !hasUpper {
		return fmt.Errorf("%w: password must contain an uppercase letter", e.ErrorWrongParams)
	}
	if p.RequireLower && !hasLower {
		return fmt.Errorf("%w: password must contain a lowercase letter", e.ErrorWrongParams)
	}
	if p.RequireDigit && !hasDigit {
		return fmt.Errorf("%w: password must contain a digit", e.ErrorWrongParams)
	}
	return nil
}

func HashPassword(password string, cost int) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
