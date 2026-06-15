package service

import "testing"

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
