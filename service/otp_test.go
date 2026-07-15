package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type mockCache struct {
	mu   sync.Mutex
	data map[string]any
}

func newMockCache() *mockCache {
	return &mockCache{data: make(map[string]any)}
}

func (m *mockCache) Get(_ context.Context, key string, dest any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	ptr, ok := dest.(*string)
	if !ok {
		return fmt.Errorf("dest must be *string")
	}
	*ptr = v.(string)
	return nil
}

func (m *mockCache) SetWithTTL(_ context.Context, key string, value any, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func TestOTPGenerateAndVerify(t *testing.T) {
	otp := NewOTP(newMockCache())
	ctx := context.Background()

	code, err := otp.Generate(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	if err := otp.Verify(ctx, "user@example.com", code); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
}

func TestOTPVerifyWrongCode(t *testing.T) {
	otp := NewOTP(newMockCache())
	ctx := context.Background()

	_, err := otp.Generate(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := otp.Verify(ctx, "user@example.com", "000000"); err == nil {
		t.Fatal("Verify should fail on wrong code")
	}
}

func TestOTPVerifyDeletesCode(t *testing.T) {
	otp := NewOTP(newMockCache())
	ctx := context.Background()

	code, _ := otp.Generate(ctx, "user@example.com")
	_ = otp.Verify(ctx, "user@example.com", code)

	if err := otp.Verify(ctx, "user@example.com", code); err == nil {
		t.Fatal("Verify should fail after code is consumed")
	}
}

func TestOTPCheckDoesNotConsume(t *testing.T) {
	otp := NewOTP(newMockCache())
	ctx := context.Background()

	code, _ := otp.Generate(ctx, "user@example.com")

	// Check succeeds and leaves the code in place — repeatable.
	if err := otp.Check(ctx, "user@example.com", code); err != nil {
		t.Fatalf("Check should succeed: %v", err)
	}
	if err := otp.Check(ctx, "user@example.com", code); err != nil {
		t.Fatalf("Check should still succeed (non-consuming): %v", err)
	}

	// Verify then consumes it, after which Check fails.
	if err := otp.Verify(ctx, "user@example.com", code); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
	if err := otp.Check(ctx, "user@example.com", code); err == nil {
		t.Fatal("Check should fail after the code is consumed")
	}
}

func TestOTPCheckWrongCode(t *testing.T) {
	otp := NewOTP(newMockCache())
	ctx := context.Background()

	_, _ = otp.Generate(ctx, "user@example.com")

	if err := otp.Check(ctx, "user@example.com", "000000"); err == nil {
		t.Fatal("Check should fail on wrong code")
	}
}

func TestOTPCustomOptions(t *testing.T) {
	otp := NewOTP(newMockCache(),
		WithKeyPrefix("custom:"),
		WithOTPTTL(5*time.Minute),
		WithLength(8),
		WithDigits(8),
	)
	ctx := context.Background()

	code, err := otp.Generate(ctx, "test")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != 8 {
		t.Fatalf("expected 8-char code, got %q", code)
	}
}
