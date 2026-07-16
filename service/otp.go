package service

import (
	"context"
	"fmt"
	"time"

	"github.com/A-pen-app/auth-sdk/store"
	"github.com/sethvargo/go-password/password"
)

type OTPOption func(*OTP)

func WithKeyPrefix(prefix string) OTPOption {
	return func(o *OTP) { o.keyPrefix = prefix }
}

func WithOTPTTL(ttl time.Duration) OTPOption {
	return func(o *OTP) { o.ttl = ttl }
}

func WithLength(length int) OTPOption {
	return func(o *OTP) { o.length = length }
}

func WithDigits(digits int) OTPOption {
	return func(o *OTP) { o.digits = digits }
}

type OTP struct {
	cache     store.Cache
	keyPrefix string
	ttl       time.Duration
	length    int
	digits    int
}

func NewOTP(cache store.Cache, opts ...OTPOption) *OTP {
	o := &OTP{
		cache:     cache,
		keyPrefix: "verify_code:",
		ttl:       10 * time.Minute,
		length:    6,
		digits:    6,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func (o *OTP) Generate(ctx context.Context, key string) (string, error) {
	code, err := password.Generate(o.length, o.digits, 0, true, true)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	if err := o.cache.SetWithTTL(ctx, o.keyPrefix+key, code, o.ttl); err != nil {
		return "", fmt.Errorf("store otp: %w", err)
	}
	return code, nil
}

// Check verifies the code WITHOUT consuming it: a successful check leaves the
// code in place so it can still be spent later by Verify. Use it for a
// pre-validation step (e.g. confirm a reset code before collecting the new
// password).
func (o *OTP) Check(ctx context.Context, key, code string) error {
	var stored string
	if err := o.cache.Get(ctx, o.keyPrefix+key, &stored); err != nil {
		return fmt.Errorf("otp not found or expired: %w", err)
	}
	if code != stored {
		return fmt.Errorf("otp mismatch")
	}
	return nil
}

// Verify checks the code and, on success, consumes it (single use).
func (o *OTP) Verify(ctx context.Context, key, code string) error {
	if err := o.Check(ctx, key, code); err != nil {
		return err
	}
	o.cache.Delete(ctx, o.keyPrefix+key)
	return nil
}
