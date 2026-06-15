package service

import (
	"context"
	"errors"
	"testing"

	e "github.com/A-pen-app/errors"

	"github.com/A-pen-app/auth-sdk/models"
)

type mockProvider struct {
	info *models.UserInfo
	err  error
}

func (p *mockProvider) Verify(_ context.Context, _ string) (*models.UserInfo, error) {
	return p.info, p.err
}

type mockStore struct {
	byPlatform map[string]*models.User
	byEmail    map[string]*models.User
	created    *models.CreateUserParams
	createUser *models.User
	createErr  error
}

func newMockStore() *mockStore {
	return &mockStore{
		byPlatform: make(map[string]*models.User),
		byEmail:    make(map[string]*models.User),
	}
}

func (s *mockStore) GetByPlatformID(_ context.Context, platformUserID, platform string) (*models.User, error) {
	u, ok := s.byPlatform[platform+":"+platformUserID]
	if !ok {
		return nil, e.ErrorNotFound
	}
	return u, nil
}

func (s *mockStore) GetByEmail(_ context.Context, email string) (*models.User, error) {
	u, ok := s.byEmail[email]
	if !ok {
		return nil, e.ErrorNotFound
	}
	return u, nil
}

func (s *mockStore) Create(_ context.Context, params *models.CreateUserParams) (*models.User, error) {
	s.created = params
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.createUser != nil {
		return s.createUser, nil
	}
	return &models.User{ID: "new-id", Email: params.Email}, nil
}

func TestLoginByOAuth(t *testing.T) {
	store := newMockStore()
	store.byPlatform["google:gid-123"] = &models.User{ID: "uid-1", Email: "a@b.com"}

	svc := NewAuth(store, WithProvider("google", &mockProvider{
		info: &models.UserInfo{ID: "gid-123", Email: "a@b.com", Name: "Test"},
	}))

	user, info, err := svc.LoginByOAuth(context.Background(), "google", "token")
	if err != nil {
		t.Fatalf("LoginByOAuth: %v", err)
	}
	if user.ID != "uid-1" {
		t.Fatalf("expected uid-1, got %s", user.ID)
	}
	if info.Name != "Test" {
		t.Fatalf("expected name Test, got %s", info.Name)
	}
}

func TestLoginByOAuthUserNotFound(t *testing.T) {
	store := newMockStore()
	svc := NewAuth(store, WithProvider("google", &mockProvider{
		info: &models.UserInfo{ID: "gid-999"},
	}))

	_, info, err := svc.LoginByOAuth(context.Background(), "google", "token")
	if !errors.Is(err, e.ErrorNotFound) {
		t.Fatalf("expected ErrorNotFound, got %v", err)
	}
	if info == nil || info.ID != "gid-999" {
		t.Fatal("should still return UserInfo on user not found")
	}
}

func TestLoginByOAuthUnknownProvider(t *testing.T) {
	svc := NewAuth(newMockStore())
	_, _, err := svc.LoginByOAuth(context.Background(), "unknown", "token")
	if !errors.Is(err, e.ErrorWrongParams) {
		t.Fatalf("expected ErrorWrongParams, got %v", err)
	}
}

func TestLoginByEmail(t *testing.T) {
	hashed, _ := HashPassword("secret", 10)
	store := newMockStore()
	store.byEmail["a@b.com"] = &models.User{ID: "uid-1", Email: "a@b.com", HashedPassword: &hashed}

	svc := NewAuth(store)

	user, err := svc.LoginByEmail(context.Background(), "a@b.com", "secret")
	if err != nil {
		t.Fatalf("LoginByEmail: %v", err)
	}
	if user.ID != "uid-1" {
		t.Fatalf("expected uid-1, got %s", user.ID)
	}
}

func TestLoginByEmailWrongPassword(t *testing.T) {
	hashed, _ := HashPassword("secret", 10)
	store := newMockStore()
	store.byEmail["a@b.com"] = &models.User{ID: "uid-1", HashedPassword: &hashed}

	svc := NewAuth(store)
	_, err := svc.LoginByEmail(context.Background(), "a@b.com", "wrong")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestLoginByEmailNoPassword(t *testing.T) {
	store := newMockStore()
	store.byEmail["a@b.com"] = &models.User{ID: "uid-1"}

	svc := NewAuth(store)
	_, err := svc.LoginByEmail(context.Background(), "a@b.com", "secret")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestLoginByOTP(t *testing.T) {
	cache := newMockCache()
	otp := NewOTP(cache)
	store := newMockStore()
	store.byEmail["a@b.com"] = &models.User{ID: "uid-1", Email: "a@b.com"}

	svc := NewAuth(store, WithOTP(otp))
	ctx := context.Background()

	code, err := otp.Generate(ctx, "a@b.com")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	user, err := svc.LoginByOTP(ctx, "a@b.com", code)
	if err != nil {
		t.Fatalf("LoginByOTP: %v", err)
	}
	if user.ID != "uid-1" {
		t.Fatalf("expected uid-1, got %s", user.ID)
	}
}

func TestLoginByOTPWrongCode(t *testing.T) {
	cache := newMockCache()
	otp := NewOTP(cache)
	store := newMockStore()
	store.byEmail["a@b.com"] = &models.User{ID: "uid-1"}

	svc := NewAuth(store, WithOTP(otp))
	ctx := context.Background()

	_, _ = otp.Generate(ctx, "a@b.com")
	_, err := svc.LoginByOTP(ctx, "a@b.com", "000000")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestLoginByOTPNotConfigured(t *testing.T) {
	svc := NewAuth(newMockStore())
	_, err := svc.LoginByOTP(context.Background(), "a@b.com", "123456")
	if err == nil {
		t.Fatal("expected error when OTP not configured")
	}
}

func TestSignUpByOAuth(t *testing.T) {
	store := newMockStore()
	store.createUser = &models.User{ID: "new-id", Email: "a@b.com"}

	svc := NewAuth(store, WithProvider("google", &mockProvider{
		info: &models.UserInfo{ID: "gid-123", Email: "a@b.com", Name: "Test", PhotoURL: "http://photo"},
	}))

	user, info, err := svc.SignUpByOAuth(context.Background(), "google", "token")
	if err != nil {
		t.Fatalf("SignUpByOAuth: %v", err)
	}
	if user.ID != "new-id" {
		t.Fatalf("expected new-id, got %s", user.ID)
	}
	if info.Name != "Test" {
		t.Fatalf("expected name Test, got %s", info.Name)
	}
	if store.created.PlatformUserID != "gid-123" {
		t.Fatalf("expected platform user ID gid-123, got %s", store.created.PlatformUserID)
	}
	if store.created.Platform != "google" {
		t.Fatalf("expected platform google, got %s", store.created.Platform)
	}
}

func TestSignUpByEmail(t *testing.T) {
	store := newMockStore()
	store.createUser = &models.User{ID: "new-id", Email: "a@b.com"}

	svc := NewAuth(store, WithBcryptCost(10))

	user, err := svc.SignUpByEmail(context.Background(), "a@b.com", "secret123")
	if err != nil {
		t.Fatalf("SignUpByEmail: %v", err)
	}
	if user.ID != "new-id" {
		t.Fatalf("expected new-id, got %s", user.ID)
	}
	if store.created.HashedPassword == nil {
		t.Fatal("expected hashed password to be set")
	}
	if err := VerifyPassword(*store.created.HashedPassword, "secret123"); err != nil {
		t.Fatalf("password should verify: %v", err)
	}
}
