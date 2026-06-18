package service

import (
	"context"
	"errors"
	"testing"

	e "github.com/A-pen-app/errors"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/A-pen-app/auth-sdk/store"
)

type mockProvider struct {
	info *models.UserInfo
	err  error
}

func (p *mockProvider) Verify(_ context.Context, _ string) (*models.UserInfo, error) {
	return p.info, p.err
}

type mockStore struct {
	users           map[string]*models.User
	created         *models.CreateUserParams
	createUser      *models.User
	createErr       error
	updatedID       string
	updatedPassword string
}

func newMockStore() *mockStore {
	return &mockStore{
		users: make(map[string]*models.User),
	}
}

func (s *mockStore) addByEmail(email string, u *models.User) {
	s.users["email:"+email] = u
}

func (s *mockStore) addByPlatformID(id string, platform models.Platform, u *models.User) {
	s.users["platform:"+string(platform)+":"+id] = u
}

func (s *mockStore) Get(_ context.Context, opts ...store.QueryOption) (*models.User, error) {
	q := store.BuildQuery(opts...)
	if q.Email != "" {
		u, ok := s.users["email:"+q.Email]
		if !ok {
			return nil, e.ErrorNotFound
		}
		return u, nil
	}
	if q.PlatformID != "" {
		u, ok := s.users["platform:"+string(q.Platform)+":"+q.PlatformID]
		if !ok {
			return nil, e.ErrorNotFound
		}
		return u, nil
	}
	return nil, e.ErrorNotFound
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

func (s *mockStore) UpdatePassword(_ context.Context, userID, hashedPassword string) error {
	s.updatedID = userID
	s.updatedPassword = hashedPassword
	return nil
}

type mockEmailSender struct {
	otpEmail     string
	otpCode      string
	resetEmail   string
	resetCode    string
	sendOTPErr   error
	sendResetErr error
}

func (m *mockEmailSender) SendOTP(_ context.Context, email, code string) error {
	m.otpEmail = email
	m.otpCode = code
	return m.sendOTPErr
}

func (m *mockEmailSender) SendPasswordReset(_ context.Context, email, code string) error {
	m.resetEmail = email
	m.resetCode = code
	return m.sendResetErr
}

// --- OAuth tests ---

func TestLoginByOAuth(t *testing.T) {
	ms := newMockStore()
	ms.addByPlatformID("gid-123", models.PlatformGoogle, &models.User{ID: "uid-1", Email: "a@b.com"})

	svc := NewAuth(ms, WithProvider(models.PlatformGoogle, &mockProvider{
		info: &models.UserInfo{ID: "gid-123", Email: "a@b.com", Name: "Test"},
	}))

	user, info, err := svc.LoginByOAuth(context.Background(), models.PlatformGoogle, "token")
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
	ms := newMockStore()
	svc := NewAuth(ms, WithProvider(models.PlatformGoogle, &mockProvider{
		info: &models.UserInfo{ID: "gid-999"},
	}))

	_, info, err := svc.LoginByOAuth(context.Background(), models.PlatformGoogle, "token")
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

func TestSignUpByOAuth(t *testing.T) {
	ms := newMockStore()
	ms.createUser = &models.User{ID: "new-id", Email: "a@b.com"}

	svc := NewAuth(ms, WithProvider(models.PlatformGoogle, &mockProvider{
		info: &models.UserInfo{ID: "gid-123", Email: "a@b.com", Name: "Test", PhotoURL: "http://photo"},
	}))

	user, info, err := svc.SignUpByOAuth(context.Background(), models.PlatformGoogle, "token")
	if err != nil {
		t.Fatalf("SignUpByOAuth: %v", err)
	}
	if user.ID != "new-id" {
		t.Fatalf("expected new-id, got %s", user.ID)
	}
	if info.Name != "Test" {
		t.Fatalf("expected name Test, got %s", info.Name)
	}
	if ms.created.PlatformUserID != "gid-123" {
		t.Fatalf("expected platform user ID gid-123, got %s", ms.created.PlatformUserID)
	}
	if ms.created.Platform != models.PlatformGoogle {
		t.Fatalf("expected platform google, got %s", ms.created.Platform)
	}
}

// --- Email login tests ---

func TestLoginByEmail(t *testing.T) {
	hashed, _ := HashPassword("secret", 10)
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", Email: "a@b.com", HashedPassword: &hashed})

	svc := NewAuth(ms)

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
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", HashedPassword: &hashed})

	svc := NewAuth(ms)
	_, err := svc.LoginByEmail(context.Background(), "a@b.com", "wrong")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestLoginByEmailNoPassword(t *testing.T) {
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1"})

	svc := NewAuth(ms)
	_, err := svc.LoginByEmail(context.Background(), "a@b.com", "secret")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestSignUpByEmail(t *testing.T) {
	ms := newMockStore()
	ms.createUser = &models.User{ID: "new-id", Email: "a@b.com"}

	svc := NewAuth(ms, WithBcryptCost(10))

	user, err := svc.SignUpByEmail(context.Background(), "a@b.com", "secret123")
	if err != nil {
		t.Fatalf("SignUpByEmail: %v", err)
	}
	if user.ID != "new-id" {
		t.Fatalf("expected new-id, got %s", user.ID)
	}
	if ms.created.HashedPassword == nil {
		t.Fatal("expected hashed password to be set")
	}
	if err := VerifyPassword(*ms.created.HashedPassword, "secret123"); err != nil {
		t.Fatalf("password should verify: %v", err)
	}
	if ms.created.Platform != models.PlatformEmail {
		t.Fatalf("expected platform email, got %s", ms.created.Platform)
	}
}

// --- OTP tests ---

func TestLoginByOTP(t *testing.T) {
	cache := newMockCache()
	otp := NewOTP(cache)
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", Email: "a@b.com"})

	svc := NewAuth(ms, WithOTP(otp))
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
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1"})

	svc := NewAuth(ms, WithOTP(otp))
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

func TestSendOTP(t *testing.T) {
	cache := newMockCache()
	otp := NewOTP(cache)
	sender := &mockEmailSender{}

	svc := NewAuth(newMockStore(), WithOTP(otp), WithEmailSender(sender))
	ctx := context.Background()

	if err := svc.SendOTP(ctx, "a@b.com"); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}
	if sender.otpEmail != "a@b.com" {
		t.Fatalf("expected email a@b.com, got %s", sender.otpEmail)
	}
	if sender.otpCode == "" {
		t.Fatal("expected code to be set")
	}
}

func TestVerifyOTP(t *testing.T) {
	cache := newMockCache()
	otp := NewOTP(cache)

	svc := NewAuth(newMockStore(), WithOTP(otp))
	ctx := context.Background()

	code, _ := otp.Generate(ctx, "a@b.com")
	if err := svc.VerifyOTP(ctx, "a@b.com", code); err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}
}

// --- ChangePassword tests ---

func TestChangePassword(t *testing.T) {
	hashed, _ := HashPassword("oldpw", 10)
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", Email: "a@b.com", HashedPassword: &hashed})

	svc := NewAuth(ms, WithBcryptCost(10))
	ctx := context.Background()

	if err := svc.ChangePassword(ctx, "a@b.com", "oldpw", "newpw"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if ms.updatedID != "uid-1" {
		t.Fatalf("expected updated user uid-1, got %s", ms.updatedID)
	}
	if err := VerifyPassword(ms.updatedPassword, "newpw"); err != nil {
		t.Fatalf("new password should verify: %v", err)
	}
}

func TestChangePasswordWrongOld(t *testing.T) {
	hashed, _ := HashPassword("oldpw", 10)
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", HashedPassword: &hashed})

	svc := NewAuth(ms)
	err := svc.ChangePassword(context.Background(), "a@b.com", "wrong", "newpw")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

func TestChangePasswordNoPassword(t *testing.T) {
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1"})

	svc := NewAuth(ms)
	err := svc.ChangePassword(context.Background(), "a@b.com", "old", "new")
	if !errors.Is(err, e.ErrorUnauthorized) {
		t.Fatalf("expected ErrorUnauthorized, got %v", err)
	}
}

// --- Password reset tests ---

func TestSendPasswordReset(t *testing.T) {
	hashed, _ := HashPassword("pw", 10)
	cache := newMockCache()
	resetOTP := NewOTP(cache, WithKeyPrefix("reset_code:"))
	sender := &mockEmailSender{}
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", HashedPassword: &hashed})

	svc := NewAuth(ms, WithResetOTP(resetOTP), WithEmailSender(sender))
	ctx := context.Background()

	if err := svc.SendPasswordReset(ctx, "a@b.com"); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	if sender.resetEmail != "a@b.com" {
		t.Fatalf("expected email a@b.com, got %s", sender.resetEmail)
	}
	if sender.resetCode == "" {
		t.Fatal("expected reset code to be set")
	}
}

func TestSendPasswordResetNoUser(t *testing.T) {
	cache := newMockCache()
	resetOTP := NewOTP(cache, WithKeyPrefix("reset_code:"))
	sender := &mockEmailSender{}

	svc := NewAuth(newMockStore(), WithResetOTP(resetOTP), WithEmailSender(sender))

	err := svc.SendPasswordReset(context.Background(), "nobody@b.com")
	if err != nil {
		t.Fatalf("expected nil (account enumeration prevention), got %v", err)
	}
	if sender.resetEmail != "" {
		t.Fatal("should not send email when user not found")
	}
}

func TestSendPasswordResetNoPassword(t *testing.T) {
	cache := newMockCache()
	resetOTP := NewOTP(cache, WithKeyPrefix("reset_code:"))
	sender := &mockEmailSender{}
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1"})

	svc := NewAuth(ms, WithResetOTP(resetOTP), WithEmailSender(sender))

	err := svc.SendPasswordReset(context.Background(), "a@b.com")
	if err != nil {
		t.Fatalf("expected nil (no password user), got %v", err)
	}
	if sender.resetEmail != "" {
		t.Fatal("should not send email when user has no password")
	}
}

func TestResetPassword(t *testing.T) {
	hashed, _ := HashPassword("oldpw", 10)
	cache := newMockCache()
	resetOTP := NewOTP(cache, WithKeyPrefix("reset_code:"))
	ms := newMockStore()
	ms.addByEmail("a@b.com", &models.User{ID: "uid-1", HashedPassword: &hashed})

	svc := NewAuth(ms, WithResetOTP(resetOTP), WithBcryptCost(10))
	ctx := context.Background()

	code, _ := resetOTP.Generate(ctx, "a@b.com")

	if err := svc.ResetPassword(ctx, "a@b.com", code, "newpw"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if ms.updatedID != "uid-1" {
		t.Fatalf("expected updated user uid-1, got %s", ms.updatedID)
	}
	if err := VerifyPassword(ms.updatedPassword, "newpw"); err != nil {
		t.Fatalf("new password should verify: %v", err)
	}
}

func TestResetPasswordWrongCode(t *testing.T) {
	cache := newMockCache()
	resetOTP := NewOTP(cache, WithKeyPrefix("reset_code:"))
	ms := newMockStore()

	svc := NewAuth(ms, WithResetOTP(resetOTP))

	err := svc.ResetPassword(context.Background(), "a@b.com", "wrong", "newpw")
	if err == nil {
		t.Fatal("expected error on wrong reset code")
	}
}
