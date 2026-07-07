package service

import (
	"context"
	"errors"
	"fmt"

	e "github.com/A-pen-app/errors"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/A-pen-app/auth-sdk/store"
)

type AuthOption func(*authService)

func WithProvider(platform models.Platform, p models.Provider) AuthOption {
	return func(s *authService) { s.providers[platform] = p }
}

func WithOTP(otp *OTP) AuthOption {
	return func(s *authService) { s.otp = otp }
}

func WithResetOTP(otp *OTP) AuthOption {
	return func(s *authService) { s.resetOTP = otp }
}

func WithEmailSender(sender store.EmailSender) AuthOption {
	return func(s *authService) { s.emailSender = sender }
}

func WithBcryptCost(cost int) AuthOption {
	return func(s *authService) { s.bcryptCost = cost }
}

// WithPasswordPolicy overrides the rules new passwords must satisfy at signup,
// reset, and change. Defaults to DefaultPasswordPolicy.
func WithPasswordPolicy(p PasswordPolicy) AuthOption {
	return func(s *authService) { s.passwordPolicy = p }
}

type authService struct {
	providers      map[models.Platform]models.Provider
	store          store.UserStore
	otp            *OTP
	resetOTP       *OTP
	emailSender    store.EmailSender
	bcryptCost     int
	passwordPolicy PasswordPolicy
}

func NewAuth(us store.UserStore, opts ...AuthOption) Auth {
	s := &authService{
		providers:      make(map[models.Platform]models.Provider),
		store:          us,
		bcryptCost:     10,
		passwordPolicy: DefaultPasswordPolicy(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *authService) VerifyOAuth(ctx context.Context, platform models.Platform, token string) (*models.UserInfo, error) {
	p, ok := s.providers[platform]
	if !ok {
		return nil, fmt.Errorf("%w: %s", e.ErrorWrongParams, platform)
	}
	return p.Verify(ctx, token)
}

func (s *authService) LoginByOAuth(ctx context.Context, platform models.Platform, token string) (*models.User, *models.UserInfo, error) {
	info, err := s.VerifyOAuth(ctx, platform, token)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.store.Get(ctx, store.ByPlatformID(info.ID, platform))
	if err != nil {
		return nil, info, err
	}
	return user, info, nil
}

func (s *authService) LoginByEmail(ctx context.Context, email, password string) (*models.User, error) {
	user, err := s.store.Get(ctx, store.ByEmail(email))
	if err != nil {
		return nil, err
	}
	if user.HashedPassword == nil {
		return nil, e.ErrorUnauthorized
	}
	if err := VerifyPassword(*user.HashedPassword, password); err != nil {
		return nil, e.ErrorUnauthorized
	}
	return user, nil
}

func (s *authService) LoginByOTP(ctx context.Context, email, code string) (*models.User, error) {
	if s.otp == nil {
		return nil, fmt.Errorf("auth: otp not configured")
	}
	if err := s.otp.Verify(ctx, email, code); err != nil {
		return nil, e.ErrorUnauthorized
	}
	return s.store.Get(ctx, store.ByEmail(email))
}

func (s *authService) SignUpByOAuth(ctx context.Context, platform models.Platform, token string) (*models.User, *models.UserInfo, error) {
	info, err := s.VerifyOAuth(ctx, platform, token)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.store.Create(ctx, &models.CreateUserParams{
		PlatformUserID: info.ID,
		Platform:       platform,
		Email:          info.Email,
		Name:           info.Name,
		PhotoURL:       info.PhotoURL,
	})
	if err != nil {
		return nil, info, err
	}
	return user, info, nil
}

func (s *authService) SignUpByEmail(ctx context.Context, email, password string) (*models.User, error) {
	if err := s.passwordPolicy.Validate(password); err != nil {
		return nil, err
	}
	hashed, err := HashPassword(password, s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return s.store.Create(ctx, &models.CreateUserParams{
		Platform:       models.PlatformEmail,
		Email:          email,
		HashedPassword: &hashed,
	})
}

func (s *authService) SendOTP(ctx context.Context, email string) error {
	if s.otp == nil {
		return fmt.Errorf("auth: otp not configured")
	}
	if s.emailSender == nil {
		return fmt.Errorf("auth: email sender not configured")
	}
	code, err := s.otp.Generate(ctx, email)
	if err != nil {
		return err
	}
	return s.emailSender.SendOTP(ctx, email, code)
}

func (s *authService) VerifyOTP(ctx context.Context, email, code string) error {
	if s.otp == nil {
		return fmt.Errorf("auth: otp not configured")
	}
	return s.otp.Verify(ctx, email, code)
}

func (s *authService) ChangePassword(ctx context.Context, email, oldPassword, newPassword string) error {
	user, err := s.store.Get(ctx, store.ByEmail(email))
	if err != nil {
		return err
	}
	if user.HashedPassword == nil {
		return e.ErrorUnauthorized
	}
	if err := VerifyPassword(*user.HashedPassword, oldPassword); err != nil {
		return e.ErrorUnauthorized
	}
	if err := s.passwordPolicy.Validate(newPassword); err != nil {
		return err
	}
	hashed, err := HashPassword(newPassword, s.bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return s.store.UpdatePassword(ctx, user.ID, hashed)
}

func (s *authService) SendPasswordReset(ctx context.Context, email string) error {
	if s.resetOTP == nil {
		return fmt.Errorf("auth: reset otp not configured")
	}
	if s.emailSender == nil {
		return fmt.Errorf("auth: email sender not configured")
	}
	user, err := s.store.Get(ctx, store.ByEmail(email))
	if err != nil {
		if errors.Is(err, e.ErrorNotFound) {
			return nil
		}
		return err
	}
	if user.HashedPassword == nil {
		return nil
	}
	code, err := s.resetOTP.Generate(ctx, email)
	if err != nil {
		return err
	}
	return s.emailSender.SendPasswordReset(ctx, email, code)
}

func (s *authService) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	if s.resetOTP == nil {
		return fmt.Errorf("auth: reset otp not configured")
	}
	if err := s.resetOTP.Verify(ctx, email, code); err != nil {
		return err
	}
	if err := s.passwordPolicy.Validate(newPassword); err != nil {
		return err
	}
	hashed, err := HashPassword(newPassword, s.bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	user, err := s.store.Get(ctx, store.ByEmail(email))
	if err != nil {
		return err
	}
	return s.store.UpdatePassword(ctx, user.ID, hashed)
}
