package service

import (
	"context"
	"fmt"

	e "github.com/A-pen-app/errors"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/A-pen-app/auth-sdk/store"
)

type AuthOption func(*authService)

func WithProvider(platform string, p models.Provider) AuthOption {
	return func(s *authService) { s.providers[platform] = p }
}

func WithOTP(otp *OTP) AuthOption {
	return func(s *authService) { s.otp = otp }
}

func WithBcryptCost(cost int) AuthOption {
	return func(s *authService) { s.bcryptCost = cost }
}

type authService struct {
	providers  map[string]models.Provider
	store      store.UserStore
	otp        *OTP
	bcryptCost int
}

func NewAuth(us store.UserStore, opts ...AuthOption) Auth {
	s := &authService{
		providers:  make(map[string]models.Provider),
		store:      us,
		bcryptCost: 10,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *authService) VerifyOAuth(ctx context.Context, platform, token string) (*models.UserInfo, error) {
	p, ok := s.providers[platform]
	if !ok {
		return nil, fmt.Errorf("%w: %s", e.ErrorWrongParams, platform)
	}
	return p.Verify(ctx, token)
}

func (s *authService) LoginByOAuth(ctx context.Context, platform, token string) (*models.User, *models.UserInfo, error) {
	info, err := s.VerifyOAuth(ctx, platform, token)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.store.GetByPlatformID(ctx, info.ID, platform)
	if err != nil {
		return nil, info, err
	}
	return user, info, nil
}

func (s *authService) LoginByEmail(ctx context.Context, email, password string) (*models.User, error) {
	user, err := s.store.GetByEmail(ctx, email)
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
	return s.store.GetByEmail(ctx, email)
}

func (s *authService) SignUpByOAuth(ctx context.Context, platform, token string) (*models.User, *models.UserInfo, error) {
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
	hashed, err := HashPassword(password, s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return s.store.Create(ctx, &models.CreateUserParams{
		Email:          email,
		HashedPassword: &hashed,
	})
}
