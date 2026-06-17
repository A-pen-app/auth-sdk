package service

import (
	"context"

	"github.com/A-pen-app/auth-sdk/models"
)

type Auth interface {
	VerifyOAuth(ctx context.Context, platform models.Platform, token string) (*models.UserInfo, error)

	LoginByOAuth(ctx context.Context, platform models.Platform, token string) (*models.User, *models.UserInfo, error)
	LoginByEmail(ctx context.Context, email, password string) (*models.User, error)
	LoginByOTP(ctx context.Context, email, code string) (*models.User, error)

	SignUpByOAuth(ctx context.Context, platform models.Platform, token string) (*models.User, *models.UserInfo, error)
	SignUpByEmail(ctx context.Context, email, password string) (*models.User, error)

	SendOTP(ctx context.Context, email string) error
	VerifyOTP(ctx context.Context, email, code string) error

	ChangePassword(ctx context.Context, email, oldPassword, newPassword string) error
	SendPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, email, code, newPassword string) error
}
