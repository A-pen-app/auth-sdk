package service

import (
	"context"

	"github.com/A-pen-app/auth-sdk/models"
)

type Auth interface {
	VerifyOAuth(ctx context.Context, platform, token string) (*models.UserInfo, error)
	LoginByOAuth(ctx context.Context, platform, token string) (*models.User, *models.UserInfo, error)
	LoginByEmail(ctx context.Context, email, password string) (*models.User, error)
	LoginByOTP(ctx context.Context, email, code string) (*models.User, error)
	SignUpByOAuth(ctx context.Context, platform, token string) (*models.User, *models.UserInfo, error)
	SignUpByEmail(ctx context.Context, email, password string) (*models.User, error)
}
