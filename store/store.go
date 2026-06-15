package store

import (
	"context"
	"time"

	"github.com/A-pen-app/auth-sdk/models"
)

type UserStore interface {
	GetByPlatformID(ctx context.Context, platformUserID, platform string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Create(ctx context.Context, params *models.CreateUserParams) (*models.User, error)
}

type Cache interface {
	Get(ctx context.Context, key string, dest any) error
	SetWithTTL(ctx context.Context, key string, value any, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}
