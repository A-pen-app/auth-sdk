package store

import (
	"context"
	"time"

	"github.com/A-pen-app/auth-sdk/models"
)

type QueryOption func(*Query)

type Query struct {
	Email      string
	PlatformID string
	Platform   models.Platform
}

func BuildQuery(opts ...QueryOption) Query {
	var q Query
	for _, opt := range opts {
		opt(&q)
	}
	return q
}

func ByEmail(email string) QueryOption {
	return func(q *Query) { q.Email = email }
}

func ByPlatformID(id string, platform models.Platform) QueryOption {
	return func(q *Query) { q.PlatformID = id; q.Platform = platform }
}

type UserStore interface {
	Get(ctx context.Context, opts ...QueryOption) (*models.User, error)
	Create(ctx context.Context, params *models.CreateUserParams) (*models.User, error)
	UpdatePassword(ctx context.Context, userID, hashedPassword string) error
}

type Cache interface {
	Get(ctx context.Context, key string, dest any) error
	SetWithTTL(ctx context.Context, key string, value any, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

type EmailSender interface {
	SendOTP(ctx context.Context, email, code string) error
	SendPasswordReset(ctx context.Context, email, code string) error
}
