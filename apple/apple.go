package apple

import (
	"context"
	"errors"
	"fmt"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

const jwksURL = "https://appleid.apple.com/auth/keys"

type Option func(*Apple)

func WithIOSClientID(id string) Option {
	return func(a *Apple) { a.clientIDs["ios"] = id }
}

func WithWebClientID(id string) Option {
	return func(a *Apple) { a.clientIDs["web"] = id }
}

type Apple struct {
	clientIDs map[string]string
}

func New(opts ...Option) *Apple {
	a := &Apple{clientIDs: make(map[string]string)}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Apple) Verify(_ context.Context, token string) (*models.UserInfo, error) {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("apple jwks fetch: %w", err)
	}

	t, err := jwt.Parse(token, jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("apple token parse: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return nil, errors.New("apple: invalid token claims")
	}

	aud, _ := claims["aud"].(string)
	if !a.isAllowedClientID(aud) {
		return nil, fmt.Errorf("apple: wrong audience %s", aud)
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("apple: missing sub claim")
	}

	info := &models.UserInfo{ID: sub}

	_, isPrivate := claims["is_private_email"]
	if !isPrivate {
		if email, ok := claims["email"].(string); ok {
			info.Email = email
		}
	}

	return info, nil
}

func (a *Apple) isAllowedClientID(aud string) bool {
	for _, id := range a.clientIDs {
		if id == aud {
			return true
		}
	}
	return false
}
