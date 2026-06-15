package apple

import (
	"context"
	"errors"
	"fmt"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat/go-jwx/jwk"
)

const jwksURL = "https://appleid.apple.com/auth/keys"

type Option func(*Apple)

func WithBundleID(id string) Option {
	return func(a *Apple) { a.audiences["bundle"] = id }
}

func WithWebClientID(id string) Option {
	return func(a *Apple) { a.audiences["web"] = id }
}

type Apple struct {
	audiences map[string]string
}

func New(opts ...Option) *Apple {
	a := &Apple{audiences: make(map[string]string)}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Apple) Verify(_ context.Context, token string) (*models.UserInfo, error) {
	t, err := jwt.Parse(token, a.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("apple token parse: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return nil, errors.New("apple: invalid token claims")
	}

	aud, _ := claims["aud"].(string)
	if !a.isAllowedAudience(aud) {
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

func (a *Apple) isAllowedAudience(aud string) bool {
	for _, id := range a.audiences {
		if id == aud {
			return true
		}
	}
	return false
}

func (a *Apple) keyFunc(token *jwt.Token) (any, error) {
	set, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("apple jwks fetch: %w", err)
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("apple: missing kid in header")
	}

	if keys := set.LookupKeyID(keyID); len(keys) == 1 {
		return keys[0].Materialize()
	}

	return nil, fmt.Errorf("apple: key %q not found", keyID)
}
