package google

import (
	"context"
	"fmt"
	"net/http"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/oauth2/v1"
	"google.golang.org/api/option"
)

type Option func(*Google)

func WithIOSClientID(id string) Option {
	return func(g *Google) { g.clientIDs["ios"] = id }
}

func WithAndroidClientID(id string) Option {
	return func(g *Google) { g.clientIDs["android"] = id }
}

func WithWebClientID(id string) Option {
	return func(g *Google) { g.clientIDs["web"] = id }
}

type Google struct {
	clientIDs map[string]string
}

func New(opts ...Option) *Google {
	g := &Google{clientIDs: make(map[string]string)}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func (g *Google) Verify(ctx context.Context, token string) (*models.UserInfo, error) {
	svc, err := oauth2.NewService(ctx, option.WithHTTPClient(&http.Client{}))
	if err != nil {
		return nil, fmt.Errorf("google oauth2 service: %w", err)
	}

	info, err := svc.Tokeninfo().IdToken(token).Do()
	if err != nil {
		return nil, fmt.Errorf("google token verify: %w", err)
	}

	if !g.isAllowedClientID(info.Audience) {
		return nil, fmt.Errorf("google: unknown client ID %s", info.Audience)
	}

	name, photoURL := profileClaims(token)
	return &models.UserInfo{
		ID:       info.UserId,
		Email:    info.Email,
		Name:     name,
		PhotoURL: photoURL,
	}, nil
}

// profileClaims reads the display fields out of an id_token. tokeninfo only
// returns the verification fields (user_id/email/audience), so the profile has
// to come from the token's own claims. Parsing is unverified on purpose: the
// caller verified the same token above, and these fields are display-only — a
// malformed payload just yields empty strings.
func profileClaims(token string) (name, photoURL string) {
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(token, claims); err != nil {
		return "", ""
	}
	name, _ = claims["name"].(string)
	photoURL, _ = claims["picture"].(string)
	return name, photoURL
}

func (g *Google) isAllowedClientID(aud string) bool {
	for _, id := range g.clientIDs {
		if id == aud {
			return true
		}
	}
	return false
}
