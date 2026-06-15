package google

import (
	"context"
	"fmt"
	"net/http"

	"github.com/A-pen-app/auth-sdk/models"
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

	if !g.isAllowedAudience(info.Audience) {
		return nil, fmt.Errorf("google: unknown client ID %s", info.Audience)
	}

	return &models.UserInfo{
		ID:    info.UserId,
		Email: info.Email,
	}, nil
}

func (g *Google) isAllowedAudience(aud string) bool {
	for _, id := range g.clientIDs {
		if id == aud {
			return true
		}
	}
	return false
}
