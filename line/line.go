package line

import (
	"context"
	"fmt"

	"github.com/A-pen-app/auth-sdk/models"
	linelogin "github.com/kkdai/line-login-sdk-go"
)

type LINE struct {
	channelID     string
	channelSecret string
	client        *linelogin.Client
}

func New(channelID, channelSecret string) (*LINE, error) {
	client, err := linelogin.New(channelID, channelSecret)
	if err != nil {
		return nil, fmt.Errorf("line client init: %w", err)
	}
	return &LINE{
		channelID:     channelID,
		channelSecret: channelSecret,
		client:        client,
	}, nil
}

func (l *LINE) Verify(ctx context.Context, token string) (*models.UserInfo, error) {
	if models.IsJWT(token) {
		return l.verifyIDToken(ctx, token)
	}
	return l.verifyAccessToken(ctx, token)
}

func (l *LINE) verifyIDToken(_ context.Context, token string) (*models.UserInfo, error) {
	resp, err := l.client.VerifyIDToken(token, linelogin.VerifyIDTokenRequestOptions{}).Do()
	if err != nil {
		return nil, fmt.Errorf("line id token verify: %w", err)
	}
	return &models.UserInfo{
		ID:       resp.Sub,
		Email:    resp.Email,
		Name:     resp.Name,
		PhotoURL: resp.Picture,
	}, nil
}

func (l *LINE) verifyAccessToken(_ context.Context, token string) (*models.UserInfo, error) {
	if _, err := l.client.TokenVerify(token).Do(); err != nil {
		return nil, fmt.Errorf("line access token verify: %w", err)
	}
	resp, err := l.client.GetUserProfile(token).Do()
	if err != nil {
		return nil, fmt.Errorf("line get profile: %w", err)
	}
	return &models.UserInfo{
		ID:       resp.UserID,
		Name:     resp.DisplayName,
		PhotoURL: resp.PictureURL,
	}, nil
}
