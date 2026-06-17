package models

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
)

type Platform string

const (
	PlatformGoogle   Platform = "google"
	PlatformApple    Platform = "apple"
	PlatformFacebook Platform = "facebook"
	PlatformLINE     Platform = "line"
	PlatformEmail    Platform = "email"
)

type Provider interface {
	Verify(ctx context.Context, token string) (*UserInfo, error)
}

type UserInfo struct {
	ID       string
	Email    string
	Name     string
	PhotoURL string
}

func IsJWT(token string) bool {
	_, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	return err == nil
}
