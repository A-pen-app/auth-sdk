package facebook

import (
	"context"
	"fmt"

	"github.com/A-pen-app/auth-sdk/models"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	fb "github.com/huandu/facebook/v2"
)

const jwksURL = "https://www.facebook.com/.well-known/oauth/openid/jwks/"

type Facebook struct {
	appID     string
	appSecret string
	app       *fb.App
}

func New(appID, appSecret string) *Facebook {
	return &Facebook{
		appID:     appID,
		appSecret: appSecret,
		app:       fb.New(appID, appSecret),
	}
}

func (f *Facebook) Verify(ctx context.Context, token string) (*models.UserInfo, error) {
	if models.IsJWT(token) {
		return f.verifyIDToken(ctx, token)
	}
	return f.verifyAccessToken(ctx, token)
}

func (f *Facebook) verifyAccessToken(_ context.Context, token string) (*models.UserInfo, error) {
	s := f.app.Session(token)
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("facebook access token invalid: %w", err)
	}

	var u struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	res, err := s.Get("/me", fb.Params{
		"fields": "email,name,picture.type(large)",
	})
	if err != nil {
		return nil, fmt.Errorf("facebook get user: %w", err)
	}
	if err := res.Decode(&u); err != nil {
		return nil, fmt.Errorf("facebook decode user: %w", err)
	}

	return &models.UserInfo{
		ID:       u.ID,
		Email:    u.Email,
		Name:     u.Name,
		PhotoURL: u.Picture.Data.URL,
	}, nil
}

func (f *Facebook) verifyIDToken(_ context.Context, idToken string) (*models.UserInfo, error) {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("facebook jwks fetch: %w", err)
	}

	token, err := jwt.Parse(idToken, jwks.Keyfunc)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("facebook id token invalid: %w", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["aud"] != f.appID {
		return nil, fmt.Errorf("facebook: invalid audience")
	}

	info := &models.UserInfo{}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("facebook: missing sub")
	}
	info.ID = sub

	if name, ok := claims["name"].(string); ok {
		info.Name = name
	}
	if email, ok := claims["email"].(string); ok {
		info.Email = email
	}
	if picture, ok := claims["picture"].(string); ok {
		info.PhotoURL = picture
	}

	return info, nil
}
