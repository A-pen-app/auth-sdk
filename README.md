# auth-sdk

Shared authentication SDK for A-pen-app services. Provides OAuth provider verification, password hashing, OTP, email sending, password management, and login/signup orchestration.

## Structure

```
auth-sdk/
├── models/       # Platform enum, Provider interface, UserInfo, User, CreateUserParams
├── service/      # Auth service (login/signup/OTP/password), OTP, password utils
├── store/        # UserStore (QueryOption), Cache, EmailSender interfaces
├── google/       # Google OAuth provider
├── apple/        # Apple Sign In provider
├── facebook/     # Facebook OAuth provider (access token + ID token)
└── line/         # LINE Login provider (access token + ID token)
```

## Setup

```go
import (
    "github.com/A-pen-app/auth-sdk/models"
    "github.com/A-pen-app/auth-sdk/service"
    "github.com/A-pen-app/auth-sdk/google"
    "github.com/A-pen-app/auth-sdk/apple"
    "github.com/A-pen-app/auth-sdk/facebook"
    "github.com/A-pen-app/auth-sdk/line"
)

lineProvider, err := line.New(channelID, channelSecret)

otp := service.NewOTP(redisCache,
    service.WithKeyPrefix("verify_code:"),
    service.WithOTPTTL(10*time.Minute),
    service.WithLength(6),
    service.WithDigits(6),
)

resetOTP := service.NewOTP(redisCache,
    service.WithKeyPrefix("reset_code:"),
    service.WithOTPTTL(30*time.Minute),
    service.WithLength(6),
    service.WithDigits(6),
)

authSvc := service.NewAuth(myUserStore,
    service.WithProvider(models.PlatformGoogle, google.New(
        google.WithIOSClientID(iosID),
        google.WithAndroidClientID(androidID),
        google.WithWebClientID(webID),
    )),
    service.WithProvider(models.PlatformApple, apple.New(
        apple.WithIOSClientID(bundleID),
        apple.WithWebClientID(serviceID),
    )),
    service.WithProvider(models.PlatformFacebook, facebook.New(fbAppID, fbAppSecret)),
    service.WithProvider(models.PlatformLINE, lineProvider),
    service.WithOTP(otp),
    service.WithResetOTP(resetOTP),
    service.WithEmailSender(myEmailSender),
    service.WithBcryptCost(14),
)
```

## Auth Service

```go
// OAuth
info, err := authSvc.VerifyOAuth(ctx, models.PlatformGoogle, token)

// Login
user, info, err := authSvc.LoginByOAuth(ctx, models.PlatformGoogle, token)
user, err := authSvc.LoginByEmail(ctx, email, password)
user, err := authSvc.LoginByOTP(ctx, email, code)

// Sign up
user, info, err := authSvc.SignUpByOAuth(ctx, models.PlatformGoogle, token)
user, err := authSvc.SignUpByEmail(ctx, email, password)

// OTP
err := authSvc.SendOTP(ctx, email)        // generate + send email
err := authSvc.VerifyOTP(ctx, email, code) // verify + consume

// Password management
err := authSvc.ChangePassword(ctx, email, oldPassword, newPassword)
err := authSvc.SendPasswordReset(ctx, email)              // silent on not found
err := authSvc.ResetPassword(ctx, email, code, newPassword)
```

## Password Utilities

```go
hashed, err := service.HashPassword(password, 14)
err := service.VerifyPassword(hashedPassword, password)
```

## Interfaces

Consumer repos implement these:

### store.UserStore

```go
type UserStore interface {
    Get(ctx context.Context, opts ...QueryOption) (*models.User, error)
    Create(ctx context.Context, params *models.CreateUserParams) (*models.User, error)
    UpdatePassword(ctx context.Context, userID, hashedPassword string) error
}
```

Query by email or platform ID using functional options:

```go
user, err := userStore.Get(ctx, store.ByEmail(email))
user, err := userStore.Get(ctx, store.ByPlatformID(id, models.PlatformGoogle))
```

Consumer implementation example:

```go
func (s *myStore) Get(ctx context.Context, opts ...store.QueryOption) (*models.User, error) {
    q := store.BuildQuery(opts...)
    if q.Email != "" {
        return s.getByEmail(ctx, q.Email)
    }
    if q.PlatformID != "" {
        return s.getByPlatformID(ctx, q.PlatformID, q.Platform)
    }
    return nil, errors.New("no query condition")
}
```

### store.Cache

```go
type Cache interface {
    Get(ctx context.Context, key string, dest any) error
    SetWithTTL(ctx context.Context, key string, value any, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}
```

### store.EmailSender

```go
type EmailSender interface {
    SendOTP(ctx context.Context, email, code string) error
    SendPasswordReset(ctx context.Context, email, code string) error
}
```

Consumer controls email templates, subject, and delivery method (email-svc, SES, SendGrid, etc.).
