package models

type User struct {
	ID             string
	Email          string
	Name           string
	HashedPassword *string
	GoogleID       *string
	AppleID        *string
	FacebookID     *string
	LineID         *string
}

type CreateUserParams struct {
	PlatformUserID string
	Platform       Platform
	Email          string
	Name           string
	PhotoURL       string
	HashedPassword *string
}
