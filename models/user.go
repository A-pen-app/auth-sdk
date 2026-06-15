package models

type User struct {
	ID             string
	Email          string
	HashedPassword *string
}

type CreateUserParams struct {
	PlatformUserID string
	Platform       string
	Email          string
	Name           string
	PhotoURL       string
	HashedPassword *string
}
