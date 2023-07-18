package models

import (
	"github.com/golang-jwt/jwt/v5"
)

// Create a struct that models the structure of a user in the request body
type Credentials struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
}

// Claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Level    int    `json:"level"`
	jwt.RegisteredClaims
}

// Token is a struct that will be encoded to a JWT
type Token struct {
	Token string `json:"token"`
}
