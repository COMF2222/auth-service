package model

import (
	"time"

	"github.com/google/uuid"
)

type UserTokenRequest struct {
	UserID string `form:"user_id" binding:"required,uuid"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	AccessToken  string `json:"access_token" binding:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" binding:"required" example:"d9f8a7b3f2e3c4b5..."`
}

type RefreshTokenRecord struct {
	ID               uuid.UUID `db:"id"`
	UserID           uuid.UUID `db:"user_id"`
	RefreshTokenHash string    `db:"refresh_token_hash"`
	UserAgent        string    `db:"user_agent"`
	IPAddress        string    `db:"ip_address"`
	Revoked          bool      `db:"revoked"`
	CreatedAt        time.Time `db:"created_at"`
}

type WebhookPayload struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Event     string `json:"event"`
}
