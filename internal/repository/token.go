package repository

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hh/internal/model"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/context"

	"hh/config"
)

type TokenRepository struct {
	db         *pgxpool.Pool
	httpClient *http.Client
	cfg        *config.Config
}

func NewTokenRepository(db *pgxpool.Pool, httpClient *http.Client, cfg *config.Config) *TokenRepository {
	return &TokenRepository{db: db, httpClient: httpClient, cfg: cfg}
}

func (r *TokenRepository) GetTokens(ctx context.Context, token model.RefreshTokenRecord) (model.RefreshTokenRecord, error) {
	query := `
		INSERT INTO refresh_tokens (id, user_id, refresh_token_hash, user_agent, ip_address, revoked, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, refresh_token_hash, user_agent, ip_address, revoked, created_at;
	`

	var savedToken model.RefreshTokenRecord
	err := r.db.QueryRow(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.RefreshTokenHash,
		token.UserAgent,
		token.IPAddress,
		token.Revoked,
		token.CreatedAt,
	).Scan(
		&savedToken.ID,
		&savedToken.UserID,
		&savedToken.RefreshTokenHash,
		&savedToken.UserAgent,
		&savedToken.IPAddress,
		&savedToken.Revoked,
		&savedToken.CreatedAt,
	)

	if err != nil {
		return model.RefreshTokenRecord{}, err
	}

	return savedToken, nil
}

func (r *TokenRepository) GetRefreshToken(ctx context.Context, userID string) (*model.RefreshTokenRecord, error) {
	query := `
		SELECT refresh_token_hash, user_agent, ip_address, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1;
	`
	row := r.db.QueryRow(ctx, query, userID)

	var refreshToken model.RefreshTokenRecord
	err := row.Scan(&refreshToken.RefreshTokenHash, &refreshToken.UserAgent, &refreshToken.IPAddress, &refreshToken.Revoked, &refreshToken.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("refreshToken not found")
	}

	return &refreshToken, nil
}

func (r *TokenRepository) RevokeUserTokens(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1 AND revoked = $2
	`

	result, err := r.db.Exec(ctx, query, userID, false)
	if err != nil {
		return fmt.Errorf("не удалось отозвать токены пользователя: %w", err)
	}

	result.RowsAffected()

	return nil
}

func (r *TokenRepository) SendIpChangeWebhook(ctx context.Context, userID, oldIP, userAgent, newIP string) error {
	payload := model.WebhookPayload{
		UserID:    userID,
		IPAddress: newIP,
		UserAgent: userAgent,
		Event:     "ip_address_changed",
	}

	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		r.cfg.WebhookURL,
		bytes.NewBuffer(payloadBytes),
	)
	if err != nil {
		return fmt.Errorf("не удалось создать webhook запрос")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Type", "security.ip_change")
	req.Header.Set("X-Old-IP", oldIP)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка отправки webhook")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook вернул статус %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (r *TokenRepository) GetCurrentSessionID(ctx context.Context, userID string) (string, error) {
	var sessionID string

	query := `
		SELECT id 
		FROM refresh_tokens 
		WHERE user_id = $1 AND revoked = false
		ORDER BY created_at DESC 
		LIMIT 1
	`
	err := r.db.QueryRow(ctx, query, userID).Scan(&sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no active session found for user: %s", userID)
		}
		return "", fmt.Errorf("failed to get current session: %w", err)
	}

	return sessionID, nil

}
