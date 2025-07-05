package service

import (
	"context"
	"fmt"
	"hh/config"
	"hh/internal/model"
	"hh/internal/repository"
	"hh/internal/token"
	"time"

	"github.com/google/uuid"
)

type TokenService struct {
	tokenManager    *token.Manager
	tokenRepository *repository.TokenRepository
	cfg             *config.Config
}

func NewTokenService(tokenManager *token.Manager, tokenRepository *repository.TokenRepository) *TokenService {
	return &TokenService{tokenManager: tokenManager, tokenRepository: tokenRepository}
}

func (s *TokenService) GetTokens(ctx context.Context, userID, userAgent, sessionID, ip string) (*model.TokenPair, error) {
	accessToken, err := s.tokenManager.NewJWT(userID, sessionID, 15*time.Minute)
	if err != nil {
		return &model.TokenPair{}, err
	}

	refreshToken, hashToken, err := s.tokenManager.NewRefreshToken()
	if err != nil {
		return &model.TokenPair{}, err
	}

	tokenID, _ := uuid.NewUUID()

	userUUID, _ := uuid.Parse(userID)

	refreshTokenRecord := model.RefreshTokenRecord{
		ID:               tokenID,
		UserID:           userUUID,
		RefreshTokenHash: hashToken,
		UserAgent:        userAgent,
		IPAddress:        ip,
		Revoked:          false,
		CreatedAt:        time.Now(),
	}

	_, err = s.tokenRepository.GetTokens(ctx, refreshTokenRecord)
	if err != nil {
		return nil, fmt.Errorf("ошибка сохранения refresh token: %w", err)
	}

	return &model.TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *TokenService) RefreshTokens(ctx context.Context, oldAccessToken, oldRefreshToken, userAgent, ip string) (*model.RefreshRequest, error) {
	claims, err := s.tokenManager.Parse(oldAccessToken)
	if err != nil {
		return nil, fmt.Errorf("невалидный токен: %w", err)
	}

	userID := claims

	storedToken, err := s.tokenRepository.GetRefreshToken(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении refresh token: %w", err)
	}

	if storedToken.Revoked {
		return nil, fmt.Errorf("token использован")
	}

	if time.Now().After(storedToken.CreatedAt.Add(24 * time.Hour)) {
		return nil, fmt.Errorf("token истек")
	}

	if err := s.tokenManager.VerifyRefreshToken(storedToken.RefreshTokenHash, oldRefreshToken); err != nil {
		if err := s.tokenRepository.RevokeUserTokens(ctx, userID); err != nil {
			return nil, fmt.Errorf("не удалось отозвать токены: %w", err)
		}
		return nil, fmt.Errorf("невалидный refresh token")
	}

	if storedToken.UserAgent != userAgent {
		if err := s.tokenRepository.RevokeUserTokens(ctx, userID); err != nil {
			return nil, fmt.Errorf("не удалось отозвать токены: %w", err)
		}
		return nil, fmt.Errorf("несоответствие user agent")
	}

	if storedToken.IPAddress != ip && s.cfg.WebhookURL != "" {
		go s.tokenRepository.SendIpChangeWebhook(ctx, userID, storedToken.IPAddress, userAgent, ip)
	}

	if err := s.tokenRepository.RevokeUserTokens(ctx, userID); err != nil {
		return nil, fmt.Errorf("не удалось удалить старые токены: %w", err)
	}

	tokenID, _ := uuid.NewUUID()

	accessToken, err := s.tokenManager.NewJWT(userID, tokenID.String(), 15*time.Minute)
	if err != nil {
		return &model.RefreshRequest{}, err
	}

	refreshToken, hashToken, err := s.tokenManager.NewRefreshToken()
	if err != nil {
		return &model.RefreshRequest{}, err
	}

	userUUID, _ := uuid.Parse(userID)

	refreshTokenRecord := model.RefreshTokenRecord{
		ID:               tokenID,
		UserID:           userUUID,
		RefreshTokenHash: hashToken,
		UserAgent:        userAgent,
		IPAddress:        ip,
		Revoked:          false,
		CreatedAt:        time.Now(),
	}

	_, err = s.tokenRepository.GetTokens(ctx, refreshTokenRecord)
	if err != nil {
		return nil, fmt.Errorf("ошибка сохранения refresh token: %w", err)
	}

	return &model.RefreshRequest{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *TokenService) Logout(ctx context.Context, userID string) error {
	if err := s.tokenRepository.RevokeUserTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	return nil
}
