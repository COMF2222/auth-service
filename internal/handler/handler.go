package handler

import (
	"context"
	"hh/internal/model"
	"hh/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ErrorResponse struct {
	Error string `json:"error" example:"описание ошибки"`
}

type LogoutResponse struct {
	Message string `json:"message" example:"описание ответа"`
}

type GetGUIDResponse struct {
	UserID string `json:"user_id" example:"описание ответа"`
}

type AuthHandler struct {
	authService *service.TokenService
}

func NewAuthHandler(authService *service.TokenService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// GenerateTokens godoc
// @Summary Generate access and refresh tokens
// @Description Создаёт пару токенов для пользователя по user_id
// @Tags auth
// @Accept json
// @Produce json
// @Param user_id query string true "User ID (GUID)"
// @Success 200 {object} model.TokenPair "Успешный ответ с токенами"
// @Failure 400 {object} ErrorResponse "user_id отсутствует в запросе"
// @Failure 500 {object} ErrorResponse "внутренняя ошибка сервера"
// @Router /tokens [get]
func (h *AuthHandler) GenerateTokens(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	sessionID := uuid.New().String()

	tokenPair, err := h.authService.GetTokens(context.Background(), userID, userAgent, sessionID, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error:": err.Error()})
	}

	c.JSON(http.StatusOK, tokenPair)
}

// RefreshTokens godoc
// @Summary Refresh access and refresh tokens
// @Description Обновляет пару токенов с проверкой старых refresh и access токенов
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.RefreshRequest true "Токены для обновления"
// @Success 200 {object} model.RefreshRequest "Новые токены"
// @Failure 401 {object} ErrorResponse "Невалидный или отозванный токен"
// @Failure 400 {object} ErrorResponse "Неверный запрос"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /refresh [post]
func (h *AuthHandler) RefreshTokens(c *gin.Context) {
	var request model.RefreshRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	tokenPair, err := h.authService.RefreshTokens(context.Background(), request.AccessToken, request.RefreshToken, userAgent, ip)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

// GetGUID godoc
// @Summary Get current user GUID
// @Description Возвращает GUID текущего авторизованного пользователя
// @Tags user
// @Produce json
// @Param Authorization header string true "Access token" default(Bearer <token>)
// @Success 200 {object} GetGUIDResponse "GUID пользователя"
// @Failure 401 {object} ErrorResponse "Неавторизованный доступ или неверный токен"
// @Security ApiKeyAuth
// @Router /me [get]
func (h *AuthHandler) GetGUID(c *gin.Context) {
	userID := c.GetString("user_id")

	c.JSON(200, gin.H{"user_id": userID})

}

// Logout godoc
// @Summary Logout user
// @Description Деавторизация пользователя, отзыв всех токенов
// @Tags auth
// @Produce json
// @Param Authorization header string true "Access token" default(Bearer <token>)
// @Success 200 {object} LogoutResponse "Logout successful"
// @Failure 401 {object} ErrorResponse "Неавторизованный доступ или неверный токен"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Security ApiKeyAuth
// @Router /logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	userID := c.GetString("user_id")

	err := h.authService.Logout(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to deauthorize"})
		return
	}

	c.JSON(200, gin.H{"message": "logout successful"})
}
