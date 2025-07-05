package handler

import (
	"context"
	"hh/internal/model"
	"hh/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *service.TokenService
}

func NewAuthHandler(authService *service.TokenService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) GenerateTokens(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	tokenPair, err := h.authService.GetTokens(context.Background(), userID, userAgent, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error:": err.Error()})
	}

	c.JSON(http.StatusOK, tokenPair)
}

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
