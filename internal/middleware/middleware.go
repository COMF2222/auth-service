package middleware

import (
	"context"
	"hh/internal/repository"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Middleware struct {
	repo *repository.TokenRepository
}

func NewMiddleware(repo *repository.TokenRepository) *Middleware {
	return &Middleware{repo: repo}
}

func AuthMiddleware(m *Middleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует токен"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Невалидный токен"})
			return
		}

		userID, ok := claims["sub"].(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверный payload токена"})
			return
		}

		sessionID, ok := claims["session_id"].(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			return
		}

		storedSession, err := m.repo.GetCurrentSessionID(context.Background(), userID)
		if err != nil || sessionID != storedSession {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session revoked"})
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}
