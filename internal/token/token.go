package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	signingKey string
}

func NewManager(signingKey string) (*Manager, error) {
	if signingKey == "" {
		return nil, errors.New("empty signing key")
	}

	return &Manager{signingKey: signingKey}, nil
}

func (m *Manager) NewJWT(userId string, sessionID string, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":        userId,
		"session_id": sessionID,
		"exp":        time.Now().Add(ttl).Unix(),
	})

	return token.SignedString([]byte(m.signingKey))
}

func (m *Manager) Parse(accessToken string) (string, error) {
	token, err := jwt.Parse(accessToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(m.signingKey), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("error get user claims from token")
	}

	return claims["sub"].(string), nil
}

func (m *Manager) NewRefreshToken() (string, string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", "", err
	}

	token := base64.StdEncoding.EncodeToString(b)

	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return token, string(hashed), nil
}

func (m *Manager) VerifyRefreshToken(storedHash, providedToken string) error {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(providedToken))
	return err
}
