package main

import (
	"hh/config"
	"hh/internal/handler"
	"hh/internal/repository"
	"hh/internal/service"
	"hh/internal/token"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	sigingKey := cfg.JWTSecret
	httpClient := http.DefaultClient
	httpClient = &http.Client{}
	if err != nil {
		log.Fatal("Ошибка загрузки конфига", err)
	}

	db, err := repository.NewPostgresDB(cfg)
	if err != nil {
		log.Fatal("Ошибка подключения к БД", err)
	}
	defer db.Close()

	tokenRepo := repository.NewTokenRepository(db, httpClient, cfg)

	tokenManager, err := token.NewManager(sigingKey)
	if err != nil {
		log.Fatal("Ошибка инициализации tokenManager", err)
	}

	tokenService := service.NewTokenService(tokenManager, tokenRepo)

	authHandler := handler.NewAuthHandler(tokenService)

	r := gin.Default()

	r.GET("/tokens", authHandler.GenerateTokens)
	r.POST("/refresh", authHandler.RefreshTokens)

	r.Run(":8082")
}
