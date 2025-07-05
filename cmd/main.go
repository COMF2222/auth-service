package main

import (
	"hh/config"
	"hh/internal/handler"
	"hh/internal/middleware"
	"hh/internal/repository"
	"hh/internal/service"
	"hh/internal/token"
	"log"
	"net/http"

	_ "hh/docs"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Auth service
// @version 1.0
// @desription API server for hh.ru

// @host localhost:8082
// @BasePath /

// @securityDefinitions.apiKey ApiKeyAuth
// @in header
// @name Authorization
// @description Введите токен с префиксом `Bearer`, например, «Bearer abcdef12345».

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

	authMiddleware := middleware.NewMiddleware(tokenRepo)

	authHandler := handler.NewAuthHandler(tokenService)

	r := gin.Default()

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/tokens", authHandler.GenerateTokens)
	r.POST("/refresh", authHandler.RefreshTokens)

	r.GET("/me", middleware.AuthMiddleware(authMiddleware), authHandler.GetGUID)
	r.POST("/logout", middleware.AuthMiddleware(authMiddleware), authHandler.Logout)

	r.Run(":8082")
}
