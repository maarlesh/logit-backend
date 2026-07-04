package main

import (
	"log"
	"logit-backend/api"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()

	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET must be set")
	}

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/auth/register", func(c *gin.Context) {
		api.Register(c)
	})
	r.GET("/auth/kdf-params", func(c *gin.Context) {
		api.GetKdfParams(c)
	})
	r.POST("/auth/login", func(c *gin.Context) {
		api.Login(c)
	})
	r.POST("/auth/refresh", func(c *gin.Context) {
		api.Refresh(c)
	})

	protected := r.Group("/")
	protected.Use(api.AuthMiddleware())
	protected.POST("/auth/logout", func(c *gin.Context) {
		api.Logout(c)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r.Run(":" + port)
}
