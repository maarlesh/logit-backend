package main

import (
	"logit-backend/api"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/auth/register", func(c *gin.Context) {
		api.Register(c)
	})
	r.POST("/auth/login", func(c *gin.Context) {
		api.Login(c)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r.Run(":" + port)
}
