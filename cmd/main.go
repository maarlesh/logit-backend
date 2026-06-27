package main

import (
	"logit-backend/api"

	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()

	r := gin.Default()

	r.POST("/auth/register", func(c *gin.Context) {
		api.Register(c)
	})
	r.POST("/auth/login", func(c *gin.Context) {
		api.Login(c)
	})

	r.Run(":8080")
}
