package main

import (
	"logit-backend/api"

	"github.com/gin-gonic/gin"
)

func main() {
	db := api.InitDB()

	r := gin.Default()
	
	r.POST("/user", func(c *gin.Context) {
		api.CreateUser(db, c)
	})
	
	r.Run(":8080")
}