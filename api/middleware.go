package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const userIDContextKey = "userID"

// AuthMiddleware validates the Bearer access token and attaches the user ID to the context.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
			ResponseJSON(c, http.StatusUnauthorized, "Missing or malformed authorization header", nil)
			c.Abort()
			return
		}

		userID, err := ParseAccessToken(parts[1])
		fmt.Println("Parsed userID:", userID, "Error:", err)
		if err != nil {
			ResponseJSON(c, http.StatusUnauthorized, "Invalid or expired token", err)
			c.Abort()
			return
		}

		c.Set(userIDContextKey, userID)
		c.Next()
	}
}

// GetUserID returns the user ID attached by AuthMiddleware.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	value, exists := c.Get(userIDContextKey)
	if !exists {
		return uuid.Nil, false
	}
	userID, ok := value.(uuid.UUID)
	return userID, ok
}
