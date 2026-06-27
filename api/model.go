package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type JsonResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func ResponseJSON(c *gin.Context, status int, message string, data any) {
	response := JsonResponse{
		Status:  status,
		Message: message,
		Data:    data,
	}
	c.JSON(status, response)
}

type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformWeb     Platform = "web"
)

type Device struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	Platform  Platform  `json:"platform"`
}

type User struct {
    ID uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    Email       string    `json:"email" gorm:"uniqueIndex"`
    Password    string    `json:"password"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

