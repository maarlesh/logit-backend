package api

import (
	"time"

	"github.com/gin-gonic/gin"
)

type CreateRecordRequest struct {
	RecordType RecordType `json:"record_type" binding:"required"`
	CipherText []byte     `json:"cipher_text" binding:"required"`
	Nounce []byte `json:"nounce" binding:"required"`
}


func CreateRecord(c *gin.Context) {
	var req CreateRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ResponseJSON(c, 400, "Invalid input", nil)
		return
	}

	userID, exists := GetUserID(c)

	if !exists {
		ResponseJSON(c, 401, "Unauthorized", nil)
		return
	}

	record := Record{
		RecordType: req.RecordType,
		UserID:     userID,
		Ciphertext: req.CipherText,
		Nonce:      req.Nounce,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := DB.Create(&record).Error; err != nil {
		ResponseJSON(c, 500, "Failed to create record", nil)
		return
	}

	ResponseJSON(c, 201, "Record created successfully", record)
}
