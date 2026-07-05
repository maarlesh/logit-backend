package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CreateRecordRequest struct {
	RecordType RecordType `json:"record_type" binding:"required"`
	CipherText []byte     `json:"cipher_text" binding:"required"`
	Nounce     []byte     `json:"nounce" binding:"required"`
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

func GetRecords(c *gin.Context) {
	userID, exists := GetUserID(c)

	if !exists {
		ResponseJSON(c, 401, "Unauthorized", nil)
		return
	}

	queryRecordType := c.Query("record_type")

	if queryRecordType != "" {
		var records []Record
		if err := DB.Where("user_id = ? AND record_type = ?", userID, queryRecordType).Find(&records).Error; err != nil {
			ResponseJSON(c, 500, "Failed to fetch records", nil)
			return
		} else {
			ResponseJSON(c, 200, "Records fetched successfully", records)
			return
		}
	}

	var records []Record
	if err := DB.Where("user_id = ?", userID).Find(&records).Error; err != nil {
		ResponseJSON(c, 500, "Failed to fetch records", nil)
		return
	}

	ResponseJSON(c, 200, "Records fetched successfully", records)
}

func UpdateRecord(c *gin.Context) {
	userID, exists := GetUserID(c)
	if !exists {
		ResponseJSON(c, 401, "Unauthorized", nil)
		return
	}

	recordID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ResponseJSON(c, 400, "Invalid record id", nil)
		return
	}

	var req CreateRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ResponseJSON(c, 400, "Invalid input", nil)
		return
	}

	var record Record
	if err := DB.Where("id = ? AND user_id = ?", recordID, userID).First(&record).Error; err != nil {
		ResponseJSON(c, 404, "Record not found", nil)
		return
	}

	record.RecordType = req.RecordType
	record.Ciphertext = req.CipherText
	record.Nonce = req.Nounce
	record.UpdatedAt = time.Now()

	if err := DB.Save(&record).Error; err != nil {
		ResponseJSON(c, 500, "Failed to update record", nil)
		return
	}

	ResponseJSON(c, 200, "Record updated successfully", record)
}

func DeleteRecord(c *gin.Context) {
	userID, exists := GetUserID(c)
	if !exists {
		ResponseJSON(c, 401, "Unauthorized", nil)
		return
	}

	recordID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ResponseJSON(c, 400, "Invalid record id", nil)
		return
	}

	var record Record
	if err := DB.Where("id = ? AND user_id = ?", recordID, userID).First(&record).Error; err != nil {
		ResponseJSON(c, 404, "Record not found", nil)
		return
	}

	if err := DB.Delete(&record).Error; err != nil {
		ResponseJSON(c, 500, "Failed to delete record", nil)
		return
	}

	ResponseJSON(c, 200, "Record deleted successfully", nil)
}