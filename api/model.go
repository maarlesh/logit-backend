package api

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
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
	c.JSON(status, JsonResponse{Status: status, Message: message, Data: data})
}

// KdfParams holds Argon2id parameters stored as JSONB.
// Stored per-user so parameters can be upgraded independently.
type KdfParams struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

func (k KdfParams) Value() (driver.Value, error) {
      b, err := json.Marshal(k)
      if err != nil {
              return nil, err
      }
      return string(b), nil  // string → postgres parses as json/jsonb
}

func (k *KdfParams) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("KdfParams: expected []byte from db")
	}
	return json.Unmarshal(b, k)
}

type User struct {
	ID              uuid.UUID `json:"id"         gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Email           string    `json:"email"       gorm:"uniqueIndex;not null"`
	AuthKeyHash     string    `json:"-"           gorm:"not null"`
	KdfSalt         []byte    `json:"kdf_salt"    gorm:"type:bytea;not null"`
	KdfParams       KdfParams `json:"kdf_params"  gorm:"type:jsonb;not null"`
	WrappedVaultKey []byte    `json:"-"           gorm:"type:bytea;not null"`
	VaultKeyNonce   []byte    `json:"-"           gorm:"type:bytea;not null"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RecordType string

const (
	RecordTypeExpense RecordType = "expense"
	RecordTypeIncome  RecordType = "income"
	RecordTypeAccount RecordType = "account"
)

type Record struct {
	ID         uuid.UUID  `json:"id"          gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID     uuid.UUID  `json:"user_id"     gorm:"type:uuid;not null;index"`
	RecordType RecordType `json:"record_type" gorm:"type:text;not null;index"`
	Ciphertext []byte     `json:"ciphertext"  gorm:"type:bytea;not null"`
	Nonce      []byte     `json:"nonce"       gorm:"type:bytea;not null"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type Session struct {
	ID               uuid.UUID `json:"id"      gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID           uuid.UUID `json:"-"       gorm:"type:uuid;not null;index"`
	RefreshTokenHash string    `json:"-"       gorm:"not null"`
	ExpiresAt        time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt        time.Time `json:"created_at"`
}
