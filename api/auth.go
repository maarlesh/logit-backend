package api

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RegisterRequest struct {
    Email           string    `json:"email"             binding:"required,email"`
    AuthKey         string    `json:"auth_key"          binding:"required"`
    KdfSalt         []byte    `json:"kdf_salt"          binding:"required"`
    KdfParams       KdfParams `json:"kdf_params"        binding:"required"`
    WrappedVaultKey []byte    `json:"wrapped_vault_key" binding:"required"`
    VaultKeyNonce   []byte    `json:"vault_key_nonce"   binding:"required"`
}

func Register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        ResponseJSON(c, http.StatusBadRequest, "Invalid input", nil)
        return
    }

    user := User{
        Email:           req.Email,
        AuthKeyHash:     req.AuthKey, // hash this in next step
        KdfSalt:         req.KdfSalt,
        KdfParams:       req.KdfParams,
        WrappedVaultKey: req.WrappedVaultKey,
        VaultKeyNonce:   req.VaultKeyNonce,
    }

    if err := DB.Create(&user).Error; err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to create user", nil)
        return
    }

    ResponseJSON(c, http.StatusCreated, "registered successfully", gin.H{
        "user_id": user.ID,
    })
}

type LoginRequest struct {
    Email   string `json:"email"    binding:"required,email"`
    AuthKey string `json:"auth_key" binding:"required"`
}

type LoginResponse struct {
    AccessToken     string    `json:"access_token"`
    RefreshToken    string    `json:"refresh_token"`
    KdfSalt         []byte    `json:"kdf_salt"`
    KdfParams       KdfParams `json:"kdf_params"`
    WrappedVaultKey []byte    `json:"wrapped_vault_key"`
    VaultKeyNonce   []byte    `json:"vault_key_nonce"`
}

func Login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        ResponseJSON(c, http.StatusBadRequest, "Invalid input", nil)
        return
    }

    var user User
    if err := DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
        // same message whether email missing or wrong auth_key — avoids user enumeration
        ResponseJSON(c, http.StatusUnauthorized, "Invalid credentials", nil)
        return
    }

    // TODO: replace with Argon2id hash comparison when Register hashes auth_key
    if user.AuthKeyHash != req.AuthKey {
        ResponseJSON(c, http.StatusUnauthorized, "Invalid credentials", nil)
        return
    }

    accessToken, err := generateAccessToken(user.ID.String())
    if err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to generate token", nil)
        return
    }

    refreshToken := uuid.New().String()
    session := Session{
        UserID:           user.ID,
        RefreshTokenHash: hashToken(refreshToken),
        ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
    }
    if err := DB.Create(&session).Error; err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to create session", nil)
        return
    }

    ResponseJSON(c, http.StatusOK, "login successful", LoginResponse{
        AccessToken:     accessToken,
        RefreshToken:    refreshToken,
        KdfSalt:         user.KdfSalt,
        KdfParams:       user.KdfParams,
        WrappedVaultKey: user.WrappedVaultKey,
        VaultKeyNonce:   user.VaultKeyNonce,
    })
}

func generateAccessToken(userID string) (string, error) {
    claims := jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(15 * time.Minute).Unix(),
        "iat": time.Now().Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// SHA-256 hash for storing refresh tokens — fast is fine here since
// refresh tokens are high-entropy UUIDs, not low-entropy passwords
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return fmt.Sprintf("%x", h)
}

