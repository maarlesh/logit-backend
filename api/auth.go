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
	"golang.org/x/crypto/bcrypt"
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

    authKeyHash, err := bcrypt.GenerateFromPassword([]byte(req.AuthKey), bcrypt.DefaultCost)
    if err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to process credentials", nil)
        return
    }

    user := User{
        Email:           req.Email,
        AuthKeyHash:     string(authKeyHash),
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

type KdfParamsResponse struct {
    KdfSalt   []byte    `json:"kdf_salt"`
    KdfParams KdfParams `json:"kdf_params"`
}

// GetKdfParams lets a client that has no local copy of a user's KDF salt/params (e.g. a fresh
// device) fetch them by email before deriving auth_key for Login. No credentials required —
// these values aren't secret on their own, only useful alongside the password.
func GetKdfParams(c *gin.Context) {
    email := c.Query("email")
    if email == "" {
        ResponseJSON(c, http.StatusBadRequest, "email is required", nil)
        return
    }

    var user User
    if err := DB.Where("email = ?", email).First(&user).Error; err != nil {
        ResponseJSON(c, http.StatusNotFound, "Account not found", nil)
        return
    }

    ResponseJSON(c, http.StatusOK, "ok", KdfParamsResponse{
        KdfSalt:   user.KdfSalt,
        KdfParams: user.KdfParams,
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

    if err := bcrypt.CompareHashAndPassword([]byte(user.AuthKeyHash), []byte(req.AuthKey)); err != nil {
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

