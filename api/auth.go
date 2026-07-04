package api

import (
	"crypto/sha256"
	"errors"
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

    accessToken, refreshToken, err := createSession(user.ID)
    if err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to create session", nil)
        return
    }

    ResponseJSON(c, http.StatusCreated, "registered successfully", LoginResponse{
        AccessToken:     accessToken,
        RefreshToken:    refreshToken,
        KdfSalt:         user.KdfSalt,
        KdfParams:       user.KdfParams,
        WrappedVaultKey: user.WrappedVaultKey,
        VaultKeyNonce:   user.VaultKeyNonce,
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

    accessToken, refreshToken, err := createSession(user.ID)
    if err != nil {
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

// createSession issues an access token and creates a Session row backing a new refresh token.
func createSession(userID uuid.UUID) (accessToken string, refreshToken string, err error) {
    accessToken, err = generateAccessToken(userID.String())
    if err != nil {
        return "", "", err
    }

    refreshToken = uuid.New().String()
    session := Session{
        UserID:           userID,
        RefreshTokenHash: hashToken(refreshToken),
        ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
    }
    if err := DB.Create(&session).Error; err != nil {
        return "", "", err
    }

    return accessToken, refreshToken, nil
}

func jwtSecret() []byte {
    return []byte(os.Getenv("JWT_SECRET"))
}

func generateAccessToken(userID string) (string, error) {
    claims := jwt.MapClaims{
        "sub": userID,
        "exp": time.Now().Add(24 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret())
}

// ParseAccessToken validates the JWT (signature, alg, expiry) and returns the user ID from "sub".
func ParseAccessToken(tokenString string) (uuid.UUID, error) {
    token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
        return jwtSecret(), nil
    }, jwt.WithValidMethods([]string{"HS256"}))
    if err != nil || !token.Valid {
        return uuid.Nil, errors.New("invalid or expired token")
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return uuid.Nil, errors.New("invalid token claims")
    }

    sub, ok := claims["sub"].(string)
    if !ok {
        return uuid.Nil, errors.New("missing sub claim")
    }

    userID, err := uuid.Parse(sub)
    if err != nil {
        return uuid.Nil, errors.New("invalid sub claim")
    }

    return userID, nil
}

// SHA-256 hash for storing refresh tokens — fast is fine here since
// refresh tokens are high-entropy UUIDs, not low-entropy passwords
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return fmt.Sprintf("%x", h)
}

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}

func Refresh(c *gin.Context) {
    var req RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        ResponseJSON(c, http.StatusBadRequest, "Invalid input", nil)
        return
    }

    var session Session
    if err := DB.Where("refresh_token_hash = ?", hashToken(req.RefreshToken)).First(&session).Error; err != nil {
        ResponseJSON(c, http.StatusUnauthorized, "Invalid refresh token", nil)
        return
    }

    if session.ExpiresAt.Before(time.Now()) {
        DB.Delete(&session)
        ResponseJSON(c, http.StatusUnauthorized, "Refresh token expired", nil)
        return
    }

    accessToken, err := generateAccessToken(session.UserID.String())
    if err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to generate token", nil)
        return
    }

    // Rotate the refresh token so a stolen one stops working once the legitimate client refreshes.
    newRefreshToken := uuid.New().String()
    session.RefreshTokenHash = hashToken(newRefreshToken)
    session.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
    if err := DB.Save(&session).Error; err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to refresh session", nil)
        return
    }

    ResponseJSON(c, http.StatusOK, "token refreshed", RefreshResponse{
        AccessToken:  accessToken,
        RefreshToken: newRefreshToken,
    })
}

func Logout(c *gin.Context) {
    userID, ok := GetUserID(c)
    if !ok {
        ResponseJSON(c, http.StatusUnauthorized, "Invalid session", nil)
        return
    }

    var req RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        ResponseJSON(c, http.StatusBadRequest, "Invalid input", nil)
        return
    }

    var session Session
    if err := DB.Where("refresh_token_hash = ?", hashToken(req.RefreshToken)).First(&session).Error; err != nil || session.UserID != userID {
        ResponseJSON(c, http.StatusUnauthorized, "Invalid session", nil)
        return
    }

    if err := DB.Delete(&session).Error; err != nil {
        ResponseJSON(c, http.StatusInternalServerError, "Failed to log out", nil)
        return
    }

    ResponseJSON(c, http.StatusOK, "logged out", nil)
}

