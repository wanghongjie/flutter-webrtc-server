package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// contextKey 是 context 键的私有类型，用于避免不同包之间的键冲突
type contextKey string

const (
	// UserIDKey 是 context 中存储用户 ID 的键
	UserIDKey contextKey = "user_id"
	// EmailKey 是 context 中存储用户邮箱的键
	EmailKey contextKey = "email"
)

func getJWTSecret() ([]byte, error) {
	secret := strings.TrimSpace(os.Getenv("AUTH_JWT_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("JWT_SECRET"))
	}
	if secret == "" {
		return nil, fmt.Errorf("jwt secret not configured")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("jwt secret too short")
	}
	return []byte(secret), nil
}

type Claims struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateToken generates a new JWT token for the user
func GenerateToken(userID uint64, email string) (string, error) {
	// Token expires in 30 days
	expirationTime := time.Now().Add(24 * time.Hour * 30)
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "rephone-security",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret, err := getJWTSecret()
	if err != nil {
		return "", err
	}
	return token.SignedString(secret)
}

// ValidateToken parses and validates the JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	secret, err := getJWTSecret()
	if err != nil {
		return nil, err
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// AuthMiddleware is a middleware that validates the JWT token
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid authorization header format"})
			return
		}

		tokenString := parts[1]
		claims, err := ValidateToken(tokenString)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid token"})
			return
		}

		// 将解析后的用户信息写入 context，链式调用保留所有值
		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, EmailKey, claims.Email)
		next(w, r.WithContext(ctx))
	}
}

// EmailFromContext 从 context 中取出 AuthMiddleware 注入的 email。
//
// 若未注入则返回 ("", false)，调用方按需决定是否强制校验。
func EmailFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(EmailKey).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// UserIDFromContext 从 context 中取出 AuthMiddleware 注入的 user_id。
//
// 若未注入则返回 (0, false)。
func UserIDFromContext(ctx context.Context) (uint64, bool) {
	v, ok := ctx.Value(UserIDKey).(uint64)
	if !ok || v == 0 {
		return 0, false
	}
	return v, true
}
