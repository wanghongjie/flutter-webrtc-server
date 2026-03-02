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

		// Add claims to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(r.Context(), "email", claims.Email)
		next(w, r.WithContext(ctx))
	}
}
