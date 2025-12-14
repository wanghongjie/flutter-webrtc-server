package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// Service wraps dependencies required for authentication related handlers.
type Service struct {
	DB *sql.DB
}

type User struct {
	ID    uint64 `json:"id"`
	Email string `json:"email"`
}

type jsonResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, resp jsonResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// generateCode returns a numeric verification code with the given length.
func generateCode(length int) string {
	if length <= 0 {
		return ""
	}
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			// fallback to '0' on error
			b[i] = '0'
			continue
		}
		b[i] = byte('0') + byte(n.Int64())
	}
	return string(b)
}

type checkEmailRequest struct {
	Email string `json:"email"`
}

// HandleCheckEmail verifies if an email has been registered.
// If not registered it will generate a verification code and (in real deployments)
// send it via email. For now it just logs the code.
func (s *Service) HandleCheckEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req checkEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	email := req.Email
	if email == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email required"})
		return
	}

	var count int
	err := s.DB.QueryRow("SELECT COUNT(1) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		logger.Errorf("check email query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// already registered
	if count > 0 {
		writeJSON(w, http.StatusOK, jsonResponse{
			Success: true,
			Data: map[string]bool{
				"registered": true,
			},
		})
		return
	}

	// not registered: create verification code
	code := generateCode(6)
	expiresAt := time.Now().Add(10 * time.Minute)

	_, err = s.DB.Exec(
		"INSERT INTO email_verification_codes (email, code, expires_at) VALUES (?, ?, ?)",
		email, code, expiresAt,
	)
	if err != nil {
		logger.Errorf("insert verification code error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// TODO: integrate with real email service. For now just log the code.
	logger.Infof("Send verification code %s to email %s", code, email)

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: map[string]bool{
			"registered": false,
		},
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HandleLogin authenticates a user by email and password.
func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and password required"})
		return
	}

	var (
		id           uint64
		passwordHash string
	)
	err := s.DB.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", req.Email).
		Scan(&id, &passwordHash)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or password"})
		return
	} else if err != nil {
		logger.Errorf("login query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or password"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: User{
			ID:    id,
			Email: req.Email,
		},
	})
}

type verifyCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// HandleVerifyCode checks if an email verification code is valid.
func (s *Service) HandleVerifyCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req verifyCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	var (
		id        uint64
		expiresAt time.Time
		used      bool
	)
	err := s.DB.QueryRow(
		"SELECT id, expires_at, used FROM email_verification_codes WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1",
		req.Email, req.Code,
	).Scan(&id, &expiresAt, &used)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid code"})
		return
	} else if err != nil {
		logger.Errorf("verify code query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if used || time.Now().After(expiresAt) {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "code expired or used"})
		return
	}

	_, _ = s.DB.Exec("UPDATE email_verification_codes SET used = 1 WHERE id = ?", id)

	writeJSON(w, http.StatusOK, jsonResponse{Success: true})
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"` // 验证码现在是可选的
}

// HandleRegister registers a new user with email and password (verification code no longer required).
func (s *Service) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and password required"})
		return
	}

	// check if user already exists
	var count int
	if err := s.DB.QueryRow("SELECT COUNT(1) FROM users WHERE email = ?", req.Email).Scan(&count); err != nil {
		logger.Errorf("check user exists error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	if count > 0 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email already registered"})
		return
	}

	// 验证码验证通过后，注册不再需要验证码
	// 这里可以添加其他验证逻辑，比如检查是否有有效的验证令牌等

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("hash password error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	res, err := s.DB.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, string(hash))
	if err != nil {
		logger.Errorf("insert user error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	userID, _ := res.LastInsertId()

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: User{
			ID:    uint64(userID),
			Email: req.Email,
		},
	})
}
