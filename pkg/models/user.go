package models

import (
	"database/sql"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/database"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// User 用户模型
type User struct {
	ID           uint64    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // 不在JSON中显示密码
	CreatedAt    time.Time `json:"created_at"`
}

// EmailVerificationCode 邮箱验证码模型
type EmailVerificationCode struct {
	ID        uint64    `json:"id"`
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateUser 创建新用户
func CreateUser(email, password string) (*User, error) {
	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 插入数据库
	query := `INSERT INTO users (email, password_hash) VALUES (?, ?)`
	result, err := database.DB.Exec(query, email, string(hashedPassword))
	if err != nil {
		logger.Errorf("Failed to create user: %v", err)
		return nil, err
	}

	// 获取插入的ID
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// 返回用户信息
	user := &User{
		ID:           uint64(id),
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	logger.Infof("User created successfully: %s", email)
	return user, nil
}

// GetUserByEmail 根据邮箱获取用户
func GetUserByEmail(email string) (*User, error) {
	user := &User{}
	query := `SELECT id, email, password_hash, created_at FROM users WHERE email = ?`

	err := database.DB.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // 用户不存在
		}
		logger.Errorf("Failed to get user by email: %v", err)
		return nil, err
	}

	return user, nil
}

// GetUserByID 根据ID获取用户
func GetUserByID(id uint64) (*User, error) {
	user := &User{}
	query := `SELECT id, email, password_hash, created_at FROM users WHERE id = ?`

	err := database.DB.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // 用户不存在
		}
		logger.Errorf("Failed to get user by ID: %v", err)
		return nil, err
	}

	return user, nil
}

// VerifyPassword 验证密码
func (u *User) VerifyPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// CreateVerificationCode 创建邮箱验证码
func CreateVerificationCode(email, code string, expiresAt time.Time) error {
	query := `INSERT INTO email_verification_codes (email, code, expires_at) VALUES (?, ?, ?)`
	_, err := database.DB.Exec(query, email, code, expiresAt)
	if err != nil {
		logger.Errorf("Failed to create verification code: %v", err)
		return err
	}

	logger.Infof("Verification code created for email: %s", email)
	return nil
}

// VerifyCode 验证邮箱验证码
func VerifyCode(email, code string) (bool, error) {
	var id uint64
	var used bool
	var expiresAt time.Time

	query := `SELECT id, used, expires_at FROM email_verification_codes 
			  WHERE email = ? AND code = ? ORDER BY created_at DESC LIMIT 1`

	err := database.DB.QueryRow(query, email, code).Scan(&id, &used, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // 验证码不存在
		}
		logger.Errorf("Failed to verify code: %v", err)
		return false, err
	}

	// 检查是否已使用
	if used {
		return false, nil
	}

	// 检查是否过期
	if time.Now().After(expiresAt) {
		return false, nil
	}

	// 标记为已使用
	updateQuery := `UPDATE email_verification_codes SET used = 1 WHERE id = ?`
	_, err = database.DB.Exec(updateQuery, id)
	if err != nil {
		logger.Errorf("Failed to mark code as used: %v", err)
		return false, err
	}

	logger.Infof("Verification code verified successfully for email: %s", email)
	return true, nil
}
