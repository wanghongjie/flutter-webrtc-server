package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Service struct {
	DB     *sql.DB
	Mailer Mailer
	FCM    *FCMClient
}

type FCMClient struct {
	ProjectID   string
	Endpoint    string
	TokenSource oauth2.TokenSource
	Client      *http.Client
}

func NewFCMClientFromServiceAccount(saPath, projectID, endpoint string) (*FCMClient, error) {
	if strings.TrimSpace(saPath) == "" || strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("service account path and projectID are required")
	}

	data, err := os.ReadFile(saPath)
	if err != nil {
		return nil, fmt.Errorf("read service account file error: %w", err)
	}

	ctx := context.Background()
	creds, err := google.CredentialsFromJSON(ctx, data, "https://www.googleapis.com/auth/firebase.messaging")
	if err != nil {
		return nil, fmt.Errorf("create credentials from json error: %w", err)
	}

	if endpoint == "" {
		endpoint = fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", projectID)
	}

	return &FCMClient{
		ProjectID:   projectID,
		Endpoint:    endpoint,
		TokenSource: creds.TokenSource,
		Client:      &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (c *FCMClient) SendAlert(token, title, body string, data map[string]string) error {
	if c == nil {
		err := fmt.Errorf("fcm client is nil")
		logger.Errorf("fcm send alert error: %v", err)
		return err
	}
	if strings.TrimSpace(token) == "" {
		err := fmt.Errorf("empty fcm token")
		logger.Errorf("fcm send alert error: %v", err)
		return err
	}

	ctx := context.Background()
	accessToken, err := c.TokenSource.Token()
	if err != nil {
		logger.Errorf("fcm get access token error: %v", err)
		return fmt.Errorf("get fcm access token error: %w", err)
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"token": token,
			"notification": map[string]string{
				"title": title,
				"body":  body,
			},
			"data": data,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		logger.Errorf("fcm marshal payload error: %v", err)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(b))
	if err != nil {
		logger.Errorf("fcm new request error: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken.AccessToken)

	resp, err := c.Client.Do(req)
	if err != nil {
		logger.Errorf("fcm http request error: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("fcm status %d: %s", resp.StatusCode, string(bodyBytes))
		logger.Errorf("fcm send alert error: %v", err)
		return err
	}
	return nil
}

type User struct {
	ID       uint64 `json:"id"`
	Email    string `json:"email"`
	VipLevel uint8  `json:"vip_level"`
	Language string `json:"language,omitempty"`
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

// clientIP tries to get the real client ip (behind proxy) with fallback to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	// r.RemoteAddr is like "ip:port"
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
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
	err := s.DB.QueryRow("SELECT COUNT(1) FROM users WHERE email = ? AND status = 'active'", email).Scan(&count)
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

	if _, err = s.DB.Exec(
		"INSERT INTO email_verification_codes (email, code, expires_at) VALUES (?, ?, ?)",
		email, code, expiresAt,
	); err != nil {
		logger.Errorf("insert verification code error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// Send verification code via email if configured; fallback to log.
	if s.Mailer != nil {
		if err := s.Mailer.SendVerificationCode(email, code); err != nil {
			logger.Errorf("send verification code email error: %v", err)
			// Best-effort cleanup: invalidate latest code if email delivery failed.
			_, _ = s.DB.Exec(
				"UPDATE email_verification_codes SET expires_at = ? WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1",
				time.Now(), email, code,
			)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "failed to send verification email"})
			return
		}
	} else {
		logger.Infof("Send verification code %s to email %s", code, email)
	}

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
	Language string `json:"language,omitempty"`
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

	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.Language = strings.TrimSpace(req.Language)

	if req.Language != "" {
		normalized, ok := normalizeLanguage(req.Language)
		if !ok {
			writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "language must be 'zh-CN' or 'en-US'"})
			return
		}
		req.Language = normalized
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and password required"})
		return
	}

	var (
		id           uint64
		passwordHash string
		vipLevel     uint8
	)
	err := s.DB.QueryRow("SELECT id, password_hash, vip_level FROM users WHERE email = ? AND status = 'active'", req.Email).
		Scan(&id, &passwordHash, &vipLevel)
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

	if req.Language != "" {
		if _, err := s.DB.Exec("UPDATE users SET language = ? WHERE id = ?", req.Language, id); err != nil {
			logger.Errorf("update user language on login error: %v", err)
		}
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: User{
			ID:       id,
			Email:    req.Email,
			VipLevel: vipLevel,
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
	Code     string `json:"code,omitempty"`
	Language string `json:"language,omitempty"`
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

	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.Language = strings.TrimSpace(req.Language)

	if req.Language != "" {
		normalized, ok := normalizeLanguage(req.Language)
		if !ok {
			writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "language must be 'zh-CN' or 'en-US'"})
			return
		}
		req.Language = normalized
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and password required"})
		return
	}

	// check if user already exists
	var (
		currentStatus string
		existingID    uint64
	)
	err := s.DB.QueryRow("SELECT id, status FROM users WHERE email = ?", req.Email).Scan(&existingID, &currentStatus)
	if err != nil && err != sql.ErrNoRows {
		logger.Errorf("check user exists error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if err == nil && currentStatus == "active" {
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

	var (
		userID   int64
		vipLevel uint8
	)
	if err == nil && currentStatus == "deleted" {
		// Reactivate deleted user
		if req.Language != "" {
			_, err = s.DB.Exec("UPDATE users SET password_hash = ?, status = 'active', language = ? WHERE id = ?", string(hash), req.Language, existingID)
		} else {
			_, err = s.DB.Exec("UPDATE users SET password_hash = ?, status = 'active' WHERE id = ?", string(hash), existingID)
		}
		if err != nil {
			logger.Errorf("reactivate user error: %v", err)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
			return
		}
		userID = int64(existingID)
		err = s.DB.QueryRow("SELECT vip_level FROM users WHERE id = ?", existingID).Scan(&vipLevel)
		if err != nil {
			logger.Errorf("query vip_level after reactivate error: %v", err)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
			return
		}
	} else {
		// Insert new user
		res, err := s.DB.Exec("INSERT INTO users (email, password_hash, status, language) VALUES (?, ?, 'active', ?)", req.Email, string(hash), req.Language)
		if err != nil {
			logger.Errorf("insert user error: %v", err)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
			return
		}
		userID, _ = res.LastInsertId()
		vipLevel = 0
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: User{
			ID:       uint64(userID),
			Email:    req.Email,
			VipLevel: vipLevel,
		},
	})
}

// DeviceBinding 设备绑定结构
type DeviceBinding struct {
	ID             uint64    `json:"id"`
	MonitorEmail   string    `json:"monitor_email"`
	CameraEmail    string    `json:"camera_email"`
	CameraDeviceID string    `json:"camera_device_id"`
	CameraName     string    `json:"camera_name"`
	CameraLocation string    `json:"camera_location"`
	CameraOnline   bool      `json:"camera_online"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AddBindingRequest 添加绑定请求
type AddBindingRequest struct {
	MonitorEmail   string `json:"monitor_email"`
	CameraEmail    string `json:"camera_email"`
	CameraDeviceID string `json:"camera_device_id"`
	CameraName     string `json:"camera_name"`
	CameraLocation string `json:"camera_location"`
}

// HandleAddBinding 添加设备绑定关系
func (s *Service) HandleAddBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req AddBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	// 验证必填字段
	if req.MonitorEmail == "" || req.CameraEmail == "" || req.CameraDeviceID == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "monitor_email, camera_email and camera_device_id are required"})
		return
	}

	// 检查是否已存在绑定关系
	var existingID uint64
	err := s.DB.QueryRow(
		"SELECT id FROM device_bindings WHERE monitor_email = ? AND camera_email = ? AND camera_device_id = ?",
		req.MonitorEmail, req.CameraEmail, req.CameraDeviceID,
	).Scan(&existingID)

	if err == nil {
		// 已存在，更新状态为active
		_, err = s.DB.Exec(
			"UPDATE device_bindings SET status = 'active', camera_name = ?, camera_location = ? WHERE id = ?",
			req.CameraName, req.CameraLocation, existingID,
		)
		if err != nil {
			logger.Errorf("update binding error: %v", err)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
			return
		}

		writeJSON(w, http.StatusOK, jsonResponse{
			Success: true,
			Message: "binding updated",
			Data:    map[string]interface{}{"id": existingID},
		})
		return
	} else if err != sql.ErrNoRows {
		logger.Errorf("check binding exists error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// 插入新绑定关系
	res, err := s.DB.Exec(
		"INSERT INTO device_bindings (monitor_email, camera_email, camera_device_id, camera_name, camera_location, status) VALUES (?, ?, ?, ?, ?, 'active')",
		req.MonitorEmail, req.CameraEmail, req.CameraDeviceID, req.CameraName, req.CameraLocation,
	)
	if err != nil {
		logger.Errorf("insert binding error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	bindingID, _ := res.LastInsertId()

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "binding created",
		Data:    map[string]interface{}{"id": bindingID},
	})
}

// UpdateCameraInfoRequest 通过 camera_device_id 更新相机名称/位置
type UpdateCameraInfoRequest struct {
	CameraDeviceID string `json:"camera_device_id"`
	CameraName     string `json:"camera_name"`
	CameraLocation string `json:"camera_location"`
}

// HandleUpdateCameraInfoByDeviceID updates camera_name and camera_location by camera_device_id.
// Note: if same camera_device_id is bound to multiple monitors, it will update all matching rows.
func (s *Service) HandleUpdateCameraInfoByDeviceID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req UpdateCameraInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.CameraDeviceID == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "camera_device_id is required"})
		return
	}
	// 至少更新一个字段
	if req.CameraName == "" && req.CameraLocation == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "camera_name or camera_location is required"})
		return
	}

	res, err := s.DB.Exec(
		"UPDATE device_bindings SET camera_name = COALESCE(NULLIF(?, ''), camera_name), camera_location = COALESCE(NULLIF(?, ''), camera_location) WHERE camera_device_id = ? AND status != 'revoked'",
		req.CameraName, req.CameraLocation, req.CameraDeviceID,
	)
	if err != nil {
		logger.Errorf("update camera info error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, jsonResponse{Success: false, Message: "no binding found for this camera_device_id"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "camera info updated",
		Data:    map[string]interface{}{"affected": affected},
	})
}

// DeleteCameraRequest 通过 camera_device_id 删除(撤销)相机绑定关系
type DeleteCameraRequest struct {
	CameraDeviceID string `json:"camera_device_id"`
}

// HandleDeleteCameraByDeviceID revokes device bindings by camera_device_id.
// It performs a soft-delete by setting status='revoked'.
func (s *Service) HandleDeleteCameraByDeviceID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req DeleteCameraRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.CameraDeviceID == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "camera_device_id is required"})
		return
	}

	res, err := s.DB.Exec(
		"UPDATE device_bindings SET status = 'revoked' WHERE camera_device_id = ? AND status != 'revoked'",
		req.CameraDeviceID,
	)
	if err != nil {
		logger.Errorf("delete(revoke) camera bindings error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, jsonResponse{Success: false, Message: "no binding found for this camera_device_id"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "camera bindings revoked",
		Data:    map[string]interface{}{"affected": affected},
	})
}

// SubmitFeedbackRequest 提交意见反馈请求
type SubmitFeedbackRequest struct {
	Email    string `json:"email"`
	DeviceID string `json:"device_id"`
	Content  string `json:"content"`
	Contact  string `json:"contact"`
}

// HandleSubmitFeedback 提交意见反馈
func (s *Service) HandleSubmitFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req SubmitFeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "content is required"})
		return
	}
	// 简单限制，防止过大内容
	if len(req.Content) > 5000 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "content too long"})
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	res, err := s.DB.Exec(
		"INSERT INTO feedbacks (email, device_id, content, contact, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
		nullIfEmpty(req.Email),
		nullIfEmpty(req.DeviceID),
		req.Content,
		nullIfEmpty(req.Contact),
		nullIfEmpty(ip),
		nullIfEmpty(ua),
	)
	if err != nil {
		logger.Errorf("insert feedback error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	id, _ := res.LastInsertId()

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "feedback submitted",
		Data:    map[string]interface{}{"id": id},
	})
}

func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func normalizeLanguage(lang string) (string, bool) {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return "", true
	}
	lower := strings.ToLower(lang)
	switch lower {
	case "zh-cn":
		return "zh-CN", true
	case "en-us":
		return "en-US", true
	default:
		return "", false
	}
}

type registerPushTokenRequest struct {
	Email    string `json:"email"`
	Platform string `json:"platform"`
	FCMToken string `json:"fcm_token"`
}

type updateLanguageRequest struct {
	Email    string `json:"email"`
	Language string `json:"language"`
}

// HandleRegisterPushToken 保存或更新用户的推送平台和 FCM token。
func (s *Service) HandleRegisterPushToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req registerPushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Platform = strings.ToLower(strings.TrimSpace(req.Platform))
	req.FCMToken = strings.TrimSpace(req.FCMToken)

	if req.Email == "" || req.Platform == "" || req.FCMToken == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email, platform and fcm_token are required"})
		return
	}

	if req.Platform != "android" && req.Platform != "ios" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "platform must be 'android' or 'ios'"})
		return
	}

	if len(req.FCMToken) > 512 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "fcm_token too long"})
		return
	}

	if _, err := s.DB.Exec(
		"UPDATE users SET platform = ?, fcm_token = ? WHERE email = ? AND status = 'active'",
		req.Platform,
		req.FCMToken,
		req.Email,
	); err != nil {
		logger.Errorf("update push token error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "push token registered",
	})
}

func (s *Service) HandleUpdateLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req updateLanguageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Language = strings.TrimSpace(req.Language)

	if req.Email == "" || req.Language == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and language are required"})
		return
	}

	normalized, ok := normalizeLanguage(req.Language)
	if !ok {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "language must be 'zh-CN' or 'en-US'"})
		return
	}
	req.Language = normalized

	if _, err := s.DB.Exec("UPDATE users SET language = ? WHERE email = ? AND status = 'active'", req.Language, req.Email); err != nil {
		logger.Errorf("update user language error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "language updated",
	})
}

type pushAlertRequest struct {
	Email     string `json:"email"`
	Platform  string `json:"platform"`
	Timestamp int64  `json:"timestamp"`
	CameraID  string `json:"camera_id"`
}

func (s *Service) HandlePushAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	if s.FCM == nil || s.FCM.TokenSource == nil {
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "push service not configured"})
		return
	}

	var req pushAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Platform = strings.ToLower(strings.TrimSpace(req.Platform))
	req.CameraID = strings.TrimSpace(req.CameraID)

	if req.Email == "" || req.Platform == "" || req.CameraID == "" || req.Timestamp == 0 {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email, platform, camera_id and timestamp are required"})
		return
	}

	if req.Platform != "android" && req.Platform != "ios" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "platform must be 'android' or 'ios'"})
		return
	}

	var (
		fcmToken sql.NullString
		langVal  sql.NullString
	)
	err := s.DB.QueryRow(
		"SELECT fcm_token, language FROM users WHERE email = ? AND status = 'active'",
		req.Email,
	).Scan(&fcmToken, &langVal)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, jsonResponse{Success: false, Message: "user not found or inactive"})
		return
	} else if err != nil {
		logger.Errorf("query user fcm_token error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if !fcmToken.Valid || strings.TrimSpace(fcmToken.String) == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "push token not registered"})
		return
	}

	data := map[string]string{
		"camera_id": req.CameraID,
		"timestamp": strconv.FormatInt(req.Timestamp, 10),
		"platform":  req.Platform,
		"email":     req.Email,
	}

	userLang := "zh-CN"
	if langVal.Valid {
		if normalized, ok := normalizeLanguage(langVal.String); ok && normalized != "" {
			userLang = normalized
		}
	}

	title := "检测到有人"
	body := "你的摄像头检测到人形"
	if userLang == "en-US" {
		title = "Person detected"
		body = "Your camera has detected a person"
	}

	if err := s.FCM.SendAlert(fcmToken.String, title, body, data); err != nil {
		logger.Errorf("send fcm alert error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "push send error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Message: "push alert sent",
	})
}

type deleteAccountRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HandleDeleteAccount soft-deletes a user account.
func (s *Service) HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req deleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email and password required"})
		return
	}

	// Verify user credentials
	var passwordHash string
	err := s.DB.QueryRow("SELECT password_hash FROM users WHERE email = ? AND status = 'active'", req.Email).Scan(&passwordHash)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or password"})
		return
	} else if err != nil {
		logger.Errorf("delete account query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or password"})
		return
	}

	// Soft delete user
	_, err = s.DB.Exec("UPDATE users SET status = 'deleted' WHERE email = ?", req.Email)
	if err != nil {
		logger.Errorf("delete account update error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Message: "account deleted"})
}

type resetPasswordRequest struct {
	Email       string `json:"email"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// HandleResetPassword verifies old password and updates to new password.
func (s *Service) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}

	if req.Email == "" || req.OldPassword == "" || req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "email, old_password and new_password are required"})
		return
	}

	// Verify old password
	var passwordHash string
	err := s.DB.QueryRow("SELECT password_hash FROM users WHERE email = ? AND status = 'active'", req.Email).Scan(&passwordHash)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or old password"})
		return
	} else if err != nil {
		logger.Errorf("reset password query error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.OldPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, jsonResponse{Success: false, Message: "invalid email or old password"})
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("hash new password error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	// Update password
	_, err = s.DB.Exec("UPDATE users SET password_hash = ? WHERE email = ?", string(hash), req.Email)
	if err != nil {
		logger.Errorf("update password error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{Success: true, Message: "password updated"})
}

// HandleGetBindingsByMonitor 通过监控端邮箱查询绑定关系
func (s *Service) HandleGetBindingsByMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}

	// 从查询参数获取监控端邮箱
	monitorEmail := r.URL.Query().Get("monitor_email")
	if monitorEmail == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "monitor_email parameter is required"})
		return
	}

	// 查询绑定关系
	rows, err := s.DB.Query(
		"SELECT id, monitor_email, camera_email, camera_device_id, camera_name, camera_location, camera_online, status, created_at, updated_at FROM device_bindings WHERE monitor_email = ? AND status != 'revoked' ORDER BY created_at DESC",
		monitorEmail,
	)
	if err != nil {
		logger.Errorf("query bindings error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}
	defer rows.Close()

	var bindings []DeviceBinding
	for rows.Next() {
		var binding DeviceBinding
		err := rows.Scan(
			&binding.ID,
			&binding.MonitorEmail,
			&binding.CameraEmail,
			&binding.CameraDeviceID,
			&binding.CameraName,
			&binding.CameraLocation,
			&binding.CameraOnline,
			&binding.Status,
			&binding.CreatedAt,
			&binding.UpdatedAt,
		)
		if err != nil {
			logger.Errorf("scan binding error: %v", err)
			continue
		}
		bindings = append(bindings, binding)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("rows error: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "server error"})
		return
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data:    bindings,
	})
}
