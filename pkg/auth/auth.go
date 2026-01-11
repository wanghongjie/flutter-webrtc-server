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
	Mailer Mailer
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

// DeviceBinding 设备绑定结构
type DeviceBinding struct {
	ID             uint64    `json:"id"`
	MonitorEmail   string    `json:"monitor_email"`
	CameraEmail    string    `json:"camera_email"`
	CameraDeviceID string    `json:"camera_device_id"`
	CameraName     string    `json:"camera_name"`
	CameraLocation string    `json:"camera_location"`
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
		"SELECT id, monitor_email, camera_email, camera_device_id, camera_name, camera_location, status, created_at, updated_at FROM device_bindings WHERE monitor_email = ? AND status != 'revoked' ORDER BY created_at DESC",
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
