package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// PaymentRequest 接收客户端传来的支付验证参数
type PaymentRequest struct {
	OrderID       string `json:"order_id"`
	ProductID     string `json:"product_id"`
	PurchaseToken string `json:"purchase_token"`
	Email         string `json:"email"`
	Platform      string `json:"platform"` // "android" or "ios"
	PackageName   string `json:"package_name"`
}

// PaymentResponse 返回给客户端的验证结果
type PaymentResponse struct {
	Success   bool   `json:"success"`
	Status    string `json:"status"`
	VipLevel  int    `json:"vip_level"`
	ExpireAt  string `json:"expire_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// HandleVerifyGooglePurchase 验证 Google Play 订单
func (s *Service) HandleVerifyGooglePurchase(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.ProductID == "" || req.PurchaseToken == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	packageName := req.PackageName
	if packageName == "" {
		packageName = s.PackageName
	}
	if packageName == "" {
		// 默认 fallback
		packageName = "com.rephone.security"
	}

	log.Printf("Verifying purchase for %s: %s (pkg: %s)", req.Email, req.ProductID, packageName)

	var expireAt time.Time
	var isValid bool

	if s.PaymentClient != nil {
		// Call Google Play Developer API
		isSubscription := req.ProductID == "rephone_premium_monthly" || 
			req.ProductID == "rephone_premium_yearly" || 
			req.ProductID == "rephone_pro"
		
		var apiURL string
		if isSubscription {
			apiURL = fmt.Sprintf("https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/subscriptions/%s/tokens/%s", packageName, req.ProductID, req.PurchaseToken)
		} else {
			apiURL = fmt.Sprintf("https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/products/%s/tokens/%s", packageName, req.ProductID, req.PurchaseToken)
		}

		resp, err := s.PaymentClient.Get(apiURL)
		if err != nil {
			log.Printf("Google Play API error: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Google Play API returned status: %d", resp.StatusCode)
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("Google Play API error body: %s", string(bodyBytes))
			http.Error(w, "Verification failed at provider", http.StatusPaymentRequired)
			return
		}

		var googleResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&googleResp); err != nil {
			log.Printf("Failed to decode Google response: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}

		if isSubscription {
			if expMillisStr, ok := googleResp["expiryTimeMillis"].(string); ok {
				expMillis, _ := strconv.ParseInt(expMillisStr, 10, 64)
				expireAt = time.Unix(expMillis/1000, 0)
				isValid = true
			}
		} else {
			// For products, check purchaseState == 0 (Purchased)
			if state, ok := googleResp["purchaseState"].(float64); ok && state == 0 {
				isValid = true
				expireAt = time.Now().Add(30 * 24 * time.Hour)
			}
		}
	} else {
		// Dev mode: no client configured, simulate success
		log.Println("No PaymentClient configured, simulating success")
		isValid = true
		
		var duration time.Duration
		if req.ProductID == "rephone_premium_monthly" {
			duration = 30 * 24 * time.Hour
		} else if req.ProductID == "rephone_premium_yearly" {
			duration = 365 * 24 * time.Hour
		} else if req.ProductID == "rephone_pro" {
			// Dev mode fallback for new model: try to guess based on token or just default to month
			// In real dev environment, we might want to pass 'basePlanId' in request for simulation
			duration = 30 * 24 * time.Hour
		} else {
			duration = 30 * 24 * time.Hour
		}
		
		var currentExpireAt sql.NullTime
		err := s.DB.QueryRow("SELECT expire_at FROM users WHERE email = ?", req.Email).Scan(&currentExpireAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.Printf("Error querying user: %v", err)
		}
		
		if currentExpireAt.Valid && currentExpireAt.Time.After(time.Now()) {
			expireAt = currentExpireAt.Time.Add(duration)
		} else {
			expireAt = time.Now().Add(duration)
		}
	}

	if !isValid {
		http.Error(w, "Purchase invalid", http.StatusPaymentRequired)
		return
	}

	// Update user
	vipLevel := 1
	// Update last_verify_at to now, and set subscription_state to 1 (Active)
	_, err := s.DB.Exec("UPDATE users SET vip_level = ?, expire_at = ?, last_verify_at = ?, subscription_state = 1 WHERE email = ?", vipLevel, expireAt, time.Now(), req.Email)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Save subscription record
	_, err = s.DB.Exec(`
		INSERT INTO subscriptions (email, order_id, product_id, purchase_token, platform, purchase_time, expire_time, status)
		VALUES (?, ?, ?, ?, ?, NOW(), ?, 1)
		ON DUPLICATE KEY UPDATE 
			expire_time = VALUES(expire_time),
			updated_at = NOW(),
			status = 1
	`, req.Email, req.OrderID, req.ProductID, req.PurchaseToken, req.Platform, expireAt)

	if err != nil {
		// Log error but don't fail the request, as user status is already updated
		log.Printf("Error saving subscription record: %v", err)
	}

	resp := PaymentResponse{
		Success:  true,
		Status:   "success",
		VipLevel: vipLevel,
		ExpireAt: expireAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RefreshSubscriptionRequest 接收客户端传来的刷新请求
type RefreshSubscriptionRequest struct {
	Email string `json:"email"`
}

// HandleRefreshSubscription 主动刷新订阅状态
// 客户端不知道具体的 token，服务端从 subscriptions 表里查最近的一条
func (s *Service) HandleRefreshSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	log.Printf("Refreshing subscription for %s", req.Email)

	// 1. 查最近一次有效的订阅记录 (PurchaseToken)
	var purchaseToken, productId, orderId string
	var platform string
	err := s.DB.QueryRow(`
		SELECT purchase_token, product_id, order_id, platform 
		FROM subscriptions 
		WHERE email = ? 
		ORDER BY created_at DESC 
		LIMIT 1
	`, req.Email).Scan(&purchaseToken, &productId, &orderId, &platform)

	if err == sql.ErrNoRows {
		// 没有订阅记录 -> 不是 VIP
		log.Printf("No subscription found for %s", req.Email)
		s.resetVipStatus(w, req.Email)
		return
	} else if err != nil {
		log.Printf("Error querying subscription: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// 2. 构造 PaymentRequest 复用 HandleVerifyGooglePurchase 的逻辑
	// 注意：这里我们直接构造 request body 然后调用 HandleVerifyGooglePurchase
	// 或者，更优雅的方式是把 core logic 抽出来。
	// 为了省事且保证逻辑一致，我们手动构造一个 PaymentRequest 结构体，
	// 但 HandleVerifyGooglePurchase 接收的是 http.Request。
	// 
	// 最好是把 verify 的核心逻辑抽取为 verifySubscription(email, productId, token)
	// 但考虑到时间，我们可以直接在内部调用 verify 逻辑。

	// 复用 verify 逻辑 (Copy-paste adapt or Refactor)
	// Refactoring is better.
	
	// Let's call the internal verify logic directly.
	// We need to verify against Google.
	
	// Check cache first (Logic from HandleVerifyGooglePurchase)
	var currentVipLevel int
	var currentExpireAt sql.NullTime
	var lastVerifyAt sql.NullTime
	err = s.DB.QueryRow("SELECT vip_level, expire_at, last_verify_at FROM users WHERE email = ?", req.Email).Scan(&currentVipLevel, &currentExpireAt, &lastVerifyAt)
	
	now := time.Now()
	// Cache hit?
	if currentVipLevel > 0 && currentExpireAt.Valid && currentExpireAt.Time.After(now) {
		if lastVerifyAt.Valid && now.Sub(lastVerifyAt.Time) < 6*time.Hour {
			// Cache valid
			resp := PaymentResponse{
				Success:  true,
				Status:   "success",
				VipLevel: currentVipLevel,
				ExpireAt: currentExpireAt.Time.Format(time.RFC3339),
				Message:  "Cached status (Refresh)",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// Cache miss, need to verify with Google
	// We have the token from DB.
	
	packageName := s.PackageName
	if packageName == "" {
		packageName = "com.rephone.security"
	}

	var expireAt time.Time
	var isValid bool

	if s.PaymentClient != nil {
		// Call Google Play Developer API
		isSubscription := productId == "rephone_premium_monthly" || 
			productId == "rephone_premium_yearly" || 
			productId == "rephone_pro"
		
		var apiURL string
		if isSubscription {
			apiURL = fmt.Sprintf("https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/subscriptions/%s/tokens/%s", packageName, productId, purchaseToken)
		} else {
			apiURL = fmt.Sprintf("https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/products/%s/tokens/%s", packageName, productId, purchaseToken)
		}

		resp, err := s.PaymentClient.Get(apiURL)
		if err != nil {
			log.Printf("Google Play API error: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Google Play API returned status: %d", resp.StatusCode)
			// Token 可能失效了，或者过期太久了
			// 这种情况下，我们应该认为用户不再是 VIP
			// Update subscription status to 0 (Expired/Invalid)
			s.DB.Exec("UPDATE subscriptions SET status = 0, updated_at = NOW() WHERE purchase_token = ?", purchaseToken)
			s.resetVipStatus(w, req.Email)
			return
		}

		var googleResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&googleResp); err != nil {
			log.Printf("Failed to decode Google response: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}

		if isSubscription {
			if expMillisStr, ok := googleResp["expiryTimeMillis"].(string); ok {
				expMillis, _ := strconv.ParseInt(expMillisStr, 10, 64)
				expireAt = time.Unix(expMillis/1000, 0)
				// 只有过期时间在未来才算有效
				if expireAt.After(time.Now()) {
					isValid = true
				}
			}
		} else {
			// For products, check purchaseState == 0 (Purchased)
			if state, ok := googleResp["purchaseState"].(float64); ok && state == 0 {
				isValid = true
				expireAt = time.Now().Add(30 * 24 * time.Hour) // 消耗品/非订阅假设
			}
		}
	} else {
		// Dev mode
		log.Println("Dev mode refresh: simulating success based on existing DB token")
		// In dev mode, if we found a token, we assume it's valid for now
		isValid = true
		expireAt = time.Now().Add(30 * 24 * time.Hour)
	}

	if !isValid {
		// Expired
		// Update subscription status to 0 (Expired/Invalid)
		if !expireAt.IsZero() {
			s.DB.Exec("UPDATE subscriptions SET status = 0, expire_time = ?, updated_at = NOW() WHERE purchase_token = ?", expireAt, purchaseToken)
		} else {
			s.DB.Exec("UPDATE subscriptions SET status = 0, updated_at = NOW() WHERE purchase_token = ?", purchaseToken)
		}
		s.resetVipStatus(w, req.Email)
		return
	}

	// Update user
	vipLevel := 1
	// Update last_verify_at to now, and set subscription_state to 1 (Active)
	_, err = s.DB.Exec("UPDATE users SET vip_level = ?, expire_at = ?, last_verify_at = ?, subscription_state = 1 WHERE email = ?", vipLevel, expireAt, time.Now(), req.Email)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Update subscription record
	_, err = s.DB.Exec(`
		UPDATE subscriptions 
		SET expire_time = ?, updated_at = NOW(), status = 1
		WHERE purchase_token = ?
	`, expireAt, purchaseToken)
	
	if err != nil {
		log.Printf("Error updating subscription record: %v", err)
	}

	resp := PaymentResponse{
		Success:  true,
		Status:   "success",
		VipLevel: vipLevel,
		ExpireAt: expireAt.Format(time.RFC3339),
		Message:  "Refreshed status",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Service) resetVipStatus(w http.ResponseWriter, email string) {
	_, err := s.DB.Exec("UPDATE users SET vip_level = 0, subscription_state = 0 WHERE email = ?", email)
	if err != nil {
		log.Printf("Error resetting user vip: %v", err)
	}
	resp := PaymentResponse{
		Success:  true,
		Status:   "expired",
		VipLevel: 0,
		Message:  "Subscription expired or not found",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
