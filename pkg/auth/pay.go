package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PaymentRequest 接收客户端传来的支付验证参数
type PaymentRequest struct {
	OrderID       string `json:"order_id"`
	ProductID     string `json:"product_id"`
	BasePlanID    string `json:"base_plan_id"` // Android Base Plans (monthly/yearly) under rephone_pro
	PurchaseToken string `json:"purchase_token"`
	ReceiptData   string `json:"receipt_data"` // iOS receipt data
	TransactionID string `json:"transaction_id"`
	Email         string `json:"email"`
	Platform      string `json:"platform"` // "android" or "ios"
	PackageName   string `json:"package_name"`
}

// AppleVerifyRequest 发送给 Apple 的验证请求
type AppleVerifyRequest struct {
	ReceiptData string `json:"receipt-data"`
	Password    string `json:"password,omitempty"` // Shared Secret
}

// AppleVerifyResponse Apple 验证响应
type AppleVerifyResponse struct {
	Status             int                 `json:"status"`
	Environment        string              `json:"environment"`
	Receipt            AppleReceipt        `json:"receipt"`
	LatestReceiptInfo  []AppleReceiptInfo  `json:"latest_receipt_info"`
	PendingRenewalInfo []AppleRenewalInfo  `json:"pending_renewal_info"`
}

type AppleReceipt struct {
	BundleID                   string             `json:"bundle_id"`
	ApplicationVersion         string             `json:"application_version"`
	InApp                      []AppleReceiptInfo `json:"in_app"`
	OriginalApplicationVersion string             `json:"original_application_version"`
	CreationDateMs             string             `json:"creation_date_ms"`
}

type AppleReceiptInfo struct {
	OriginalTransactionID string `json:"original_transaction_id"`
	TransactionID         string `json:"transaction_id"`
	ProductID             string `json:"product_id"`
	ExpiresDateMs         string `json:"expires_date_ms"`
	PurchaseDateMs        string `json:"purchase_date_ms"`
}

type AppleRenewalInfo struct {
	ProductID              string `json:"product_id"`
	AutoRenewStatus        string `json:"auto_renew_status"`
	OriginalTransactionID  string `json:"original_transaction_id"`
	ExpirationIntent       string `json:"expiration_intent"` // "1" = voluntarily canceled, etc.
}

// PaymentResponse 返回给客户端的验证结果
type PaymentResponse struct {
	Success          bool   `json:"success"`
	Status           string `json:"status"`
	VipLevel         int    `json:"vip_level"`
	ExpireAt         string `json:"expire_at,omitempty"`
	Message          string `json:"message,omitempty"`
	ActiveProductID  string `json:"active_product_id,omitempty"`
	ActivePlan       string `json:"active_plan,omitempty"` // monthly|yearly|unknown
	Platform         string `json:"platform,omitempty"`    // ios|android
	SubscriptionState int   `json:"subscription_state,omitempty"`
}

func activePlanFromProduct(productID string) string {
	switch productID {
	case "rephone_premium_monthly":
		return "monthly"
	case "rephone_premium_yearly":
		return "yearly"
	default:
		return "unknown"
	}
}

func activePlanFromGoogle(productID, basePlanID string) string {
	if productID == "rephone_pro" {
		if basePlanID == "monthly" || basePlanID == "yearly" {
			return basePlanID
		}
		return "unknown"
	}
	return activePlanFromProduct(productID)
}

// HandleVerifyGooglePurchase 验证 Google Play 订单
func (s *Service) HandleVerifyGooglePurchase(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.ProductID == "" || req.PurchaseToken == "" || strings.TrimSpace(req.OrderID) == "" {
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

	// Save subscription record（同一 order_id 只保留一行，收据/token 更新时覆盖字段）
	_, err = s.DB.Exec(`
		INSERT INTO subscriptions (email, order_id, product_id, base_plan_id, purchase_token, platform, purchase_time, expire_time, status)
		VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, 1)
		ON DUPLICATE KEY UPDATE 
			email = VALUES(email),
			product_id = VALUES(product_id),
			base_plan_id = VALUES(base_plan_id),
			purchase_token = VALUES(purchase_token),
			platform = VALUES(platform),
			expire_time = VALUES(expire_time),
			updated_at = NOW(),
			status = 1
	`, req.Email, req.OrderID, req.ProductID, req.BasePlanID, req.PurchaseToken, req.Platform, expireAt)

	if err != nil {
		// Log error but don't fail the request, as user status is already updated
		log.Printf("Error saving subscription record: %v", err)
	}

	resp := PaymentResponse{
		Success:           true,
		Status:            "success",
		VipLevel:          vipLevel,
		ExpireAt:          expireAt.Format(time.RFC3339),
		ActiveProductID:   req.ProductID,
		ActivePlan:        activePlanFromGoogle(req.ProductID, req.BasePlanID),
		Platform:          "android",
		SubscriptionState: 1,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleVerifyApplePurchase 验证 Apple IAP 订单
func (s *Service) HandleVerifyApplePurchase(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.ProductID == "" || req.ReceiptData == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	log.Printf("Verifying Apple purchase for %s: %s", req.Email, req.ProductID)

	// Apple Verify Logic
	// Try Production URL first
	verifyURL := "https://buy.itunes.apple.com/verifyReceipt"

	// Try to get shared secret from ENV if available
	password := os.Getenv("APPLE_SHARED_SECRET")

	appleReq := AppleVerifyRequest{
		ReceiptData: req.ReceiptData,
		Password:    password,
	}

	respData, err := s.verifyAppleReceipt(verifyURL, appleReq)
	if err != nil {
		log.Printf("Apple verify error: %v", err)
		http.Error(w, "Verification service error", http.StatusInternalServerError)
		return
	}

	var appleResp AppleVerifyResponse
	if err := json.Unmarshal(respData, &appleResp); err != nil {
		log.Printf("Failed to decode Apple response: %v", err)
		http.Error(w, "Verification service error", http.StatusInternalServerError)
		return
	}

	// Check status 21007 (Sandbox receipt sent to Prod)
	if appleResp.Status == 21007 {
		log.Printf("Received status 21007, retrying with Sandbox URL")
		verifyURL = "https://sandbox.itunes.apple.com/verifyReceipt"
		respData, err = s.verifyAppleReceipt(verifyURL, appleReq)
		if err != nil {
			log.Printf("Apple sandbox verify error: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(respData, &appleResp); err != nil {
			log.Printf("Failed to decode Apple sandbox response: %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}
	}

	if appleResp.Status != 0 {
		log.Printf("Apple verification failed with status: %d", appleResp.Status)
		http.Error(w, fmt.Sprintf("Verification failed: %d", appleResp.Status), http.StatusPaymentRequired)
		return
	}

	// Validate Product ID and Expiration
	var latestReceipt AppleReceiptInfo
	var found bool

	// Check latest_receipt_info first (for auto-renewable subscriptions)
	if len(appleResp.LatestReceiptInfo) > 0 {
		// Sort by ExpiresDateMs descending to find the latest
		sort.Slice(appleResp.LatestReceiptInfo, func(i, j int) bool {
			t1, _ := strconv.ParseInt(appleResp.LatestReceiptInfo[i].ExpiresDateMs, 10, 64)
			t2, _ := strconv.ParseInt(appleResp.LatestReceiptInfo[j].ExpiresDateMs, 10, 64)
			return t1 > t2
		})

		latestReceipt = appleResp.LatestReceiptInfo[0]
		found = true
	} else if len(appleResp.Receipt.InApp) > 0 {
		// Consumable or non-renewing
		// Sort by PurchaseDateMs
		sort.Slice(appleResp.Receipt.InApp, func(i, j int) bool {
			t1, _ := strconv.ParseInt(appleResp.Receipt.InApp[i].PurchaseDateMs, 10, 64)
			t2, _ := strconv.ParseInt(appleResp.Receipt.InApp[j].PurchaseDateMs, 10, 64)
			return t1 > t2
		})
		latestReceipt = appleResp.Receipt.InApp[0]
		found = true
	}

	if !found {
		// Check if the receipt itself has info (for very old single purchases? usually in InApp)
		// Or maybe it's empty receipt?
		log.Printf("No receipt info found")
		http.Error(w, "No receipt info found", http.StatusPaymentRequired)
		return
	}

	// Check Expiration
	var expireAt time.Time
	if latestReceipt.ExpiresDateMs != "" {
		expMs, _ := strconv.ParseInt(latestReceipt.ExpiresDateMs, 10, 64)
		expireAt = time.Unix(expMs/1000, 0)
		if expireAt.Before(time.Now()) {
			log.Printf("Subscription expired at %v", expireAt)
			http.Error(w, "Subscription expired", http.StatusPaymentRequired)
			return
		}
	} else {
		// No expiration date (Consumable or Lifetime?)
		// Assume 30 days for now if it's one of our known products
		expireAt = time.Now().Add(30 * 24 * time.Hour)
	}

	// Update DB (reuse logic)
	// We use ReceiptData as purchase_token to allow server-side refresh
	// Note: This assumes purchase_token column is large enough (TEXT/BLOB)
	purchaseToken := req.ReceiptData
	
	orderId := strings.TrimSpace(latestReceipt.TransactionID)
	if orderId == "" {
		http.Error(w, "Invalid receipt: empty transaction id", http.StatusPaymentRequired)
		return
	}

	// Update user VIP status
	vipLevel := 1
	_, err = s.DB.Exec("UPDATE users SET vip_level = ?, expire_at = ?, last_verify_at = ?, subscription_state = 1 WHERE email = ?", vipLevel, expireAt, time.Now(), req.Email)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Save subscription record（同一 order_id = Apple transaction_id 只保留一行，receipt 变化时更新 purchase_token）
	_, err = s.DB.Exec(`
		INSERT INTO subscriptions (email, order_id, product_id, base_plan_id, purchase_token, platform, purchase_time, expire_time, status)
		VALUES (?, ?, ?, NULL, ?, ?, NOW(), ?, 1)
		ON DUPLICATE KEY UPDATE 
			email = VALUES(email),
			product_id = VALUES(product_id),
			purchase_token = VALUES(purchase_token),
			expire_time = VALUES(expire_time),
			updated_at = NOW(),
			status = 1
	`, req.Email, orderId, latestReceipt.ProductID, purchaseToken, "ios", expireAt)

	if err != nil {
		log.Printf("Error saving subscription record: %v", err)
	}

	resp := PaymentResponse{
		Success:           true,
		Status:            "success",
		VipLevel:          vipLevel,
		ExpireAt:          expireAt.Format(time.RFC3339),
		ActiveProductID:   latestReceipt.ProductID,
		ActivePlan:        activePlanFromProduct(latestReceipt.ProductID),
		Platform:          "ios",
		SubscriptionState: 1,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Service) verifyAppleReceipt(url string, req AppleVerifyRequest) ([]byte, error) {
	body, _ := json.Marshal(req)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
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

	// 1. 优先选择“过期时间最长”的订阅记录（解决同一账号跨平台登录时的同步问题）
	// 先取 expire_time 最大的记录；如果 expire_time 为空，则回退取最新 created_at。
	var purchaseToken, productId, basePlanId, orderId string
	var platform string
	err := s.DB.QueryRow(`
		SELECT purchase_token, product_id, IFNULL(base_plan_id,''), order_id, platform
		FROM subscriptions
		WHERE email = ?
		ORDER BY
			CASE WHEN expire_time IS NULL THEN 1 ELSE 0 END ASC,
			expire_time DESC,
			created_at DESC
		LIMIT 1
	`, req.Email).Scan(&purchaseToken, &productId, &basePlanId, &orderId, &platform)

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

	// 2. 根据平台验证订阅状态
	var expireAt time.Time
	var isValid bool

	if platform == "ios" {
		// iOS 验证逻辑
		verifyURL := "https://buy.itunes.apple.com/verifyReceipt"
		password := os.Getenv("APPLE_SHARED_SECRET")
		appleReq := AppleVerifyRequest{
			ReceiptData: purchaseToken,
			Password:    password,
		}

		respData, err := s.verifyAppleReceipt(verifyURL, appleReq)
		if err != nil {
			log.Printf("Apple verify error (refresh): %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}

		var appleResp AppleVerifyResponse
		if err := json.Unmarshal(respData, &appleResp); err != nil {
			log.Printf("Failed to decode Apple response (refresh): %v", err)
			http.Error(w, "Verification service error", http.StatusInternalServerError)
			return
		}

		if appleResp.Status == 21007 {
			verifyURL = "https://sandbox.itunes.apple.com/verifyReceipt"
			respData, err = s.verifyAppleReceipt(verifyURL, appleReq)
			if err == nil {
				json.Unmarshal(respData, &appleResp)
			}
		}

		if appleResp.Status == 0 {
			// Find latest receipt info
			var latestReceipt AppleReceiptInfo
			found := false

			if len(appleResp.LatestReceiptInfo) > 0 {
				sort.Slice(appleResp.LatestReceiptInfo, func(i, j int) bool {
					t1, _ := strconv.ParseInt(appleResp.LatestReceiptInfo[i].ExpiresDateMs, 10, 64)
					t2, _ := strconv.ParseInt(appleResp.LatestReceiptInfo[j].ExpiresDateMs, 10, 64)
					return t1 > t2
				})
				latestReceipt = appleResp.LatestReceiptInfo[0]
				found = true
			} else if len(appleResp.Receipt.InApp) > 0 {
				sort.Slice(appleResp.Receipt.InApp, func(i, j int) bool {
					t1, _ := strconv.ParseInt(appleResp.Receipt.InApp[i].PurchaseDateMs, 10, 64)
					t2, _ := strconv.ParseInt(appleResp.Receipt.InApp[j].PurchaseDateMs, 10, 64)
					return t1 > t2
				})
				latestReceipt = appleResp.Receipt.InApp[0]
				found = true
			}

			if found {
				if latestReceipt.ExpiresDateMs != "" {
					expMs, _ := strconv.ParseInt(latestReceipt.ExpiresDateMs, 10, 64)
					expireAt = time.Unix(expMs/1000, 0)
					if expireAt.After(time.Now()) {
						isValid = true
					}
				} else {
					// No expiration -> Assume valid (lifetime/consumable)
					isValid = true
					expireAt = time.Now().Add(30 * 24 * time.Hour)
				}
			}
		} else {
			log.Printf("Apple verify failed (refresh) status: %d", appleResp.Status)
		}

	} else {
		// Android/Google 验证逻辑 (原有逻辑)
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
					Success:           true,
					Status:            "success",
					VipLevel:          currentVipLevel,
					ExpireAt:          currentExpireAt.Time.Format(time.RFC3339),
					Message:           "Cached status (Refresh)",
					ActiveProductID:   productId,
					ActivePlan:        activePlanFromGoogle(productId, basePlanId),
					Platform:          platform,
					SubscriptionState: 1,
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
		Success:           true,
		Status:            "success",
		VipLevel:          vipLevel,
		ExpireAt:          expireAt.Format(time.RFC3339),
		Message:           "Refreshed status",
		ActiveProductID:   productId,
		ActivePlan:        activePlanFromGoogle(productId, basePlanId),
		Platform:          platform,
		SubscriptionState: 1,
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
