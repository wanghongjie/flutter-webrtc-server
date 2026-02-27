package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		isSubscription := req.ProductID == "rephone_premium_monthly" || req.ProductID == "rephone_premium_yearly"
		
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
	_, err := s.DB.Exec("UPDATE users SET vip_level = ?, expire_at = ? WHERE email = ?", vipLevel, expireAt, req.Email)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
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
