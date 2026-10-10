package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
)

// wechatPendingOrderTTL 微信「待支付订单」的有效期。
//
// 下单（create-order）只是调起收银台，此时会预插入一条 status=2 的记录；
// 微信侧订单在约 2 小时后失效，用户也不可能再支付。
// 超过该时长仍停留在 status=2 的记录会被回收（置 0），
// 避免它带着「未来有效期」被权益判定逻辑误认成已支付。
const wechatPendingOrderTTL = 2 * time.Hour

// ———————————————— 请求/响应 DTO ————————————————

// WechatCreateOrderRequest 客户端请求创建微信支付订单的入参。
//
// 注意：为避免价格篡改，**客户端只传商品与套餐标识**，具体金额（分）
// 由服务端 resolveWechatAmount(productID, plan) 集中计算。
type WechatCreateOrderRequest struct {
	ProductID string `json:"product_id"` // 例：rephone_premium_monthly / rephone_pro
	Plan      string `json:"plan"`       // monthly | yearly
	Email     string `json:"email"`      // 当前登录用户 email，也从 token 中二次校验
}

// WechatCreateOrderResponse 创建订单成功响应。
//
// 客户端直接把 Params 丢给 fluwx 调起 SDK：
//
//	fluwx.payWithWeChat(fluwx.PayWithWeChat(
//	  appId: params.app_id, partnerId: params.partner_id,
//	  prepayId: params.prepay_id, packageValue: params.package,
//	  nonceStr: params.nonce_str, timeStamp: params.timestamp, sign: params.sign,
//	))
type WechatCreateOrderResponse struct {
	Success    bool               `json:"success"`
	OutTradeNo string             `json:"out_trade_no"` // 商户订单号，后续 verify/query 用
	Params     WechatAppPayParams `json:"params"`
}

// WechatVerifyOrderRequest 客户端通知服务端"SDK 回调显示支付成功"。
//
// 安全设计：服务端**不信任前端自报**，收到后必须主动向微信查单
// （QueryOrderByOutTradeNo）确认 trade_state，只有 SUCCESS 才发放权益。
type WechatVerifyOrderRequest struct {
	OutTradeNo    string `json:"out_trade_no"`
	Email         string `json:"email"`
	TransactionID string `json:"transaction_id,omitempty"` // 可选，SDK 回调里拿到了就传
}

// WechatQueryOrderRequest 客户端兜底查单（支付页面卡了很久、未收到回调）。
type WechatQueryOrderRequest struct {
	OutTradeNo string `json:"out_trade_no"`
	Email      string `json:"email"`
}

// ———————————————— HTTP Handler 实现 ————————————————

// wechatPayEnabled 判断微信支付是否真正可用。
//
// 条件：客户端已成功初始化（商户私钥/证书/密钥齐全）**且** config.ini 中 enable=true。
// 不满足时写入 503 并返回 false。
//
// 重要：微信支付链路**没有任何 mock / 模拟降级**——未配置完整就是不可用，
// 这样可彻底杜绝「配置缺失却仍能发放会员权益」的漏洞。
func (s *Service) wechatPayEnabled(w http.ResponseWriter) bool {
	if s.WechatPay == nil || !s.WechatPay.cfg.Enable {
		writeJSON(w, http.StatusServiceUnavailable,
			jsonResponse{Success: false, Message: "wechat pay is not enabled"})
		return false
	}
	return true
}

// HandleCreateWechatOrder 处理客户端创建微信支付订单。
//
// 流程：
//  1. AuthMiddleware 已注入 user_id / email，校验入参 email 和 token 一致（防串号）
//  2. 调用 WechatPay.CreateAppOrder 真实请求微信 `/v3/pay/transactions/app` 下单
//  3. 在 subscriptions 表预插入一条 pending 订单（status=2 表示"已创建待支付"）
//  4. 返回客户端调起 SDK 所需的全部参数
//
// 路由：POST /api/payment/wechat/create-order
func (s *Service) HandleCreateWechatOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}
	if !s.wechatPayEnabled(w) {
		return
	}
	var req WechatCreateOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}
	req.ProductID = strings.TrimSpace(req.ProductID)
	req.Plan = strings.TrimSpace(req.Plan)
	req.Email = strings.TrimSpace(req.Email)
	if req.ProductID == "" || req.Plan == "" || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "product_id, plan and email are required"})
		return
	}
	if req.Plan != "monthly" && req.Plan != "yearly" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "plan must be monthly or yearly"})
		return
	}

	// 校验 token 中的 email 与入参一致（避免 A 登录后给 B 下单）
	ctxEmail, _ := EmailFromContext(r.Context())
	if ctxEmail != "" && !strings.EqualFold(ctxEmail, req.Email) {
		writeJSON(w, http.StatusForbidden, jsonResponse{Success: false, Message: "email mismatch with token"})
		return
	}

	userIP := clientIP(r)

	// 只调用一次微信下单接口：CreateAppOrder 同时返回 outTradeNo 与客户端调起参数，
	// 两者必须严格对应，否则后续 notify / verify / query 无法定位订单。
	params, outTradeNo, err := s.WechatPay.CreateAppOrder(req.ProductID, req.Plan, req.Email, userIP)
	if err != nil {
		logger.Errorf("[WechatPay] 创建订单失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "create order failed"})
		return
	}

	// 预插入 pending 订单（status=2：已创建、待支付）
	// 同一 order_id（outTradeNo）重复创建时走 ON DUPLICATE KEY UPDATE 刷新，不报错。
	//
	// 关键：**待支付订单不写 expire_time（保持 NULL）**。
	// 会员时长只在 applyWechatPaymentSuccess 里按真实支付结果计算；
	// 这里若预先写入 now+duration，任何「按 expire_time 判断是否有效」的查询
	// 都会把「刚调起收银台、尚未付款」的订单判成有效，直接导致白送会员。
	now := time.Now()
	_, dbErr := s.DB.Exec(`
		INSERT INTO subscriptions (email, order_id, product_id, base_plan_id, purchase_token, platform, purchase_time, expire_time, status)
		VALUES (?, ?, ?, ?, ?, 'wechat', ?, NULL, 2)
		ON DUPLICATE KEY UPDATE
			email = VALUES(email),
			product_id = VALUES(product_id),
			base_plan_id = VALUES(base_plan_id),
			purchase_token = VALUES(purchase_token),
			platform = 'wechat',
			updated_at = NOW(),
			status = 2
	`, req.Email, outTradeNo, req.ProductID, req.Plan, params.PrepayID, now)
	if dbErr != nil {
		logger.Errorf("[WechatPay] 预写入订单失败: %v", dbErr)
		// 非致命：仍把下单结果返回客户端，后续 notify/verify 兜底落库
	}

	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: WechatCreateOrderResponse{
			Success:    true,
			OutTradeNo: outTradeNo,
			Params:     *params,
		},
	})
}

// HandleWechatNotify 处理微信支付结果异步回调。
//
// 注意：该接口**不挂 AuthMiddleware**，因为调用方是微信官方服务器。
// 安全机制（必须全部通过才会发放权益）：
//  1. 回调签名验证：用微信平台证书公钥校验 Wechatpay-Signature（防伪造/重放）
//  2. 报文解密：用 APIv3 密钥 AES-256-GCM 解密 resource（防中间人）
//  3. 商户身份校验：解密后的 appid / mchid 必须与本地配置一致（防跨商户串单）
//  4. 幂等：同一 transaction_id 多次回调不重复加时长
//
// 全程真实链路：签名验证与解密任一失败即返回 FAIL，不存在 mock 兜底。
//
// 路由：POST /api/payment/wechat/notify
//
// 响应：微信官方要求成功时返回 {"code":"SUCCESS"}，失败返回 {"code":"FAIL","message":"..."}（固定结构）
func (s *Service) HandleWechatNotify(w http.ResponseWriter, r *http.Request) {
	if s.WechatPay == nil || !s.WechatPay.cfg.Enable {
		logger.Errorf("[WechatPay] 收到 notify 但微信支付未启用，忽略该回调")
		writeWechatNotifyResult(w, false, "wechat pay is not enabled")
		return
	}

	// 1. 读取 body（注意：读完后 r.Body 空了，如需后续处理需要 rewind，但此处不需要）
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("[WechatPay] 读取 notify body 失败: %v", err)
		writeWechatNotifyResult(w, false, "read body")
		return
	}
	log.Printf("[WechatPay] 收到 notify，raw=%s", string(bodyBytes))

	// 2. 回调签名验证：notify 接口无 JWT，这是唯一的身份认证手段，强制开启。
	if err := s.WechatPay.VerifyNotifySignature(r.Header, bodyBytes); err != nil {
		logger.Errorf("[WechatPay] notify 签名验证失败（疑似伪造回调）: %v", err)
		writeWechatNotifyResult(w, false, "signature verify failed")
		return
	}

	// 3. 反序列化并解密 resource
	var payload WechatNotifyPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		logger.Errorf("[WechatPay] notify payload 解析失败: %v", err)
		writeWechatNotifyResult(w, false, "invalid payload")
		return
	}

	decrypted, err := s.WechatPay.DecryptNotifyResource(payload.Resource)
	if err != nil {
		logger.Errorf("[WechatPay] notify resource 解密失败: %v", err)
		writeWechatNotifyResult(w, false, "decrypt failed")
		return
	}

	// 4. 商户身份校验：确认这笔订单确实属于本商户/本应用
	if decrypted.AppID != "" && decrypted.AppID != s.WechatPay.cfg.AppID {
		logger.Errorf("[WechatPay] notify appid 不匹配: got=%s want=%s", decrypted.AppID, s.WechatPay.cfg.AppID)
		writeWechatNotifyResult(w, false, "appid mismatch")
		return
	}
	if decrypted.MchID != "" && decrypted.MchID != s.WechatPay.cfg.MchID {
		logger.Errorf("[WechatPay] notify mchid 不匹配: got=%s want=%s", decrypted.MchID, s.WechatPay.cfg.MchID)
		writeWechatNotifyResult(w, false, "mchid mismatch")
		return
	}

	// 6. 根据 trade_state 判断
	if decrypted.TradeState != "SUCCESS" {
		logger.Infof("[WechatPay] notify trade_state=%s (非成功)，order=%s", decrypted.TradeState, decrypted.OutTradeNo)
		// 非成功状态：把 subscriptions.status 更新成 0（失败/关闭），不抛错。
		if decrypted.OutTradeNo != "" {
			_, _ = s.DB.Exec("UPDATE subscriptions SET status = 0, updated_at = NOW() WHERE order_id = ?", decrypted.OutTradeNo)
		}
		writeWechatNotifyResult(w, true, "")
		return
	}

	// 7. 应用支付成功结果（更新 users + subscriptions）
	email, plan, _ := parseAttach(decrypted.Attach)
	if email == "" {
		// attach 为空时，从 subscriptions 表里用 out_trade_no 反查 email
		var dbEmail, dbPlan sql.NullString
		_ = s.DB.QueryRow(`SELECT email, IFNULL(base_plan_id,'') FROM subscriptions WHERE order_id = ? LIMIT 1`,
			decrypted.OutTradeNo).Scan(&dbEmail, &dbPlan)
		if dbEmail.Valid {
			email = dbEmail.String
		}
		if dbPlan.Valid && plan == "" {
			plan = dbPlan.String
		}
	}
	if email == "" {
		logger.Errorf("[WechatPay] notify 无法识别用户: order=%s attach=%s", decrypted.OutTradeNo, decrypted.Attach)
		// 返回 FAIL 让微信重试，避免因 transient 问题永久丢失这笔权益
		writeWechatNotifyResult(w, false, "unknown user")
		return
	}
	if err := s.applyWechatPaymentSuccess(decrypted.OutTradeNo, decrypted.TransactionID, email, plan); err != nil {
		logger.Errorf("[WechatPay] 应用支付成功结果失败: %v", err)
		writeWechatNotifyResult(w, false, "apply failed")
		return
	}

	writeWechatNotifyResult(w, true, "")
}

// writeWechatNotifyResult 按微信官方要求返回固定结构的回调响应。
//
// 注意：微信要求无论业务成功与否，HTTP 状态码都应为 200，
// 通过 body 中的 code 字段（SUCCESS / FAIL）表达处理结果。
func writeWechatNotifyResult(w http.ResponseWriter, ok bool, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if ok {
		_, _ = w.Write([]byte(`{"code":"SUCCESS"}`))
		return
	}
	body, _ := json.Marshal(map[string]string{"code": "FAIL", "message": message})
	_, _ = w.Write(body)
}

// HandleQueryWechatOrder 处理客户端兜底查单请求。
//
// 路由：POST /api/payment/wechat/query
func (s *Service) HandleQueryWechatOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}
	if !s.wechatPayEnabled(w) {
		return
	}
	var req WechatQueryOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}
	req.OutTradeNo = strings.TrimSpace(req.OutTradeNo)
	req.Email = strings.TrimSpace(req.Email)
	if req.OutTradeNo == "" || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "out_trade_no and email are required"})
		return
	}
	ctxEmail, _ := EmailFromContext(r.Context())
	if ctxEmail != "" && !strings.EqualFold(ctxEmail, req.Email) {
		writeJSON(w, http.StatusForbidden, jsonResponse{Success: false, Message: "email mismatch with token"})
		return
	}

	// 先查本地 subscriptions 表：如果已经 status=1 成功了，直接返回
	var status int
	var txID, plan sql.NullString
	err := s.DB.QueryRow(`SELECT status, IFNULL(purchase_token,''), IFNULL(base_plan_id,'') FROM subscriptions WHERE order_id = ? AND email = ?`,
		req.OutTradeNo, req.Email).Scan(&status, &txID, &plan)
	// 必须同时确认 purchase_token 是微信 transaction_id：
	// 待支付记录的 token 是 prepay_id（wx 开头），不能据此判定已支付。
	if err == nil && status == 1 && isWechatTransactionID(txID.String) {
		writeJSON(w, http.StatusOK, jsonResponse{
			Success: true,
			Data: map[string]interface{}{
				"paid":           true,
				"transaction_id": txID.String,
				"plan":           plan.String,
			},
		})
		return
	}

	wxResp, err := s.WechatPay.QueryOrderByOutTradeNo(req.OutTradeNo)
	if err != nil {
		logger.Errorf("[WechatPay] 查单失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "query order failed"})
		return
	}
	paid := wxResp.TradeState == "SUCCESS"
	if paid {
		email, pl, _ := parseAttach(wxResp.Attach)
		if email == "" {
			email = req.Email
		}
		if pl == "" && plan.Valid {
			pl = plan.String
		}
		if applyErr := s.applyWechatPaymentSuccess(req.OutTradeNo, wxResp.TransactionID, email, pl); applyErr != nil {
			logger.Errorf("[WechatPay] 查单发现已支付但落库失败: %v", applyErr)
		}
	}
	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: map[string]interface{}{
			"paid":           paid,
			"trade_state":    wxResp.TradeState,
			"transaction_id": wxResp.TransactionID,
			"success_time":   wxResp.SuccessTime,
		},
	})
}

// HandleVerifyWechatOrder 处理客户端自报"SDK 显示支付成功"的通知。
//
// 与 Query 的区别：该接口语义上是「用户点了确认，麻烦后端确认并发权益」，
// 因此命中 SUCCESS 时和 notify 一样调用 apply；否则返回 paid=false，
// 由客户端轮询 query 或等待异步回调。
//
// 路由：POST /api/payment/wechat/verify
func (s *Service) HandleVerifyWechatOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}
	if !s.wechatPayEnabled(w) {
		return
	}
	var req WechatVerifyOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "invalid json"})
		return
	}
	req.OutTradeNo = strings.TrimSpace(req.OutTradeNo)
	req.Email = strings.TrimSpace(req.Email)
	if req.OutTradeNo == "" || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, jsonResponse{Success: false, Message: "out_trade_no and email are required"})
		return
	}
	ctxEmail, _ := EmailFromContext(r.Context())
	if ctxEmail != "" && !strings.EqualFold(ctxEmail, req.Email) {
		writeJSON(w, http.StatusForbidden, jsonResponse{Success: false, Message: "email mismatch with token"})
		return
	}

	// 先查本地 subscriptions，避免重复处理
	var status int
	var productID, plan sql.NullString
	err := s.DB.QueryRow(`SELECT status, product_id, IFNULL(base_plan_id,'') FROM subscriptions WHERE order_id = ? AND email = ? LIMIT 1`,
		req.OutTradeNo, req.Email).Scan(&status, &productID, &plan)
	if err == nil && status == 1 {
		// 本地已是「生效中」，说明真实回调/查单已发放过权益，直接返回，不重复发放。
		writeJSON(w, http.StatusOK, jsonResponse{
			Success: true,
			Data:    map[string]interface{}{"paid": true, "verified": true, "plan": plan.String},
		})
		return
	}

	// 生产模式：不信任前端，主动查单确认
	wxResp, err := s.WechatPay.QueryOrderByOutTradeNo(req.OutTradeNo)
	if err != nil {
		logger.Errorf("[WechatPay] verify 时查单失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "verify query failed"})
		return
	}
	paid := wxResp.TradeState == "SUCCESS"
	if paid {
		pl := plan.String
		if pl == "" {
			_, plFromAttach, _ := parseAttach(wxResp.Attach)
			pl = plFromAttach
		}
		if applyErr := s.applyWechatPaymentSuccess(req.OutTradeNo, wxResp.TransactionID, req.Email, pl); applyErr != nil {
			logger.Errorf("[WechatPay] verify 落库失败: %v", applyErr)
			writeJSON(w, http.StatusInternalServerError, jsonResponse{Success: false, Message: "apply payment failed"})
			return
		}
	}
	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: map[string]interface{}{
			"paid":        paid,
			"verified":    paid,
			"trade_state": wxResp.TradeState,
		},
	})
}

// HandleListPaymentProducts 下发服务端统一定价，供会员页渲染价格。
//
// 目的：消除「客户端硬编码一份价格、服务端硬编码另一份」的双份事实来源问题。
// 改价只需改 configs/config.ini 并重启服务，客户端无需发版。
//
// 路由：GET /api/payment/products（无需登录，价格本身不是敏感信息）
func (s *Service) HandleListPaymentProducts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, jsonResponse{Success: false, Message: "method not allowed"})
		return
	}
	if !s.wechatPayEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, jsonResponse{
		Success: true,
		Data: map[string]interface{}{
			"channel":  "wechat",
			"currency": "CNY",
			"products": s.WechatPay.ListProducts(),
		},
	})
}

// ———————————————— 内部：应用支付成功结果 ————————————————

// applyWechatPaymentSuccess 把微信支付成功的结果落到 DB。
//
// 行为：
//  1. 根据 subscriptions 表判断该订单是否已处理过（幂等）
//  2. 未处理 → 计算 expireAt（已有未过期 VIP 则累加，否则从 now 开始）
//  3. 更新 users.vip_level / expire_at / last_verify_at / subscription_state
//  4. 更新 subscriptions：purchase_token=transaction_id、status=1、expire_time
//
// 注意：此函数被 notify / verify / query 三条路径调用，内部幂等。
func (s *Service) applyWechatPaymentSuccess(outTradeNo, transactionID, email, plan string) error {
	if outTradeNo == "" || email == "" {
		return fmt.Errorf("applyWechatPaymentSuccess: out_trade_no and email required")
	}

	// 1. 查本订单当前状态，确保幂等
	var (
		curStatus  int
		curTxID    sql.NullString
		curProduct string
		curPlan    sql.NullString
		curExpire  sql.NullTime
	)
	// 订单不存在（notify 先于 create-order 落库到达）时 err 非 nil，属正常情况，忽略。
	_ = s.DB.QueryRow(`
		SELECT status, IFNULL(purchase_token,''), product_id, IFNULL(base_plan_id,''), expire_time
		FROM subscriptions WHERE order_id = ? AND email = ? LIMIT 1
	`, outTradeNo, email).Scan(&curStatus, &curTxID, &curProduct, &curPlan, &curExpire)

	// 若订单不存在（例如 notify 先到，还没来得及预插入），
	// 需要用一个默认的 product_id 兜底。
	productID := curProduct
	if productID == "" {
		productID = "rephone_pro"
	}
	planValue := plan
	if planValue == "" {
		planValue = curPlan.String
	}
	if planValue == "" {
		planValue = "monthly"
	}

	duration := resolveWechatDuration(planValue)

	// 2. 微信支付必须带 transaction_id（微信支付订单号）。
	//    必须在任何写库操作之前校验：否则一旦为空，会出现
	//    「users 已加时长但 subscriptions 未落库」的不一致状态。
	if transactionID == "" {
		return fmt.Errorf("applyWechatPaymentSuccess: transaction_id is required")
	}

	// 3. 幂等：该订单已按「真实微信 transaction_id」发放过权益则跳过。
	//
	//    注意不能只判断 status == 1：下单阶段预插入的待支付记录 token 是
	//    prepay_id（wx 开头），若仅凭 status 跳过，真正支付成功后会漏发权益。
	if curStatus == 1 && isWechatTransactionID(curTxID.String) {
		logger.Infof("[WechatPay] 订单已处理（幂等跳过）: order=%s tx=%s", outTradeNo, curTxID.String)
		return nil
	}

	// 3. 计算用户新的 expireAt
	var (
		currentVipLevel uint8
		currentExpire   sql.NullTime
	)
	_ = s.DB.QueryRow(`SELECT vip_level, expire_at FROM users WHERE email = ? LIMIT 1`, email).
		Scan(&currentVipLevel, &currentExpire)

	now := time.Now()
	var baseAt time.Time
	if currentVipLevel > 0 && currentExpire.Valid && currentExpire.Time.After(now) {
		baseAt = currentExpire.Time // 累加
	} else {
		baseAt = now // 从现在开始
	}
	newExpireAt := baseAt.Add(duration)

	// 4. 更新 users
	vipLevel := 1
	if _, err := s.DB.Exec(`
		UPDATE users
		SET vip_level = ?, expire_at = ?, last_verify_at = NOW(), subscription_state = 1
		WHERE email = ?
	`, vipLevel, newExpireAt, email); err != nil {
		return fmt.Errorf("update users: %w", err)
	}

	// 5. upsert subscriptions：订单号唯一键冲突时更新
	purchaseToken := transactionID
	if _, err := s.DB.Exec(`
		INSERT INTO subscriptions (email, order_id, product_id, base_plan_id, purchase_token, platform, purchase_time, expire_time, status)
		VALUES (?, ?, ?, ?, ?, 'wechat', NOW(), ?, 1)
		ON DUPLICATE KEY UPDATE
			email          = VALUES(email),
			product_id     = VALUES(product_id),
			base_plan_id   = VALUES(base_plan_id),
			purchase_token = VALUES(purchase_token),
			platform       = 'wechat',
			expire_time    = VALUES(expire_time),
			updated_at     = NOW(),
			status         = 1
	`, email, outTradeNo, productID, planValue, purchaseToken, newExpireAt); err != nil {
		return fmt.Errorf("upsert subscriptions: %w", err)
	}

	logger.Infof("[WechatPay] 支付成功落库完成: order=%s tx=%s email=%s plan=%s expire=%s",
		outTradeNo, transactionID, email, planValue, newExpireAt.Format(time.RFC3339))
	return nil
}
