package auth

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
)

// WechatConfig 微信支付 APIv3 配置项。
//
// 说明：
//   - AppID：移动应用 AppID（微信开放平台创建应用后得到，如 wx1234567890）
//   - MchID：商户号（微信支付商户平台右上角展示，如 1600000000）
//   - MchCertSerialNo：商户 API 证书序列号（16 进制，可从商户平台/证书文件读取）
//   - APIv3Key：APIv3 密钥，32 字节字符串，用于 AES-GCM 解密回调和平台证书
//   - MchPrivateKeyPath：商户 API 私钥 apiclient_key.pem 文件路径
//   - NotifyURL：支付结果异步回调通知地址，必须是公网可访问的 HTTPS
//   - Enable：是否启用微信支付。false 时微信支付功能整体关闭（所有接口返回 503），
//     **不存在任何 mock / 模拟降级通路**，避免出现「未配置却仍能发放权益」的漏洞。
//   - PriceMonthlyFen / PriceYearlyFen：服务端统一定价（单位：分）。
//     客户端永远不传金额，改价只需改配置并重启，无需发版。
type WechatConfig struct {
	AppID             string
	MchID             string
	MchCertSerialNo   string
	APIv3Key          string
	MchPrivateKeyPath string
	NotifyURL         string
	Enable            bool
	PriceMonthlyFen   int
	PriceYearlyFen    int
}

// 默认兜底价格（单位：分），仅当配置未填写或非法时使用。
const (
	defaultPriceMonthlyFen = 299
	defaultPriceYearlyFen  = 2399
)

// WechatPayClient 微信支付客户端。
//
// 封装 APIv3 下单、查单、回调签名验证、回调 AES 解密等能力。
// 目前只实现「APP 支付」模式（Flutter 原生 App 通过微信 SDK 调起）。
type WechatPayClient struct {
	cfg     WechatConfig
	privKey *rsa.PrivateKey
	httpCli *http.Client
	baseURL string

	// 微信平台证书缓存：用于校验回调请求的 Wechatpay-Signature。
	// 平台证书由 /v3/certificates 接口下发（密文需用 APIv3Key 解密），
	// 按 serial_no 索引，过期或缺失时自动刷新。
	certMu      sync.RWMutex
	certs       map[string]*wechatPlatformCert
	certsLastAt time.Time
}

// wechatPlatformCert 一张已解密的微信平台证书。
type wechatPlatformCert struct {
	serial  string
	pubKey  *rsa.PublicKey
	expire  time.Time
	certPEM string
}

// NewWechatPayClient 根据配置初始化微信支付客户端。
//
// 步骤：
//  1. 从 pem 文件加载商户私钥（用于请求签名）
//  2. 构造带超时的 http.Client
//
// 返回错误：私钥文件缺失 / PEM 解析失败 / 不是 RSA 私钥。
func NewWechatPayClient(cfg WechatConfig) (*WechatPayClient, error) {
	if strings.TrimSpace(cfg.AppID) == "" || strings.TrimSpace(cfg.MchID) == "" {
		return nil, fmt.Errorf("wechat app_id and mch_id are required")
	}
	if strings.TrimSpace(cfg.MchCertSerialNo) == "" {
		return nil, fmt.Errorf("wechat mch_cert_serial is required")
	}
	if len(cfg.APIv3Key) != 32 {
		return nil, fmt.Errorf("wechat api_v3_key must be exactly 32 bytes, got %d", len(cfg.APIv3Key))
	}
	if strings.TrimSpace(cfg.NotifyURL) == "" {
		return nil, fmt.Errorf("wechat notify_url is required")
	}
	if strings.TrimSpace(cfg.MchPrivateKeyPath) == "" {
		return nil, fmt.Errorf("wechat mch private key path is required")
	}
	pemBytes, err := os.ReadFile(cfg.MchPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read wechat mch private key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("wechat mch private key: invalid pem format")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs1 rsa private key: %w", err)
		}
	case "PRIVATE KEY":
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
		}
		rsaKey, ok := raw.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not rsa")
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("unsupported pem block type: %s", block.Type)
	}
	logger.Infof("[WechatPay] 初始化成功：AppID=%s MchID=%s 月卡=%d分 年卡=%d分",
		cfg.AppID, cfg.MchID, resolveWechatAmount(cfg, "monthly"), resolveWechatAmount(cfg, "yearly"))

	cli := &WechatPayClient{
		cfg:     cfg,
		privKey: key,
		httpCli: &http.Client{Timeout: 10 * time.Second},
		baseURL: "https://api.mch.weixin.qq.com",
		certs:   make(map[string]*wechatPlatformCert),
	}

	// 预热平台证书：回调验签依赖它。失败不阻断启动（首回调时会重试），
	// 但会打出明确的告警，便于运维第一时间发现证书/密钥配置问题。
	if _, err := cli.getPlatformCert(""); err != nil {
		logger.Errorf("[WechatPay] 平台证书加载失败（回调验签将不可用，首次回调时会自动重试）: %v", err)
	}
	return cli, nil
}

// signWechatRequest 生成 Authorization 头中需要的签名串（APIv3 签名规范）。
//
// 签名原文格式：
//
//	HTTP_METHOD\n
//	URL_PATH\n
//	TIMESTAMP\n
//	NONCE_STR\n
//	BODY\n
//
// 签名算法：SHA256withRSA，使用商户私钥。
// 最终 Authorization 格式：WECHATPAY2-SHA256-RSA2048 mchid="...",nonce_str="...",signature="...",timestamp="...",serial_no="..."
func (c *WechatPayClient) signRequest(method, urlPath, body, nonce string, ts int64) (string, error) {
	msg := fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n", method, urlPath, ts, nonce, body)
	hash := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	return fmt.Sprintf(
		`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%d",serial_no="%s"`,
		c.cfg.MchID, nonce, sigB64, ts, c.cfg.MchCertSerialNo,
	), nil
}

// doRequest 执行一次微信支付 APIv3 请求，并把响应 JSON 解码到 out。
func (c *WechatPayClient) doRequest(ctx context.Context, method, urlPath string, body any, out any) error {
	var bodyStr string
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyStr = string(b)
	}
	nonce := randomHexString(16)
	ts := time.Now().Unix()
	auth, err := c.signRequest(method, urlPath, bodyStr, nonce, ts)
	if err != nil {
		return err
	}
	fullURL := c.baseURL + urlPath
	var reqBody io.Reader
	if bodyStr != "" {
		reqBody = strings.NewReader(bodyStr)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	if bodyStr != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read resp: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("wechat api status=%d body=%s", resp.StatusCode, string(respBytes))
	}
	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("decode resp: %w body=%s", err, string(respBytes))
		}
	}
	return nil
}

// WechatAppPrepay 微信 APP 支付下单请求体。
//
// 字段说明：
//   - AppID / MchID：由客户端自动填入
//   - Description：商品描述（展示给用户，例：RePhone Security 会员年付）
//   - OutTradeNo：商户订单号，服务端生成，全局唯一（建议 wx_ + 时间戳 + uuid）
//   - NotifyURL：异步回调地址（覆盖配置中的 NotifyURL，可按订单维度区分）
//   - Amount.Total：金额（单位：分）
//   - Payer.OpenID：APP 支付不需要 openid，留空
type WechatAppPrepayRequest struct {
	AppID       string             `json:"appid"`
	MchID       string             `json:"mchid"`
	Description string             `json:"description"`
	OutTradeNo  string             `json:"out_trade_no"`
	NotifyURL   string             `json:"notify_url"`
	Amount      WechatPrepayAmount `json:"amount"`
	Attach      string             `json:"attach,omitempty"`
}

// WechatPrepayAmount 下单金额结构。
type WechatPrepayAmount struct {
	Total    int    `json:"total"`
	Currency string `json:"currency"`
}

// WechatAppPrepayResponse APP 下单成功响应体（仅 prepay_id 字段）。
type WechatAppPrepayResponse struct {
	PrepayID string `json:"prepay_id"`
}

// WechatAppPayParams 返回给 Flutter 客户端调起微信 SDK 的 5 个参数。
//
// 客户端调用 `fluwx.payWithWeChat(PayWithWeChat(appId, partnerId, prepayId, nonceStr, timeStamp, sign))`
// 时需要的字段，全部由服务端签名后下发，客户端不参与签名，保证安全。
type WechatAppPayParams struct {
	AppID     string `json:"app_id"`
	PartnerID string `json:"partner_id"`
	PrepayID  string `json:"prepay_id"`
	Package   string `json:"package"` // 固定为 "Sign=WXPay"
	NonceStr  string `json:"nonce_str"`
	Timestamp string `json:"timestamp"` // 字符串类型，秒级时间戳
	Sign      string `json:"sign"`      // 客户端签名（再次使用商户私钥签名：appid + timestamp + noncestr + prepayid）
}

// CreateAppOrder 创建一笔「APP 支付」订单。
//
// 入参：
//   - productID：商品 ID（例：rephone_pro）
//   - plan：套餐（monthly / yearly），用于描述与价格计算
//   - email：当前登录用户 email，作为 attach 透传，回调时识别用户
//   - userIP：可选，用户真实 IP，透传到微信风控
//
// 返回：(客户端调起参数, 商户订单号 outTradeNo, error)。
// outTradeNo 必须回传给客户端并落库，后续 notify / verify / query 三处都靠它定位订单。
//
// 本函数始终真实请求微信 `/v3/pay/transactions/app`，没有模拟降级。
func (c *WechatPayClient) CreateAppOrder(productID, plan, email, userIP string) (*WechatAppPayParams, string, error) {
	outTradeNo := generateWechatOutTradeNo()
	amount := resolveWechatAmount(c.cfg, plan)
	attach := fmt.Sprintf("%s|%s", email, plan)
	description := fmt.Sprintf("RePhone Security 会员 %s", friendlyPlanLabel(plan))
	notifyURL := c.cfg.NotifyURL
	if notifyURL == "" {
		notifyURL = "https://rephone.top/api/payment/wechat/notify"
	}

	reqBody := WechatAppPrepayRequest{
		AppID:       c.cfg.AppID,
		MchID:       c.cfg.MchID,
		Description: description,
		OutTradeNo:  outTradeNo,
		NotifyURL:   notifyURL,
		Amount:      WechatPrepayAmount{Total: amount, Currency: "CNY"},
		Attach:      attach,
	}
	var resp WechatAppPrepayResponse
	if err := c.doRequest(context.Background(), http.MethodPost,
		"/v3/pay/transactions/app", reqBody, &resp); err != nil {
		return nil, "", fmt.Errorf("wechat create app order: %w", err)
	}
	logger.Infof("[WechatPay] 下单成功：order=%s prepay_id=%s", outTradeNo, resp.PrepayID)
	params, err := c.buildAppPayParams(outTradeNo, resp.PrepayID, attach)
	return params, outTradeNo, err
}

// buildAppPayParams 构造返回给客户端的调起参数并签名。
//
// 客户端侧签名原文（微信 APP 支付签名步骤二）：
//
//	appid + \n + timestamp + \n + noncestr + \n + prepayid + \n
//
// 注意：第二步的签名不参与第一步 HTTP Authorization 头计算，独立用商户私钥再次签名。
func (c *WechatPayClient) buildAppPayParams(outTradeNo, prepayID, attach string) (*WechatAppPayParams, error) {
	nonce := randomHexString(16)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	pkg := "Sign=WXPay"
	appid := c.cfg.AppID
	// 构造签名原文
	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n", appid, ts, nonce, prepayID)
	if c.privKey == nil {
		return nil, fmt.Errorf("wechat merchant private key is not loaded")
	}
	hash := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("build client sign: %w", err)
	}
	return &WechatAppPayParams{
		AppID:     appid,
		PartnerID: c.cfg.MchID,
		PrepayID:  prepayID,
		Package:   pkg,
		NonceStr:  nonce,
		Timestamp: ts,
		Sign:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// WechatOrderQueryResponse 微信查单响应（核心字段，仅取需要的）。
type WechatOrderQueryResponse struct {
	AppID          string            `json:"appid"`
	MchID          string            `json:"mchid"`
	OutTradeNo     string            `json:"out_trade_no"`
	TransactionID  string            `json:"transaction_id"`
	TradeType      string            `json:"trade_type"`
	TradeState     string            `json:"trade_state"` // SUCCESS / REFUND / NOTPAY / CLOSED ...
	TradeStateDesc string            `json:"trade_state_desc"`
	Attach         string            `json:"attach,omitempty"`
	Amount         WechatQueryAmount `json:"amount,omitempty"`
	SuccessTime    string            `json:"success_time,omitempty"`
}

// WechatQueryAmount 查单响应中的金额结构。
type WechatQueryAmount struct {
	Total         int    `json:"total"`
	PayerTotal    int    `json:"payer_total"`
	Currency      string `json:"currency"`
	PayerCurrency string `json:"payer_currency"`
}

// QueryOrderByOutTradeNo 根据商户订单号查询订单。
//
// 主要用于：
//  1. 客户端自报成功后，服务端不信任前端，主动向微信查单确认
//  2. 异步回调长期未收到时，用户手动触发的兜底查询
func (c *WechatPayClient) QueryOrderByOutTradeNo(outTradeNo string) (*WechatOrderQueryResponse, error) {
	path := fmt.Sprintf("/v3/pay/transactions/out-trade-no/%s?mchid=%s", outTradeNo, c.cfg.MchID)
	var resp WechatOrderQueryResponse
	if err := c.doRequest(context.Background(), http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("wechat query order: %w", err)
	}
	return &resp, nil
}

// WechatNotifyResource 微信异步回调中的 resource 段（AES-GCM 加密）。
type WechatNotifyResource struct {
	Algorithm      string `json:"algorithm"`
	Ciphertext     string `json:"ciphertext"`
	AssociatedData string `json:"associated_data"`
	Nonce          string `json:"nonce"`
	OriginalType   string `json:"original_type"`
}

// WechatNotifyPayload 微信异步回调完整结构。
type WechatNotifyPayload struct {
	ID           string               `json:"id"`
	CreateTime   string               `json:"create_time"`
	EventType    string               `json:"event_type"`
	ResourceType string               `json:"resource_type"`
	Summary      string               `json:"summary"`
	Resource     WechatNotifyResource `json:"resource"`
}

// WechatDecryptedNotify 解密后的支付通知明文。
type WechatDecryptedNotify struct {
	AppID          string            `json:"appid"`
	MchID          string            `json:"mchid"`
	OutTradeNo     string            `json:"out_trade_no"`
	TransactionID  string            `json:"transaction_id"`
	TradeType      string            `json:"trade_type"`
	TradeState     string            `json:"trade_state"`
	TradeStateDesc string            `json:"trade_state_desc"`
	BankType       string            `json:"bank_type"`
	Attach         string            `json:"attach,omitempty"`
	SuccessTime    string            `json:"success_time,omitempty"`
	Payer          WechatPayer       `json:"payer"`
	Amount         WechatQueryAmount `json:"amount"`
}

// WechatPayer 支付者信息。
type WechatPayer struct {
	OpenID string `json:"openid"`
}

// DecryptNotifyResource 使用 APIv3Key 通过 AES-256-GCM 解密 resource.ciphertext。
//
// 解密规范：
//   - key = APIv3Key 的字节（长度必须 32）
//   - nonce = resource.nonce
//   - aad = resource.associated_data（ASCII 字符串）
//   - ciphertext = base64.DecodeString(resource.ciphertext)，前 12 字节是 GCM tag？
//     官方文档说明：ciphertext 本身是 base64(auth_tag + 密文)，直接丢给标准库 aes-gcm Open 即可。
func (c *WechatPayClient) DecryptNotifyResource(res WechatNotifyResource) (*WechatDecryptedNotify, error) {
	plain, err := c.decryptWithAPIv3Key(res.Nonce, res.AssociatedData, res.Ciphertext)
	if err != nil {
		return nil, err
	}
	var n WechatDecryptedNotify
	if err := json.Unmarshal(plain, &n); err != nil {
		return nil, fmt.Errorf("decode notify: %w body=%s", err, string(plain))
	}
	return &n, nil
}

// ———————————————— 工具函数 ————————————————

// resolveWechatAmount 根据配置与 plan 计算订单价格（单位：分）。
//
// 价格在服务端集中管理，不信任客户端传入的金额，防止篡改。
// 取值优先级：config.ini [wechat_pay].price_monthly_fen / price_yearly_fen
// → 未配置或非法（<=0）时回落到内置默认值并打告警。
func resolveWechatAmount(cfg WechatConfig, plan string) int {
	switch plan {
	case "yearly":
		if cfg.PriceYearlyFen > 0 {
			return cfg.PriceYearlyFen
		}
		if v := wechatPriceFromEnv("WECHAT_PRICE_YEARLY_FEN"); v > 0 {
			return v
		}
		return defaultPriceYearlyFen
	case "monthly":
		fallthrough
	default:
		if cfg.PriceMonthlyFen > 0 {
			return cfg.PriceMonthlyFen
		}
		if v := wechatPriceFromEnv("WECHAT_PRICE_MONTHLY_FEN"); v > 0 {
			return v
		}
		return defaultPriceMonthlyFen
	}
}

// wechatPriceFromEnv 允许用环境变量覆盖价格，便于不同环境差异化定价。
func wechatPriceFromEnv(key string) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// WechatProduct 对外暴露的商品套餐信息（供 /api/payment/products 下发价格给客户端）。
type WechatProduct struct {
	ProductID    string `json:"product_id"`
	Plan         string `json:"plan"`
	AmountFen    int    `json:"amount_fen"`
	Currency     string `json:"currency"`
	DisplayPrice string `json:"display_price"`
	DurationDays int    `json:"duration_days"`
}

// ListProducts 返回当前服务端定价的套餐列表。
//
// 客户端「会员页」应以此为准渲染价格，避免在 Dart 侧硬编码第二份价格。
func (c *WechatPayClient) ListProducts() []WechatProduct {
	products := make([]WechatProduct, 0, 2)
	for _, p := range []struct {
		id    string
		plan  string
		label string
	}{
		{"rephone_premium_monthly", "monthly", "月卡"},
		{"rephone_premium_yearly", "yearly", "年卡"},
	} {
		fen := resolveWechatAmount(c.cfg, p.plan)
		products = append(products, WechatProduct{
			ProductID:    p.id,
			Plan:         p.plan,
			AmountFen:    fen,
			Currency:     "CNY",
			DisplayPrice: formatFenToYuan(fen),
			DurationDays: int(resolveWechatDuration(p.plan) / (24 * time.Hour)),
		})
	}
	return products
}

// formatFenToYuan 把「分」格式化成展示用的「元」字符串，例：2399 → "¥23.99"。
func formatFenToYuan(fen int) string {
	return fmt.Sprintf("¥%d.%02d", fen/100, fen%100)
}

// resolveWechatDuration 根据 plan 计算会员有效期（续费追加时使用）。
func resolveWechatDuration(plan string) time.Duration {
	switch plan {
	case "yearly":
		return 365 * 24 * time.Hour
	case "monthly":
		fallthrough
	default:
		return 30 * 24 * time.Hour
	}
}

func friendlyPlanLabel(plan string) string {
	switch plan {
	case "monthly":
		return "月卡"
	case "yearly":
		return "年卡"
	default:
		return "月卡"
	}
}

// generateWechatOutTradeNo 生成商户订单号。
//
// 约束：32 字符以内，只能是数字/大小写字母/下划线/_-/@.；商户侧全局唯一。
// 格式：wx_ + 毫秒级时间戳 + 8 位随机十六进制。
func generateWechatOutTradeNo() string {
	return fmt.Sprintf("wx%d%s", time.Now().UnixMilli(), randomHexString(8))
}

func randomHexString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 低概率错误，兜底用时间派生串
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n]
	}
	return fmt.Sprintf("%x", b)
}

// ———————————————— 微信平台证书 & 回调验签 ————————————————

// 平台证书相关常量。
const (
	// wechatCertsPath 获取平台证书的 APIv3 接口。
	wechatCertsPath = "/v3/certificates"
	// wechatNotifyTimestampSkew 回调时间戳允许的最大偏移，超出即视为重放攻击。
	wechatNotifyTimestampSkew = 5 * time.Minute
	// wechatCertRefreshInterval 本地证书缓存的强制刷新间隔。
	wechatCertRefreshInterval = 12 * time.Hour
)

// wechatCertEncryptItem / wechatCertItem / wechatCertResponse 是 /v3/certificates 的响应结构。
type wechatCertResponse struct {
	Data []wechatCertItem `json:"data"`
}

type wechatCertItem struct {
	SerialNo           string            `json:"serial_no"`
	EffectiveTime      string            `json:"effective_time"`
	ExpireTime         string            `json:"expire_time"`
	EncryptCertificate wechatEncryptCert `json:"encrypt_certificate"`
}

type wechatEncryptCert struct {
	Algorithm      string `json:"algorithm"`
	Nonce          string `json:"nonce"`
	AssociatedData string `json:"associated_data"`
	Ciphertext     string `json:"ciphertext"`
}

// decryptWithAPIv3Key 用 APIv3 密钥做 AES-256-GCM 解密。
//
// 回调 resource 与 /v3/certificates 的 encrypt_certificate 使用完全相同的
// 加密方式，因此共用这一个实现。
func (c *WechatPayClient) decryptWithAPIv3Key(nonce, associatedData, ciphertext string) ([]byte, error) {
	key := []byte(c.cfg.APIv3Key)
	if len(key) != 32 {
		return nil, fmt.Errorf("wechat apiv3 key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 cipher: %w", err)
	}
	var aad []byte
	if associatedData != "" {
		aad = []byte(associatedData)
	}
	plain, err := gcm.Open(nil, []byte(nonce), cipherBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plain, nil
}

// fetchPlatformCerts 调用 /v3/certificates 拉取并解密微信平台证书。
//
// 微信平台证书用于校验回调请求头中的 Wechatpay-Signature，
// 是「回调防伪造」的唯一可靠手段，不能省略。
func (c *WechatPayClient) fetchPlatformCerts() (map[string]*wechatPlatformCert, error) {
	var resp wechatCertResponse
	if err := c.doRequest(context.Background(), http.MethodGet, wechatCertsPath, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetch wechat platform certs: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("fetch wechat platform certs: empty data")
	}

	certs := make(map[string]*wechatPlatformCert, len(resp.Data))
	for _, item := range resp.Data {
		plain, err := c.decryptWithAPIv3Key(
			item.EncryptCertificate.Nonce,
			item.EncryptCertificate.AssociatedData,
			item.EncryptCertificate.Ciphertext,
		)
		if err != nil {
			logger.Errorf("[WechatPay] 平台证书解密失败 serial=%s: %v", item.SerialNo, err)
			continue
		}
		block, _ := pem.Decode(plain)
		if block == nil {
			logger.Errorf("[WechatPay] 平台证书 PEM 解析失败 serial=%s", item.SerialNo)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Errorf("[WechatPay] 平台证书 X509 解析失败 serial=%s: %v", item.SerialNo, err)
			continue
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			logger.Errorf("[WechatPay] 平台证书公钥非 RSA serial=%s", item.SerialNo)
			continue
		}
		certs[item.SerialNo] = &wechatPlatformCert{
			serial:  item.SerialNo,
			pubKey:  pubKey,
			expire:  cert.NotAfter,
			certPEM: string(plain),
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no usable wechat platform certificate")
	}
	return certs, nil
}

// getPlatformCert 按 serial 取平台证书公钥。
//
// serial 为空时返回任意一张未过期证书（用于启动时预热）。
// 命中不到、或缓存已超过 wechatCertRefreshInterval 时自动重新拉取。
func (c *WechatPayClient) getPlatformCert(serial string) (*wechatPlatformCert, error) {
	c.certMu.RLock()
	cached, needRefresh := c.lookupCertLocked(serial)
	stale := time.Since(c.certsLastAt) > wechatCertRefreshInterval
	c.certMu.RUnlock()

	if cached != nil && !needRefresh && !stale {
		return cached, nil
	}

	// 加锁后重新检查，避免并发下重复拉取。
	c.certMu.Lock()
	defer c.certMu.Unlock()
	if cached, need := c.lookupCertLocked(serial); cached != nil && !need && time.Since(c.certsLastAt) <= wechatCertRefreshInterval {
		return cached, nil
	}

	certs, err := c.fetchPlatformCerts()
	if err != nil {
		// 拉取失败时降级使用旧缓存（若存在且未过期），保证短暂网络抖动不影响回调。
		if cached, need := c.lookupCertLocked(serial); cached != nil && !need {
			logger.Warnf("[WechatPay] 平台证书刷新失败，沿用旧缓存: %v", err)
			return cached, nil
		}
		return nil, err
	}
	c.certs = certs
	c.certsLastAt = time.Now()
	logger.Infof("[WechatPay] 平台证书已更新：%d 张", len(certs))

	if serial == "" {
		for _, v := range certs {
			return v, nil
		}
	}
	if v, ok := certs[serial]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("wechat platform certificate not found for serial=%s", serial)
}

// lookupCertLocked 在持锁状态下查找证书；needRefresh 表示缓存中没有可用项。
func (c *WechatPayClient) lookupCertLocked(serial string) (*wechatPlatformCert, bool) {
	now := time.Now()
	if serial != "" {
		if v, ok := c.certs[serial]; ok && v.expire.After(now) {
			return v, false
		}
		return nil, true
	}
	for _, v := range c.certs {
		if v.expire.After(now) {
			return v, false
		}
	}
	return nil, true
}

// VerifyNotifySignature 校验微信支付回调请求的签名。
//
// 验签规范（微信支付 APIv3 回调）：
//   - 参与签名的请求头：Wechatpay-Timestamp / Wechatpay-Nonce / Wechatpay-Signature / Wechatpay-Serial
//   - 验签原文：timestamp + "\n" + nonce + "\n" + body + "\n"
//   - 算法：SHA256withRSA，用「微信平台证书」中的公钥验签
//   - 时间戳超过 ±5 分钟视为重放，直接拒绝
//
// body 必须是未经任何修改的原始报文字节。
func (c *WechatPayClient) VerifyNotifySignature(header http.Header, body []byte) error {
	ts := strings.TrimSpace(header.Get("Wechatpay-Timestamp"))
	nonce := strings.TrimSpace(header.Get("Wechatpay-Nonce"))
	signature := strings.TrimSpace(header.Get("Wechatpay-Signature"))
	serial := strings.TrimSpace(header.Get("Wechatpay-Serial"))
	if ts == "" || nonce == "" || signature == "" || serial == "" {
		return fmt.Errorf("missing wechatpay signature headers")
	}

	tsSec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid wechatpay timestamp: %w", err)
	}
	if skew := time.Since(time.Unix(tsSec, 0)); skew > wechatNotifyTimestampSkew || skew < -wechatNotifyTimestampSkew {
		return fmt.Errorf("wechatpay timestamp out of range (skew=%s)", skew)
	}

	cert, err := c.getPlatformCert(serial)
	if err != nil {
		return fmt.Errorf("get platform cert: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode wechatpay signature: %w", err)
	}

	msg := fmt.Sprintf("%s\n%s\n%s\n", ts, nonce, string(body))
	hash := sha256.Sum256([]byte(msg))
	if err := rsa.VerifyPKCS1v15(cert.pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("wechatpay signature mismatch: %w", err)
	}
	return nil
}

// parseAttach 解析下单时写入的 attach 字符串，格式 "email|plan"。
func parseAttach(attach string) (email, plan string, ok bool) {
	if attach == "" {
		return "", "", false
	}
	parts := strings.SplitN(attach, "|", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}
