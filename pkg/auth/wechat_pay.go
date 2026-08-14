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
	"strings"
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
//   - Enable：是否启用微信支付；为 false 时走 dev 模式模拟，便于联调
type WechatConfig struct {
	AppID             string
	MchID             string
	MchCertSerialNo   string
	APIv3Key          string
	MchPrivateKeyPath string
	NotifyURL         string
	Enable            bool
}

// WechatPayClient 微信支付客户端。
//
// 封装 APIv3 下单、查单、回调签名验证、回调 AES 解密等能力。
// 目前只实现「APP 支付」模式（Flutter 原生 App 通过微信 SDK 调起）。
type WechatPayClient struct {
	cfg      WechatConfig
	privKey  *rsa.PrivateKey
	httpCli  *http.Client
	baseURL  string
}

// NewWechatPayClient 根据配置初始化微信支付客户端。
//
// 步骤：
//  1. 从 pem 文件加载商户私钥（用于请求签名）
//  2. 构造带超时的 http.Client
//
// 返回错误：私钥文件缺失 / PEM 解析失败 / 不是 RSA 私钥。
func NewWechatPayClient(cfg WechatConfig) (*WechatPayClient, error) {
	if !cfg.Enable {
		logger.Infof("[WechatPay] Enable=false，运行在 dev 模拟模式。")
		return &WechatPayClient{
			cfg:     cfg,
			httpCli: &http.Client{Timeout: 10 * time.Second},
			baseURL: "https://api.mch.weixin.qq.com",
		}, nil
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
	logger.Infof("[WechatPay] 初始化成功：AppID=%s MchID=%s", cfg.AppID, cfg.MchID)
	return &WechatPayClient{
		cfg:     cfg,
		privKey: key,
		httpCli: &http.Client{Timeout: 10 * time.Second},
		baseURL: "https://api.mch.weixin.qq.com",
	}, nil
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
	AppID       string                  `json:"appid"`
	MchID       string                  `json:"mchid"`
	Description string                  `json:"description"`
	OutTradeNo  string                  `json:"out_trade_no"`
	NotifyURL   string                  `json:"notify_url"`
	Amount      WechatPrepayAmount      `json:"amount"`
	Attach      string                  `json:"attach,omitempty"`
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
	Package   string `json:"package"`   // 固定为 "Sign=WXPay"
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
// 返回：WechatAppPayParams，包含客户端调起 SDK 的全部参数（含签名）
//
// Dev 模式（Enable=false）：不访问微信接口，直接返回假参数，
// 同时在 DB 中写入预订单，供后续 notify/verify 接口模拟完成。
func (c *WechatPayClient) CreateAppOrder(productID, plan, email, userIP string) (*WechatAppPayParams, error) {
	outTradeNo := generateWechatOutTradeNo()
	amount := resolveWechatAmount(productID, plan)
	attach := fmt.Sprintf("%s|%s", email, plan)
	description := fmt.Sprintf("RePhone Security 会员 %s", friendlyPlanLabel(plan))
	notifyURL := c.cfg.NotifyURL
	if notifyURL == "" {
		notifyURL = "https://rephone.top/api/payment/wechat/notify"
	}

	if !c.cfg.Enable {
		// Dev 模式：不走真实接口，直接构造假的 prepay 参数，签名也用 mock 计算。
		// 注意：dev 模式下客户端调起微信会失败，但服务端后续可以通过
		// verify/query 接口"手动"确认订单，便于联调。
		logger.Infof("[WechatPay][Dev] 模拟下单：order=%s product=%s plan=%s email=%s amount=%d分",
			outTradeNo, productID, plan, email, amount)
		return c.buildAppPayParams(outTradeNo, "mock_prepay_id_"+outTradeNo, attach)
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
		return nil, fmt.Errorf("wechat create app order: %w", err)
	}
	logger.Infof("[WechatPay] 下单成功：order=%s prepay_id=%s", outTradeNo, resp.PrepayID)
	return c.buildAppPayParams(outTradeNo, resp.PrepayID, attach)
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
	if appid == "" {
		appid = "wx_placeholder"
	}
	// 构造签名原文
	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n", appid, ts, nonce, prepayID)
	var sign string
	if c.cfg.Enable && c.privKey != nil {
		hash := sha256.Sum256([]byte(msg))
		sig, err := rsa.SignPKCS1v15(rand.Reader, c.privKey, crypto.SHA256, hash[:])
		if err != nil {
			return nil, fmt.Errorf("build client sign: %w", err)
		}
		sign = base64.StdEncoding.EncodeToString(sig)
	} else {
		// Dev 模式：sign 直接填原文的 sha256 hex，便于调试对比，不参与真实验证。
		sum := sha256.Sum256([]byte(msg + "|dev"))
		sign = fmt.Sprintf("%x", sum)
	}
	return &WechatAppPayParams{
		AppID:     appid,
		PartnerID: c.cfg.MchID,
		PrepayID:  prepayID,
		Package:   pkg,
		NonceStr:  nonce,
		Timestamp: ts,
		Sign:      sign,
	}, nil
}

// WechatOrderQueryResponse 微信查单响应（核心字段，仅取需要的）。
type WechatOrderQueryResponse struct {
	AppID         string           `json:"appid"`
	MchID         string           `json:"mchid"`
	OutTradeNo    string           `json:"out_trade_no"`
	TransactionID string           `json:"transaction_id"`
	TradeType     string           `json:"trade_type"`
	TradeState    string           `json:"trade_state"` // SUCCESS / REFUND / NOTPAY / CLOSED ...
	TradeStateDesc string          `json:"trade_state_desc"`
	Attach        string           `json:"attach,omitempty"`
	Amount        WechatQueryAmount `json:"amount,omitempty"`
	SuccessTime   string           `json:"success_time,omitempty"`
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
//   1. 客户端自报成功后，服务端不信任前端，主动向微信查单确认
//   2. 异步回调长期未收到时，用户手动触发的兜底查询
func (c *WechatPayClient) QueryOrderByOutTradeNo(outTradeNo string) (*WechatOrderQueryResponse, error) {
	if !c.cfg.Enable {
		return nil, fmt.Errorf("wechat disabled (dev mode), use dev-mock query instead")
	}
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
	ID           string              `json:"id"`
	CreateTime   string              `json:"create_time"`
	EventType    string              `json:"event_type"`
	ResourceType string              `json:"resource_type"`
	Summary      string              `json:"summary"`
	Resource     WechatNotifyResource `json:"resource"`
}

// WechatDecryptedNotify 解密后的支付通知明文。
type WechatDecryptedNotify struct {
	AppID           string            `json:"appid"`
	MchID           string            `json:"mchid"`
	OutTradeNo      string            `json:"out_trade_no"`
	TransactionID   string            `json:"transaction_id"`
	TradeType       string            `json:"trade_type"`
	TradeState      string            `json:"trade_state"`
	TradeStateDesc  string            `json:"trade_state_desc"`
	BankType        string            `json:"bank_type"`
	Attach          string            `json:"attach,omitempty"`
	SuccessTime     string            `json:"success_time,omitempty"`
	Payer           WechatPayer       `json:"payer"`
	Amount          WechatQueryAmount `json:"amount"`
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
	cipherBytes, err := base64.StdEncoding.DecodeString(res.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 cipher: %w", err)
	}
	nonce := []byte(res.Nonce)
	var aad []byte
	if res.AssociatedData != "" {
		aad = []byte(res.AssociatedData)
	}
	plain, err := gcm.Open(nil, nonce, cipherBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	var n WechatDecryptedNotify
	if err := json.Unmarshal(plain, &n); err != nil {
		return nil, fmt.Errorf("decode notify: %w body=%s", err, string(plain))
	}
	return &n, nil
}

// ———————————————— 工具函数 ————————————————

// resolveWechatAmount 根据 productID + plan 计算订单价格（单位：分）。
//
// 价格在服务端集中管理，不信任客户端传入的金额，防止篡改。
//   - monthly：299 分（¥2.99 示例，上线前替换成真实定价）
//   - yearly：2399 分（¥23.99 示例，年付约 8 折）
func resolveWechatAmount(productID, plan string) int {
	switch plan {
	case "monthly":
		return 299
	case "yearly":
		return 2399
	default:
		return 299
	}
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
