package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/auth"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/signaler"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/turn"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/websocket"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/ini.v1"
)

func main() {

	cfg, err := ini.Load("configs/config.ini")
	if err != nil {
		logger.Errorf("Fail to read file: %v", err)
		os.Exit(1)
	}

	// init MySQL
	mysqlDSN := cfg.Section("mysql").Key("dsn").String()
	if len(mysqlDSN) == 0 {
		logger.Errorf("mysql.dsn is required in configs/config.ini")
		os.Exit(1)
	}
	db, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		logger.Errorf("Fail to open mysql: %v", err)
		os.Exit(1)
	}
	if err = db.Ping(); err != nil {
		logger.Errorf("Fail to ping mysql: %v", err)
		os.Exit(1)
	}

	var mailer auth.Mailer
	smtpHost := cfg.Section("smtp").Key("host").String()
	smtpPort, _ := cfg.Section("smtp").Key("port").Int()
	smtpUser := cfg.Section("smtp").Key("username").String()
	smtpPass := cfg.Section("smtp").Key("password").String()
	fromEmail := cfg.Section("smtp").Key("from_email").String()
	fromName := cfg.Section("smtp").Key("from_name").String()
	subject := cfg.Section("smtp").Key("subject").String()
	useTLS, _ := cfg.Section("smtp").Key("use_tls").Bool()
	skipVerify, _ := cfg.Section("smtp").Key("skip_verify").Bool()
	if smtpHost != "" && smtpPort != 0 && fromEmail != "" {
		mailer = auth.NewSMTPMailer(auth.SMTPConfig{
			Host:       smtpHost,
			Port:       smtpPort,
			Username:   smtpUser,
			Password:   smtpPass,
			FromEmail:  fromEmail,
			FromName:   fromName,
			Subject:    subject,
			UseTLS:     useTLS,
			SkipVerify: skipVerify,
		})
		logger.Infof("SMTP mailer enabled: %s:%d", smtpHost, smtpPort)
	}

	fcmSAPath := cfg.Section("fcm").Key("service_account").String()
	fcmProjectID := cfg.Section("fcm").Key("project_id").String()
	fcmEndpoint := cfg.Section("fcm").Key("endpoint").String()
	var fcmClient *auth.FCMClient
	if fcmSAPath != "" && fcmProjectID != "" {
		if client, err := auth.NewFCMClientFromServiceAccount(fcmSAPath, fcmProjectID, fcmEndpoint); err != nil {
			logger.Errorf("init FCM client error: %v", err)
		} else {
			fcmClient = client
		}
	}

	paymentSAPath := cfg.Section("payment").Key("service_account").String()
	packageName := cfg.Section("payment").Key("package_name").String()
	var paymentClient *http.Client
	if paymentSAPath != "" {
		if client, err := auth.NewGooglePlayClient(paymentSAPath); err != nil {
			logger.Errorf("init Payment client error: %v", err)
		} else {
			paymentClient = client
			logger.Infof("Payment client enabled for package: %s", packageName)
		}
	}

	// init WeChat Pay (国内版本)
	wechatEnable, _ := cfg.Section("wechat_pay").Key("enable").Bool()
	wechatAppID := cfg.Section("wechat_pay").Key("app_id").String()
	wechatMchID := cfg.Section("wechat_pay").Key("mch_id").String()
	wechatAPIv3Key := cfg.Section("wechat_pay").Key("api_v3_key").String()
	wechatCertSerial := cfg.Section("wechat_pay").Key("mch_cert_serial").String()
	wechatKeyPath := cfg.Section("wechat_pay").Key("mch_key_path").String()
	wechatNotifyURL := cfg.Section("wechat_pay").Key("notify_url").String()
	var wechatPayClient *auth.WechatPayClient
	if wechatEnable || wechatAppID != "" || wechatMchID != "" {
		wxClient, err := auth.NewWechatPayClient(auth.WechatConfig{
			AppID:             wechatAppID,
			MchID:             wechatMchID,
			MchCertSerialNo:   wechatCertSerial,
			APIv3Key:          wechatAPIv3Key,
			MchPrivateKeyPath: wechatKeyPath,
			NotifyURL:         wechatNotifyURL,
			Enable:            wechatEnable,
		})
		if err != nil {
			logger.Errorf("init WeChat Pay client error: %v", err)
		} else {
			wechatPayClient = wxClient
		}
	}

	authService := &auth.Service{
		DB:                db,
		Mailer:            mailer,
		FCM:               fcmClient,
		PaymentClient:     paymentClient,
		PackageName:       packageName,
		WechatPay:         wechatPayClient,
		WechatCallbackURL: wechatNotifyURL,
	}

	publicIP := cfg.Section("turn").Key("public_ip").String()
	stunPort, err := cfg.Section("turn").Key("port").Int()
	if err != nil {
		stunPort = 3478
	}
	realm := cfg.Section("turn").Key("realm").String()

	turnConfig := turn.DefaultConfig()
	turnConfig.PublicIP = publicIP
	turnConfig.Port = stunPort
	turnConfig.Realm = realm
	turn := turn.NewTurnServer(turnConfig)

	signaler := signaler.NewSignaler(turn)
	// Inject DB so signaler can update camera_online based on peer_id (camera_device_id).
	signaler.SetDB(db)
	wsServer := websocket.NewWebSocketServer(signaler.HandleNewWebSocket, signaler.HandleTurnServerCredentials)

	// register auth HTTP handlers
	http.HandleFunc("/api/auth/check-email", authService.HandleCheckEmail)
	http.HandleFunc("/api/auth/login", authService.HandleLogin)
	http.HandleFunc("/api/auth/verify-code", authService.HandleVerifyCode)
	http.HandleFunc("/api/auth/register", authService.HandleRegister)
	http.HandleFunc("/api/auth/delete-account", auth.AuthMiddleware(authService.HandleDeleteAccount))
	http.HandleFunc("/api/auth/send-reset-code", authService.HandleSendPasswordResetCode)
	http.HandleFunc("/api/auth/reset-password", authService.HandleResetPassword)
	http.HandleFunc("/api/auth/change-password", auth.AuthMiddleware(authService.HandleChangePassword))
	http.HandleFunc("/api/push/register", auth.AuthMiddleware(authService.HandleRegisterPushToken))
	http.HandleFunc("/api/push/alert", auth.AuthMiddleware(authService.HandlePushAlert))
	http.HandleFunc("/api/user/update-language", auth.AuthMiddleware(authService.HandleUpdateLanguage))

	// register device binding handlers
	http.HandleFunc("/api/device/add-binding", authService.HandleAddBinding)
	http.HandleFunc("/api/device/get-bindings", auth.AuthMiddleware(authService.HandleGetBindingsByMonitor))
	http.HandleFunc("/api/device/update-camera-info", auth.AuthMiddleware(authService.HandleUpdateCameraInfoByDeviceID))
	http.HandleFunc("/api/device/delete-camera", auth.AuthMiddleware(authService.HandleDeleteCameraByDeviceID))

	// feedback
	http.HandleFunc("/api/feedback/submit", auth.AuthMiddleware(authService.HandleSubmitFeedback))

	// payment verification
	http.HandleFunc("/api/payment/verify/google", auth.AuthMiddleware(authService.HandleVerifyGooglePurchase))
	http.HandleFunc("/api/payment/verify/apple", auth.AuthMiddleware(authService.HandleVerifyApplePurchase))
	http.HandleFunc("/api/payment/refresh", auth.AuthMiddleware(authService.HandleRefreshSubscription))

	// WeChat Pay (国内) —— 注意 notify 接口不挂 AuthMiddleware，由微信签名验证兜底
	http.HandleFunc("/api/payment/wechat/create-order", auth.AuthMiddleware(authService.HandleCreateWechatOrder))
	http.HandleFunc("/api/payment/wechat/notify", authService.HandleWechatNotify)
	http.HandleFunc("/api/payment/wechat/query", auth.AuthMiddleware(authService.HandleQueryWechatOrder))
	http.HandleFunc("/api/payment/wechat/verify", auth.AuthMiddleware(authService.HandleVerifyWechatOrder))

	sslCert := cfg.Section("general").Key("cert").String()
	sslKey := cfg.Section("general").Key("key").String()
	bindAddress := cfg.Section("general").Key("bind").String()

	port, err := cfg.Section("general").Key("port").Int()
	if err != nil {
		port = 8086
	}

	htmlRoot := cfg.Section("general").Key("html_root").String()

	config := websocket.DefaultConfig()
	config.Host = bindAddress
	config.Port = port
	config.CertFile = sslCert
	config.KeyFile = sslKey
	config.HTMLRoot = htmlRoot

	wsServer.Bind(config)
}
