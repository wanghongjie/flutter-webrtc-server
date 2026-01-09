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

	// init SMTP mailer (optional)
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
	} else {
		logger.Warnf("SMTP not configured; verification codes will be logged only")
	}

	authService := &auth.Service{DB: db, Mailer: mailer}

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
	wsServer := websocket.NewWebSocketServer(signaler.HandleNewWebSocket, signaler.HandleTurnServerCredentials)

	// register auth HTTP handlers
	http.HandleFunc("/api/auth/check-email", authService.HandleCheckEmail)
	http.HandleFunc("/api/auth/login", authService.HandleLogin)
	http.HandleFunc("/api/auth/verify-code", authService.HandleVerifyCode)
	http.HandleFunc("/api/auth/register", authService.HandleRegister)

	// register device binding handlers
	http.HandleFunc("/api/device/add-binding", authService.HandleAddBinding)
	http.HandleFunc("/api/device/get-bindings", authService.HandleGetBindingsByMonitor)

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
