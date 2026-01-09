package auth

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mailer defines email sending capability.
type Mailer interface {
	SendVerificationCode(toEmail string, code string) error
}

// SMTPConfig holds SMTP settings.
// 推荐使用 465(implicit TLS) 或 587(STARTTLS)；此实现支持 465 implicit TLS。
type SMTPConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	FromEmail  string
	FromName   string
	Subject    string
	UseTLS     bool // true for implicit TLS (e.g. port 465)
	SkipVerify bool
}

// SMTPMailer sends emails via SMTP.
type SMTPMailer struct {
	cfg SMTPConfig
}

func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

func (m *SMTPMailer) SendVerificationCode(toEmail string, code string) error {
	if strings.TrimSpace(toEmail) == "" {
		return fmt.Errorf("empty toEmail")
	}
	if m.cfg.Host == "" || m.cfg.Port == 0 {
		return fmt.Errorf("smtp host/port not configured")
	}
	if m.cfg.FromEmail == "" {
		return fmt.Errorf("smtp from_email not configured")
	}
	subject := m.cfg.Subject
	if subject == "" {
		subject = "Your verification code"
	}

	body := fmt.Sprintf("Your verification code is: %s\n\nIt expires in 10 minutes.\n", code)
	msg := buildRFC822Message(m.cfg.FromName, m.cfg.FromEmail, toEmail, subject, body)

	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	// Implicit TLS (port 465)
	if m.cfg.UseTLS {
		tlsCfg := &tls.Config{
			ServerName:         m.cfg.Host,
			InsecureSkipVerify: m.cfg.SkipVerify,
		}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		defer conn.Close()

		c, err := smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			return err
		}
		defer c.Close()

		_ = c.Hello("localhost")
		if err := c.Auth(auth); err != nil {
			return err
		}
		if err := c.Mail(m.cfg.FromEmail); err != nil {
			return err
		}
		if err := c.Rcpt(toEmail); err != nil {
			return err
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg); err != nil {
			_ = w.Close()
			return err
		}
		_ = w.Close()
		return c.Quit()
	}

	// Plain SMTP (often blocked by providers); kept for local SMTP relay scenarios.
	return smtp.SendMail(addr, auth, m.cfg.FromEmail, []string{toEmail}, msg)
}

func buildRFC822Message(fromName, fromEmail, toEmail, subject, body string) []byte {
	var buf bytes.Buffer
	from := fromEmail
	if strings.TrimSpace(fromName) != "" {
		// basic quoting; for non-ascii names you'd use MIME encoded-word, skipped for simplicity.
		from = fmt.Sprintf("%s <%s>", fromName, fromEmail)
	}
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + toEmail + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}


