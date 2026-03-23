// Package mailer sends transactional emails.
// If RESEND_API_KEY is set it uses the Resend HTTP API (recommended for cloud servers).
// Otherwise it falls back to Gmail SMTP — requires SMTP_USER + SMTP_PASS.
// If neither is configured every Send call is a no-op log (useful for local dev).
package mailer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Config holds credentials for either Resend or SMTP.
type Config struct {
	// Resend (preferred — works on DigitalOcean, no port blocks)
	ResendKey string // RESEND_API_KEY  e.g. "re_..."
	ResendFrom string // e.g. "Mekong Tunnel <noreply@angkorsearch.dev>"

	// SMTP fallback (Gmail STARTTLS port 587)
	Host string // default: smtp.gmail.com
	Port string // default: 587
	User string // Gmail address
	Pass string // Gmail App Password
	From string // display name + address
}

// Mailer sends emails.
type Mailer struct {
	cfg Config
}

// New returns a ready Mailer with sensible defaults.
func New(cfg Config) *Mailer {
	if cfg.Host == "" {
		cfg.Host = "smtp.gmail.com"
	}
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	if cfg.From == "" && cfg.User != "" {
		cfg.From = "Mekong Tunnel <" + cfg.User + ">"
	}
	if cfg.ResendFrom == "" {
		cfg.ResendFrom = "Mekong Tunnel <onboarding@resend.dev>"
	}
	return &Mailer{cfg: cfg}
}

// Enabled reports whether any email backend is configured.
func (m *Mailer) Enabled() bool {
	return m.cfg.ResendKey != "" || (m.cfg.User != "" && m.cfg.Pass != "")
}

// Send delivers an HTML email. Uses Resend if key is set, else SMTP.
func (m *Mailer) Send(to, subject, htmlBody string) error {
	if !m.Enabled() {
		log.Printf("[mailer] (not configured) to=%s subject=%q", to, subject)
		return nil
	}
	if m.cfg.ResendKey != "" {
		return m.sendResend(to, subject, htmlBody)
	}
	return m.sendSMTP(to, subject, htmlBody)
}

// ── Resend HTTP API ────────────────────────────────────────────────────────────

func (m *Mailer) sendResend(to, subject, htmlBody string) error {
	payload := map[string]any{
		"from":    m.cfg.ResendFrom,
		"to":      []string{to},
		"subject": subject,
		"html":    htmlBody,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("mailer: marshal: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mailer: resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.cfg.ResendKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("mailer: resend send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mailer: resend error %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ── SMTP (Gmail STARTTLS port 587) ─────────────────────────────────────────────

func (m *Mailer) sendSMTP(to, subject, htmlBody string) error {
	addr := net.JoinHostPort(m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Pass, m.cfg.Host)

	msg := strings.Join([]string{
		"From: " + m.cfg.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: text/html; charset="UTF-8"`,
		"",
		htmlBody,
	}, "\r\n")

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("mailer: smtp client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: m.cfg.Host}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("mailer: STARTTLS: %w", err)
		}
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("mailer: auth: %w", err)
	}
	if err := client.Mail(m.cfg.User); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mailer: RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mailer: close data: %w", err)
	}
	return client.Quit()
}

// SendVerification sends the email-verification link.
func (m *Mailer) SendVerification(toEmail, name, token, frontendURL string) {
	link := frontendURL + "/auth/verify-email?token=" + token
	html := verifyEmailHTML(name, link)
	if err := m.Send(toEmail, "Verify your Mekong Tunnel email", html); err != nil {
		log.Printf("[mailer] SendVerification to %s: %v", toEmail, err)
	} else {
		log.Printf("[mailer] verification email sent to %s", toEmail)
	}
}

// SendPasswordReset sends the password-reset link.
func (m *Mailer) SendPasswordReset(toEmail, name, token, frontendURL string) {
	link := frontendURL + "/auth/reset-password?token=" + token
	html := resetPasswordHTML(name, link)
	if err := m.Send(toEmail, "Reset your Mekong Tunnel password", html); err != nil {
		log.Printf("[mailer] SendPasswordReset to %s: %v", toEmail, err)
	} else {
		log.Printf("[mailer] password reset email sent to %s", toEmail)
	}
}

// SendLoginOTP sends a 6-digit login verification code to the user's email.
func (m *Mailer) SendLoginOTP(toEmail, name, code string) {
	html := loginOTPHTML(name, code)
	if err := m.Send(toEmail, "Your Mekong Tunnel login code: "+code, html); err != nil {
		log.Printf("[mailer] SendLoginOTP to %s: %v", toEmail, err)
	} else {
		log.Printf("[mailer] login OTP sent to %s", toEmail)
	}
}

// ── Email templates ───────────────────────────────────────────────────────────

func emailWrapper(title, preheader, bodyHTML string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>` + title + `</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif">
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all">` + preheader + `</div>
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f4f4;padding:40px 0">
  <tr><td align="center">
    <table width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%">
      <!-- Header -->
      <tr><td align="center" style="padding-bottom:24px">
        <span style="font-size:22px;font-weight:bold;color:#cc0001;letter-spacing:-0.5px">⛵ Mekong Tunnel</span>
      </td></tr>
      <!-- Card -->
      <tr><td style="background:#ffffff;border-radius:12px;padding:40px 40px 32px;border:1px solid #e8e8e8">
        ` + bodyHTML + `
      </td></tr>
      <!-- Footer -->
      <tr><td align="center" style="padding-top:24px">
        <p style="font-size:12px;color:#999;margin:0">
          &copy; Mekong Tunnel &nbsp;·&nbsp;
          <a href="https://angkorsearch.dev" style="color:#999;text-decoration:none">angkorsearch.dev</a>
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`
}

// bulletButton returns a Gmail-safe table-based button (bulletproof button technique).
func bulletButton(label, href, bgColor string) string {
	return fmt.Sprintf(`
<table cellpadding="0" cellspacing="0" border="0" style="margin:28px auto">
  <tr>
    <td align="center" bgcolor="%s"
        style="border-radius:8px;mso-padding-alt:0">
      <!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml"
        href="%s" style="height:48px;v-text-anchor:middle;width:220px"
        arcsize="10%%" stroke="f" fillcolor="%s">
        <w:anchorlock/>
        <center style="color:#ffffff;font-family:Arial,sans-serif;font-size:15px;font-weight:bold">%s</center>
      </v:roundrect><![endif]-->
      <!--[if !mso]><!-->
      <a href="%s"
         style="display:inline-block;background:%s;color:#ffffff;
                font-family:Arial,sans-serif;font-size:15px;font-weight:bold;
                text-decoration:none;padding:14px 36px;border-radius:8px;
                mso-hide:all">
        %s
      </a>
      <!--<![endif]-->
    </td>
  </tr>
</table>`, bgColor, href, bgColor, label, href, bgColor, label)
}

func verifyEmailHTML(name, link string) string {
	if name == "" {
		name = "there"
	}
	body := fmt.Sprintf(`
<h2 style="margin:0 0 8px;font-size:22px;color:#1a1a2e">Verify your email</h2>
<p style="margin:0 0 20px;font-size:15px;color:#555">Hi <strong>%s</strong>,</p>
<p style="margin:0 0 8px;font-size:15px;color:#555">
  Thanks for signing up! Please verify your email address to activate your account.
</p>
%s
<p style="font-size:13px;color:#999;margin:0 0 6px">
  Or paste this link into your browser:
</p>
<p style="font-size:12px;word-break:break-all;margin:0 0 28px">
  <a href="%s" style="color:#cc0001;text-decoration:none">%s</a>
</p>
<hr style="border:none;border-top:1px solid #eee;margin:0 0 20px">
<p style="font-size:12px;color:#aaa;margin:0">
  This link expires in <strong>24 hours</strong>.<br>
  If you did not create an account, you can safely ignore this email.
</p>`, name, bulletButton("Verify Email", link, "#cc0001"), link, link)

	return emailWrapper("Verify your Mekong Tunnel email", "Click the button to verify your email address.", body)
}

func loginOTPHTML(name, code string) string {
	if name == "" {
		name = "there"
	}
	body := fmt.Sprintf(`
<h2 style="margin:0 0 8px;font-size:22px;color:#1a1a2e">Your login code</h2>
<p style="margin:0 0 20px;font-size:15px;color:#555">Hi <strong>%s</strong>,</p>
<p style="margin:0 0 24px;font-size:15px;color:#555">
  Use the code below to complete your Mekong Tunnel login.
  It expires in <strong>5 minutes</strong>.
</p>
<div style="text-align:center;margin:0 0 28px">
  <div style="display:inline-block;background:#f4f4f4;border:2px dashed #cc0001;border-radius:12px;padding:18px 40px">
    <span style="font-family:'Courier New',Courier,monospace;font-size:36px;font-weight:bold;color:#cc0001;letter-spacing:10px">%s</span>
  </div>
</div>
<hr style="border:none;border-top:1px solid #eee;margin:0 0 20px">
<p style="font-size:12px;color:#aaa;margin:0">
  If you did not attempt to log in, you can safely ignore this email.<br>
  Someone may have entered your email by mistake.
</p>`, name, code)

	return emailWrapper("Your Mekong Tunnel login code", "Your one-time login code — expires in 5 minutes.", body)
}

func resetPasswordHTML(name, link string) string {
	if name == "" {
		name = "there"
	}
	body := fmt.Sprintf(`
<h2 style="margin:0 0 8px;font-size:22px;color:#1a1a2e">Reset your password</h2>
<p style="margin:0 0 20px;font-size:15px;color:#555">Hi <strong>%s</strong>,</p>
<p style="margin:0 0 8px;font-size:15px;color:#555">
  We received a request to reset your Mekong Tunnel password.
  Click the button below to choose a new one.
</p>
%s
<p style="font-size:13px;color:#999;margin:0 0 6px">
  Or paste this link into your browser:
</p>
<p style="font-size:12px;word-break:break-all;margin:0 0 28px">
  <a href="%s" style="color:#cc0001;text-decoration:none">%s</a>
</p>
<hr style="border:none;border-top:1px solid #eee;margin:0 0 20px">
<p style="font-size:12px;color:#aaa;margin:0">
  This link expires in <strong>1 hour</strong>.<br>
  If you did not request a password reset, you can safely ignore this email.
</p>`, name, bulletButton("Reset Password", link, "#1a1a2e"), link, link)

	return emailWrapper("Reset your Mekong Tunnel password", "Reset your password — link expires in 1 hour.", body)
}
