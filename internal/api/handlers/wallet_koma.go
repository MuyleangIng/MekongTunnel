package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultKomaAPIURL    = "https://koma.khqr.site"
	walletPollIntervalMS = 2500
)

var (
	komaCheckoutErrorPattern = regexp.MustCompile(`\b[A-Z]+(?:_[A-Z]+)+\b`)
	komaQRPattern            = regexp.MustCompile(`var qrDataUrl\s*=\s*"([^"]+)"`)
	komaTransactionPattern   = regexp.MustCompile(`var transactionId\s*=\s*"([^"]+)"`)
	komaMD5Pattern           = regexp.MustCompile(`var md5\s*=\s*"([^"]+)"`)
	komaPollTokenPattern     = regexp.MustCompile(`var pollToken\s*=\s*"([^"]+)"`)
)

type komaCheckoutSession struct {
	TransactionID string
	MD5           string
	PollToken     string
	QRDataURL     string
}

type komaStatusEnvelope struct {
	Success bool            `json:"success"`
	Data    *komaStatusData `json:"data"`
	Error   string          `json:"error,omitempty"`
}

type komaStatusData struct {
	ResponseCode    int             `json:"responseCode"`
	ResponseMessage string          `json:"responseMessage"`
	ErrorCode       *int            `json:"errorCode"`
	ErrorMessage    string          `json:"errorMessage,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
}

func (h *WalletHandler) createKomaCheckout(ctx context.Context, ref string, amountUSD float64) (*komaCheckoutSession, error) {
	merchantID := strings.TrimSpace(h.KomaMerchantID)
	secretKey := strings.TrimSpace(h.KomaSecretKey)
	if merchantID == "" || secretKey == "" {
		return nil, fmt.Errorf("Koma credentials are not configured")
	}

	successURL, cancelURL, err := h.komaCallbackURLs(ref)
	if err != nil {
		return nil, err
	}

	amount := strconv.FormatFloat(amountUSD, 'f', -1, 64)
	hash := signKomaCheckout(successURL, cancelURL, "USD", ref, merchantID, amount, secretKey)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range map[string]string{
		"amount":             amount,
		"merchantId":         merchantID,
		"hash":               hash,
		"tranID":             ref,
		"currency":           "USD",
		"returnURL":          cancelURL,
		"continueSuccessURL": successURL,
	} {
		if err := writer.WriteField(key, value); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(h.komaAPIBaseURL(), "/")+"/api/payment/checkout",
		&body,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	res, err := h.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	htmlBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	html := string(htmlBytes)

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if providerError := extractKomaCheckoutError(html); providerError != "" {
			return nil, fmt.Errorf("Koma checkout request failed: %s", providerError)
		}
		return nil, fmt.Errorf("Koma checkout request failed with status %d", res.StatusCode)
	}

	session := parseKomaCheckoutPage(html)
	if session == nil {
		return nil, fmt.Errorf("could not parse Koma checkout response")
	}

	return session, nil
}

func (h *WalletHandler) checkKomaStatus(ctx context.Context, md5 string, pollToken string) (*komaStatusEnvelope, error) {
	body, err := json.Marshal(map[string]string{
		"md5":       md5,
		"pollToken": pollToken,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(h.komaAPIBaseURL(), "/")+"/api/payment/status",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := h.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	payloadBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var payload komaStatusEnvelope
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid Koma status response: %w", err)
	}

	return &payload, nil
}

func (h *WalletHandler) httpClient() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (h *WalletHandler) komaAPIBaseURL() string {
	if v := strings.TrimSpace(h.KomaAPIURL); v != "" {
		return v
	}
	return defaultKomaAPIURL
}

func (h *WalletHandler) komaCallbackURLs(ref string) (string, string, error) {
	base := strings.TrimRight(strings.TrimSpace(h.FrontendURL), "/")
	if base == "" {
		return "", "", fmt.Errorf("frontend URL is not configured")
	}

	successURL, err := url.Parse(base + "/dashboard/wallet")
	if err != nil {
		return "", "", err
	}
	successQuery := successURL.Query()
	successQuery.Set("bakong", "success")
	successQuery.Set("ref", ref)
	successURL.RawQuery = successQuery.Encode()

	cancelURL, err := url.Parse(base + "/dashboard/wallet")
	if err != nil {
		return "", "", err
	}
	cancelQuery := cancelURL.Query()
	cancelQuery.Set("bakong", "cancelled")
	cancelQuery.Set("ref", ref)
	cancelURL.RawQuery = cancelQuery.Encode()

	return successURL.String(), cancelURL.String(), nil
}

func signKomaCheckout(successURL string, cancelURL string, currency string, tranID string, merchantID string, amount string, secretKey string) string {
	payload := successURL + cancelURL + currency + tranID + merchantID + amount
	mac := hmac.New(sha512.New, []byte(secretKey))
	_, _ = mac.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func extractKomaCheckoutError(html string) string {
	return komaCheckoutErrorPattern.FindString(html)
}

func parseKomaCheckoutPage(html string) *komaCheckoutSession {
	session := &komaCheckoutSession{
		QRDataURL:     firstMatch(html, komaQRPattern),
		TransactionID: firstMatch(html, komaTransactionPattern),
		MD5:           firstMatch(html, komaMD5Pattern),
		PollToken:     firstMatch(html, komaPollTokenPattern),
	}
	if session.QRDataURL == "" || session.TransactionID == "" || session.MD5 == "" || session.PollToken == "" {
		return nil
	}
	return session
}

func firstMatch(input string, pattern *regexp.Regexp) string {
	match := pattern.FindStringSubmatch(input)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func deriveKomaPhase(orderStatus string, payload *komaStatusEnvelope) string {
	switch orderStatus {
	case "paid", "failed", "expired":
		return orderStatus
	}

	if payload == nil {
		return "pending"
	}

	if payload.Data != nil && payload.Data.ResponseCode == 0 {
		return "paid"
	}
	if payload.Data != nil && payload.Data.ResponseCode == 1 && payload.Data.ErrorCode != nil && *payload.Data.ErrorCode == 2 {
		return "scanned"
	}
	if payload.Data != nil && payload.Data.ResponseCode == 1 && payload.Data.ErrorCode != nil && *payload.Data.ErrorCode == 3 {
		return "failed"
	}

	message := strings.ToLower(strings.TrimSpace(strings.Join([]string{
		komaStatusMessage(payload),
		komaStatusErrorMessage(payload),
		payload.Error,
	}, " ")))
	if strings.Contains(message, "expire") {
		return "expired"
	}

	return "pending"
}

func komaStatusMessage(payload *komaStatusEnvelope) string {
	if payload == nil || payload.Data == nil {
		return ""
	}
	return payload.Data.ResponseMessage
}

func komaStatusErrorMessage(payload *komaStatusEnvelope) string {
	if payload == nil || payload.Data == nil {
		return ""
	}
	return payload.Data.ErrorMessage
}
