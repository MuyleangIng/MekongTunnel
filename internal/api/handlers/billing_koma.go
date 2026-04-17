package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (h *BillingHandler) createKomaCheckout(ctx context.Context, ref string, amountUSD float64) (*komaCheckoutSession, error) {
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

func (h *BillingHandler) checkKomaStatus(ctx context.Context, md5 string, pollToken string) (*komaStatusEnvelope, error) {
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

func (h *BillingHandler) httpClient() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (h *BillingHandler) komaAPIBaseURL() string {
	if v := strings.TrimSpace(h.KomaAPIURL); v != "" {
		return v
	}
	return defaultKomaAPIURL
}

func (h *BillingHandler) komaCallbackURLs(ref string) (string, string, error) {
	base := strings.TrimRight(strings.TrimSpace(h.FrontendURL), "/")
	if base == "" {
		return "", "", fmt.Errorf("frontend URL is not configured")
	}

	successURL, err := url.Parse(base + "/dashboard/billing")
	if err != nil {
		return "", "", err
	}
	successQuery := successURL.Query()
	successQuery.Set("bakong", "success")
	successQuery.Set("ref", ref)
	successURL.RawQuery = successQuery.Encode()

	cancelURL, err := url.Parse(base + "/dashboard/billing")
	if err != nil {
		return "", "", err
	}
	cancelQuery := cancelURL.Query()
	cancelQuery.Set("bakong", "cancelled")
	cancelQuery.Set("ref", ref)
	cancelURL.RawQuery = cancelQuery.Encode()

	return successURL.String(), cancelURL.String(), nil
}
