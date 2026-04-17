package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiTokenValidator struct {
	baseURL string
	secret  string
	client  *http.Client
}

func NewAPITokenValidator(baseURL, secret string) TokenValidator {
	return &apiTokenValidator{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		secret:  strings.TrimSpace(secret),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (v *apiTokenValidator) ValidateToken(ctx context.Context, rawToken string) (string, error) {
	var out struct {
		UserID string `json:"user_id"`
	}
	if err := v.post(ctx, "/api/internal/edge/validate-token", map[string]string{"token": rawToken}, &out); err != nil {
		return "", err
	}
	return out.UserID, nil
}

func (v *apiTokenValidator) GetFirstReservedSubdomain(ctx context.Context, userID string) (string, error) {
	var out struct {
		Subdomain string `json:"subdomain"`
	}
	if err := v.get(ctx, "/api/internal/edge/first-subdomain", url.Values{"user_id": {userID}}, &out); err != nil {
		return "", err
	}
	return out.Subdomain, nil
}

func (v *apiTokenValidator) GetReservedSubdomainForUser(ctx context.Context, userID, subdomain string) (string, error) {
	var out struct {
		Subdomain string `json:"subdomain"`
	}
	if err := v.get(ctx, "/api/internal/edge/reserved-subdomain", url.Values{
		"user_id":   {userID},
		"subdomain": {subdomain},
	}, &out); err != nil {
		return "", err
	}
	return out.Subdomain, nil
}

func (v *apiTokenValidator) LookupVerifiedCustomDomainTarget(ctx context.Context, host string) (string, bool, error) {
	var out struct {
		TargetSubdomain string `json:"target_subdomain"`
		Found           bool   `json:"found"`
	}
	if err := v.get(ctx, "/api/internal/edge/custom-domain-target", url.Values{"host": {host}}, &out); err != nil {
		return "", false, err
	}
	return out.TargetSubdomain, out.Found, nil
}

func (v *apiTokenValidator) ReservedSubdomainExists(ctx context.Context, subdomain string) (bool, error) {
	var out struct {
		Exists bool `json:"exists"`
	}
	if err := v.get(ctx, "/api/internal/edge/subdomain-exists", url.Values{"subdomain": {subdomain}}, &out); err != nil {
		return false, err
	}
	return out.Exists, nil
}

func (v *apiTokenValidator) GetTunnelLastSeen(ctx context.Context, subdomain string) (*time.Time, error) {
	var out struct {
		LastSeenAt *time.Time `json:"last_seen_at"`
	}
	if err := v.get(ctx, "/api/internal/edge/tunnel-last-seen", url.Values{"subdomain": {subdomain}}, &out); err != nil {
		return nil, err
	}
	return out.LastSeenAt, nil
}

func (v *apiTokenValidator) get(ctx context.Context, path string, q url.Values, dst any) error {
	endpoint := v.baseURL + path
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return v.do(req, dst)
}

func (v *apiTokenValidator) post(ctx context.Context, path string, body any, dst any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return v.do(req, dst)
}

func (v *apiTokenValidator) do(req *http.Request, dst any) error {
	req.Header.Set("X-Tunnel-Secret", v.secret)
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d: %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var env struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	if !env.OK {
		if env.Error == "" {
			env.Error = "request failed"
		}
		return fmt.Errorf("%s", env.Error)
	}
	if dst == nil || len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, dst)
}
