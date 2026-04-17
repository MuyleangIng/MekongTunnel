package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/MuyleangIng/MekongTunnel/internal/api"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/pquerna/otp/totp"
)

const (
	testJWTSecret     = "integration-jwt-secret"
	testRefreshSecret = "integration-refresh-secret"
	testPassword      = "Passw0rd!"
)

var (
	testDB                *db.DB
	testAPIServer         *api.Server
	testHTTPServer        *httptest.Server
	testTunnelStatsServer *httptest.Server
	testHTTPClient        *http.Client
	testPasswordHash      string
	testUploadDir         string
	testBaseURL           string
	testUserSeq           atomic.Int64

	baselinePlanConfigs []*models.PlanConfig
	baselineServerCfg   *models.ServerConfig

	durationByResp sync.Map
	resultMu       sync.Mutex
	results        suiteResults
)

type suiteResults struct {
	passed  int
	failed  int
	skipped int
}

type apiEnvelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

type caseContext struct {
	freeUser      models.User
	proUser       models.User
	adminUser     models.User
	freeJWT       string
	proJWT        string
	adminJWT      string
	freeAPIToken  string
	proAPIToken   string
	adminAPIToken string
}

type endpointCase struct {
	name               string
	method             string
	path               string
	expected           int
	authRequired       string
	unauthorizedStatus int
	skipIf             func(*caseContext) string
	run                func(t *testing.T, c *caseContext) *http.Response
	runUnauthorized    func(t *testing.T, c *caseContext) *http.Response
	runForbidden       func(t *testing.T, c *caseContext) *http.Response
}

func TestMain(m *testing.M) {
	var err error
	testPasswordHash, err = auth.HashPassword(testPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash test password: %v\n", err)
		os.Exit(1)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://localhost/tunnl_test"
	}

	testDB, err = db.Connect(databaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping integration tests: no test DB available (%v)\n", err)
		os.Exit(0)
	}

	if err := db.RunMigrations(testDB, testMigrationsDir()); err != nil {
		fmt.Fprintf(os.Stderr, "run migrations: %v\n", err)
		os.Exit(1)
	}
	if err := testDB.EnsureServerConfig(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "ensure server config: %v\n", err)
		os.Exit(1)
	}

	baselinePlanConfigs, err = testDB.GetPlanConfigs(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "load baseline plan configs: %v\n", err)
		os.Exit(1)
	}
	baselineServerCfg, err = testDB.GetServerConfig(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "load baseline server config: %v\n", err)
		os.Exit(1)
	}

	testUploadDir, err = os.MkdirTemp("", "mekong-handler-upload-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create upload dir: %v\n", err)
		os.Exit(1)
	}

	testTunnelStatsServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stats" {
			http.NotFound(w, r)
			return
		}
		response.Success(w, map[string]any{
			"active_tunnels": 1,
			"total_tunnels":  1,
		})
	}))

	testAPIServer = api.New(testDB, api.Config{
		JWTSecret:       testJWTSecret,
		RefreshSecret:   testRefreshSecret,
		TunnelServerURL: testTunnelStatsServer.URL,
		AllowedOrigins:  []string{"http://localhost:3000"},
		FrontendURL:     "http://localhost:3000",
		PlanPrices:      map[string]string{"pro": os.Getenv("STRIPE_PRICE_PRO"), "org": os.Getenv("STRIPE_PRICE_ORG")},
		UploadDir:       testUploadDir,
		PublicURL:       "http://public.test",
	})
	testHTTPServer = httptest.NewServer(testAPIServer)
	testBaseURL = testHTTPServer.URL
	testHTTPClient = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	code := m.Run()

	_ = cleanAndRestoreDB()
	testHTTPServer.Close()
	testAPIServer.Close()
	testTunnelStatsServer.Close()
	_ = os.RemoveAll(testUploadDir)
	testDB.Close()

	os.Exit(code)
}

func TestAllEndpoints(t *testing.T) {
	resetResults()
	started := time.Now()

	cases := buildEndpointCases()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := newCaseContext()

			if tc.skipIf != nil {
				if reason := tc.skipIf(ctx); reason != "" {
					recordSkip(labelFor(tc.method, tc.path), reason)
					return
				}
			}

			if tc.runUnauthorized != nil {
				expected := tc.unauthorizedStatus
				if expected == 0 {
					expected = http.StatusUnauthorized
				}
				assertStatus(t, tc.runUnauthorized(t, ctx), expected, labelFor(tc.method, tc.path)+" [no auth]")
			}
			if tc.runForbidden != nil {
				assertStatus(t, tc.runForbidden(t, ctx), http.StatusForbidden, labelFor(tc.method, tc.path)+" [non-admin]")
			}
			assertStatus(t, tc.run(t, ctx), tc.expected, labelFor(tc.method, tc.path))
		})
	}

	printSummary(time.Since(started))

	resultMu.Lock()
	failed := results.failed
	resultMu.Unlock()
	if failed > 0 {
		t.Fail()
	}
}

func buildEndpointCases() []endpointCase {
	cases := []endpointCase{
		{
			name:         "Health",
			method:       http.MethodGet,
			path:         "/api/health",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/health", nil, "")
			},
		},
		{
			name:         "Announcement",
			method:       http.MethodGet,
			path:         "/api/announcement",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/announcement", nil, "")
			},
		},
		{
			name:         "AuthRegister",
			method:       http.MethodPost,
			path:         "/api/auth/register",
			expected:     http.StatusCreated,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/register", map[string]any{
					"name":         "Register Test",
					"email":        fmt.Sprintf("register-%d@example.com", testUserSeq.Add(1)),
					"password":     testPassword,
					"account_type": "personal",
				}, "")
			},
		},
		{
			name:         "AuthLogin",
			method:       http.MethodPost,
			path:         "/api/auth/login",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/login", map[string]any{
					"email":    c.freeUser.Email,
					"password": testPassword,
				}, "")
			},
		},
		{
			name:         "AuthLogout",
			method:       http.MethodPost,
			path:         "/api/auth/logout",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				cookie := mustRefreshCookie(c.freeUser.ID)
				return makeRequestWithCookies(http.MethodPost, "/api/auth/logout", nil, "", []*http.Cookie{cookie})
			},
		},
		{
			name:         "AuthMe",
			method:       http.MethodGet,
			path:         "/api/auth/me",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/me", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/me", nil, c.freeJWT)
			},
		},
		{
			name:         "AuthTokenInfo",
			method:       http.MethodGet,
			path:         "/api/auth/token-info",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/token-info", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/token-info", nil, c.freeAPIToken)
			},
		},
		{
			name:         "AuthRefresh",
			method:       http.MethodPost,
			path:         "/api/auth/refresh",
			expected:     http.StatusOK,
			authRequired: "Cookie",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequestWithCookies(http.MethodPost, "/api/auth/refresh", nil, "", []*http.Cookie{mustRefreshCookie(c.freeUser.ID)})
			},
		},
		{
			name:         "AuthForgotPassword",
			method:       http.MethodPost,
			path:         "/api/auth/forgot-password",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/forgot-password", map[string]any{"email": c.freeUser.Email}, "")
			},
		},
		{
			name:         "AuthResetPassword",
			method:       http.MethodPost,
			path:         "/api/auth/reset-password",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				token := mustPasswordResetToken(c.freeUser.ID)
				return makeRequest(http.MethodPost, "/api/auth/reset-password", map[string]any{
					"token":    token,
					"password": "NewPassw0rd!",
				}, "")
			},
		},
		{
			name:         "AuthVerifyEmail",
			method:       http.MethodPost,
			path:         "/api/auth/verify-email",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				user := seedUserWithOptions("verify", map[string]any{"email_verified": false})
				token := mustEmailVerifyToken(user.ID)
				return makeRequest(http.MethodPost, "/api/auth/verify-email", map[string]any{"token": token}, "")
			},
		},
		{
			name:         "AuthResendVerify",
			method:       http.MethodPost,
			path:         "/api/auth/resend-verify",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				user := seedUserWithOptions("resend", map[string]any{"email_verified": false})
				return makeRequest(http.MethodPost, "/api/auth/resend-verify", map[string]any{"email": user.Email}, "")
			},
		},
		{
			name:         "AuthRequestAdminVerify",
			method:       http.MethodPost,
			path:         "/api/auth/request-admin-verify",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				user := seedUserWithOptions("adminverify", map[string]any{"email_verified": false})
				return makeRequest(http.MethodPost, "/api/auth/request-admin-verify", map[string]any{
					"email":   user.Email,
					"message": "please review",
				}, "")
			},
		},
		{
			name:         "AuthEmailOTPVerify",
			method:       http.MethodPost,
			path:         "/api/auth/email-otp/verify",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, c *caseContext) *http.Response {
				if err := testDB.EnableEmailOTP(context.Background(), c.freeUser.ID); err != nil {
					t.Fatalf("enable email otp: %v", err)
				}
				code := "123456"
				if err := testDB.CreateEmailOTPCode(context.Background(), c.freeUser.ID, auth.HashToken(code), time.Now().Add(5*time.Minute)); err != nil {
					t.Fatalf("create email otp: %v", err)
				}
				tempToken, err := auth.GenerateTemp2FAToken(c.freeUser.ID, c.freeUser.Email, testJWTSecret)
				if err != nil {
					t.Fatalf("generate temp token: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/auth/email-otp/verify", map[string]any{
					"code":       code,
					"temp_token": tempToken,
				}, "")
			},
		},
		{
			name:         "AuthEnableEmailOTP",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/email/enable",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/email/enable", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/email/enable", nil, c.freeJWT)
			},
		},
		{
			name:         "AuthDisableEmailOTP",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/email/disable",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/email/disable", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if err := testDB.EnableEmailOTP(context.Background(), c.freeUser.ID); err != nil {
					t.Fatalf("enable email otp: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/auth/2fa/email/disable", nil, c.freeJWT)
			},
		},
		{
			name:         "AuthGitHub",
			method:       http.MethodGet,
			path:         "/api/auth/github",
			expected:     http.StatusFound,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/github", nil, "")
			},
		},
		{
			name:         "AuthGitHubCallback",
			method:       http.MethodGet,
			path:         "/api/auth/github/callback",
			expected:     http.StatusBadRequest,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/github/callback", nil, "")
			},
		},
		{
			name:         "AuthGoogle",
			method:       http.MethodGet,
			path:         "/api/auth/google",
			expected:     http.StatusFound,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/google", nil, "")
			},
		},
		{
			name:         "AuthGoogleCallback",
			method:       http.MethodGet,
			path:         "/api/auth/google/callback",
			expected:     http.StatusBadRequest,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/auth/google/callback", nil, "")
			},
		},
		{
			name:         "AuthSetup2FA",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/setup",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/setup", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/setup", nil, c.freeJWT)
			},
		},
		{
			name:         "AuthEnable2FA",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/enable",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/enable", map[string]any{"code": "000000"}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				secret, _, _, err := auth.GenerateTOTPSecret(c.freeUser.Email, "MekongTunnel")
				if err != nil {
					t.Fatalf("generate totp secret: %v", err)
				}
				if err := testDB.SetTOTPSecret(context.Background(), c.freeUser.ID, secret); err != nil {
					t.Fatalf("set totp secret: %v", err)
				}
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatalf("generate totp code: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/auth/2fa/enable", map[string]any{"code": code}, c.freeJWT)
			},
		},
		{
			name:         "AuthDisable2FA",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/disable",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/auth/2fa/disable", map[string]any{"code": "000000"}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				secret, _, _, err := auth.GenerateTOTPSecret(c.freeUser.Email, "MekongTunnel")
				if err != nil {
					t.Fatalf("generate totp secret: %v", err)
				}
				updated, err := testDB.UpdateUser(context.Background(), c.freeUser.ID, map[string]any{
					"totp_secret":  secret,
					"totp_enabled": true,
				})
				if err != nil {
					t.Fatalf("update user for totp disable: %v", err)
				}
				c.freeUser = *updated
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatalf("generate totp code: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/auth/2fa/disable", map[string]any{"code": code}, c.freeJWT)
			},
		},
		{
			name:         "AuthVerify2FA",
			method:       http.MethodPost,
			path:         "/api/auth/2fa/verify",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, c *caseContext) *http.Response {
				secret, _, _, err := auth.GenerateTOTPSecret(c.freeUser.Email, "MekongTunnel")
				if err != nil {
					t.Fatalf("generate totp secret: %v", err)
				}
				updated, err := testDB.UpdateUser(context.Background(), c.freeUser.ID, map[string]any{
					"totp_secret":  secret,
					"totp_enabled": true,
				})
				if err != nil {
					t.Fatalf("update user for 2fa verify: %v", err)
				}
				c.freeUser = *updated
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatalf("generate totp code: %v", err)
				}
				tempToken, err := auth.GenerateTemp2FAToken(c.freeUser.ID, c.freeUser.Email, testJWTSecret)
				if err != nil {
					t.Fatalf("generate temp token: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/auth/2fa/verify", map[string]any{
					"temp_token": tempToken,
					"code":       code,
				}, "")
			},
		},
		{
			name:         "TokensList",
			method:       http.MethodGet,
			path:         "/api/tokens",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/tokens", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/tokens", nil, c.freeJWT)
			},
		},
		{
			name:         "TokensCreate",
			method:       http.MethodPost,
			path:         "/api/tokens",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/tokens", map[string]any{"name": "CI Token"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/tokens", map[string]any{"name": "CI Token"}, c.freeJWT)
			},
		},
		{
			name:         "TokensDelete",
			method:       http.MethodDelete,
			path:         "/api/tokens/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				_, record := mustSeedAPIToken(c.freeUser.ID, "delete-token")
				return makeRequest(http.MethodDelete, "/api/tokens/"+record.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				_, record := mustSeedAPIToken(c.freeUser.ID, "delete-token")
				return makeRequest(http.MethodDelete, "/api/tokens/"+record.ID, nil, c.freeJWT)
			},
		},
		{
			name:         "CLIDeviceCreate",
			method:       http.MethodPost,
			path:         "/api/cli/device",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/cli/device", nil, "")
			},
		},
		{
			name:         "CLIDevicePoll",
			method:       http.MethodGet,
			path:         "/api/cli/device",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, _ *caseContext) *http.Response {
				sess, err := testDB.CreateDeviceSession(context.Background())
				if err != nil {
					t.Fatalf("create device session: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/cli/device?session_id="+url.QueryEscape(sess.ID), nil, "")
			},
		},
		{
			name:         "CLIDeviceApprove",
			method:       http.MethodPost,
			path:         "/api/cli/device/approve",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				sess, err := testDB.CreateDeviceSession(context.Background())
				if err != nil {
					t.Fatalf("create device session: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/cli/device/approve?session_id="+url.QueryEscape(sess.ID), nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				sess, err := testDB.CreateDeviceSession(context.Background())
				if err != nil {
					t.Fatalf("create device session: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/cli/device/approve?session_id="+url.QueryEscape(sess.ID), nil, c.freeJWT)
			},
		},
		{
			name:         "CLISubdomainsList",
			method:       http.MethodGet,
			path:         "/api/cli/subdomains",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/cli/subdomains", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/cli/subdomains", nil, c.proAPIToken)
			},
		},
		{
			name:         "CLISubdomainsCreate",
			method:       http.MethodPost,
			path:         "/api/cli/subdomains",
			expected:     http.StatusCreated,
			authRequired: "API token",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/cli/subdomains", map[string]any{"subdomain": "cli-myapp"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/cli/subdomains", map[string]any{"subdomain": "cli-myapp"}, c.proAPIToken)
			},
		},
		{
			name:         "CLISubdomainsDelete",
			method:       http.MethodDelete,
			path:         "/api/cli/subdomains/{id}",
			expected:     http.StatusNoContent,
			authRequired: "API token",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("delete-cli-sub"))
				if err != nil {
					t.Fatalf("create cli subdomain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/cli/subdomains/"+sub.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("delete-cli-sub"))
				if err != nil {
					t.Fatalf("create cli subdomain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/cli/subdomains/"+sub.ID, nil, c.proAPIToken)
			},
		},
		{
			name:         "CLIDomainsList",
			method:       http.MethodGet,
			path:         "/api/cli/domains",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/cli/domains", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/cli/domains", nil, c.proAPIToken)
			},
		},
		{
			name:         "CLIDomainsCreate",
			method:       http.MethodPost,
			path:         "/api/cli/domains",
			expected:     http.StatusCreated,
			authRequired: "API token",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/cli/domains", map[string]any{"domain": "cli.localhost"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/cli/domains", map[string]any{"domain": "cli.localhost"}, c.proAPIToken)
			},
		},
		{
			name:         "CLIDomainsDelete",
			method:       http.MethodDelete,
			path:         "/api/cli/domains/{id}",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("delete-cli"))
				if err != nil {
					t.Fatalf("create cli domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/cli/domains/"+domain.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("delete-cli"))
				if err != nil {
					t.Fatalf("create cli domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/cli/domains/"+domain.ID, nil, c.proAPIToken)
			},
		},
		{
			name:         "CLIDomainsVerify",
			method:       http.MethodPost,
			path:         "/api/cli/domains/{id}/verify",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("verify-cli"))
				if err != nil {
					t.Fatalf("create cli domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/cli/domains/"+domain.ID+"/verify", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("verify-cli"))
				if err != nil {
					t.Fatalf("create cli domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/cli/domains/"+domain.ID+"/verify", nil, c.proAPIToken)
			},
		},
		{
			name:         "CLIDomainsTarget",
			method:       http.MethodPatch,
			path:         "/api/cli/domains/{id}/target",
			expected:     http.StatusOK,
			authRequired: "API token",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				_, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target)
				if err != nil {
					t.Fatalf("create cli target subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("target-cli"))
				if err != nil {
					t.Fatalf("create cli target domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/cli/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				_, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target)
				if err != nil {
					t.Fatalf("create cli target subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("target-cli"))
				if err != nil {
					t.Fatalf("create cli target domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/cli/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, c.proAPIToken)
			},
		},
		{
			name:         "TunnelsList",
			method:       http.MethodGet,
			path:         "/api/tunnels",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/tunnels", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/tunnels", nil, c.freeJWT)
			},
		},
		{
			name:         "TunnelsStats",
			method:       http.MethodGet,
			path:         "/api/tunnels/stats",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/tunnels/stats", nil, "")
			},
		},
		{
			name:         "TunnelsReport",
			method:       http.MethodPost,
			path:         "/api/tunnels",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/tunnels", map[string]any{
					"id":         "tunnel-sync-1",
					"user_id":    c.freeUser.ID,
					"subdomain":  "sync-sub",
					"local_port": 3000,
					"remote_ip":  "127.0.0.1",
					"status":     "active",
					"started_at": time.Now().UTC().Format(time.RFC3339),
				}, "")
			},
		},
		{
			name:         "TunnelsPatch",
			method:       http.MethodPatch,
			path:         "/api/tunnels/{id}",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, c *caseContext) *http.Response {
				mustSeedTunnel(t, c.freeUser.ID, "patch-tunnel", "patchsub")
				return makeRequest(http.MethodPatch, "/api/tunnels/patch-tunnel", map[string]any{
					"status":         "stopped",
					"total_requests": 3,
					"total_bytes":    512,
				}, "")
			},
		},
		{
			name:         "UserUpdate",
			method:       http.MethodPut,
			path:         "/api/user",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/user", map[string]any{"name": "Updated Name"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/user", map[string]any{"name": "Updated Name"}, c.freeJWT)
			},
		},
		{
			name:         "UserPassword",
			method:       http.MethodPut,
			path:         "/api/user/password",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/user/password", map[string]any{
					"current_password": testPassword,
					"new_password":     "BrandNewPass1",
				}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/user/password", map[string]any{
					"current_password": testPassword,
					"new_password":     "BrandNewPass1",
				}, c.freeJWT)
			},
		},
		{
			name:         "UserDelete",
			method:       http.MethodDelete,
			path:         "/api/user",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/user", map[string]any{"password": testPassword}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/user", map[string]any{"password": testPassword}, c.freeJWT)
			},
		},
		{
			name:         "UserVerifyRequestGet",
			method:       http.MethodGet,
			path:         "/api/user/verify-request",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/user/verify-request", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/user/verify-request", nil, c.freeJWT)
			},
		},
		{
			name:         "UserVerifyRequestPost",
			method:       http.MethodPost,
			path:         "/api/user/verify-request",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/user/verify-request", map[string]any{
					"type":         "student",
					"document_url": "http://example.com/doc.pdf",
				}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/user/verify-request", map[string]any{
					"type":         "student",
					"document_url": "http://example.com/doc.pdf",
				}, c.freeJWT)
			},
		},
		{
			name:         "UserPlanPatch",
			method:       http.MethodPatch,
			path:         "/api/user/plan",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/user/plan", map[string]any{"plan": "free"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/user/plan", map[string]any{"plan": "free"}, c.freeJWT)
			},
		},
		{
			name:         "BillingGet",
			method:       http.MethodGet,
			path:         "/api/billing",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/billing", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/billing", nil, c.freeJWT)
			},
		},
		{
			name:         "BillingCheckout",
			method:       http.MethodPost,
			path:         "/api/billing/checkout",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/billing/checkout", map[string]any{"plan": "pro"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/billing/checkout", map[string]any{"plan": "pro"}, c.freeJWT)
			},
		},
		{
			name:         "BillingPortal",
			method:       http.MethodPost,
			path:         "/api/billing/portal",
			expected:     http.StatusOK,
			authRequired: "JWT",
			skipIf: func(_ *caseContext) string {
				if os.Getenv("STRIPE_SECRET_KEY") == "" {
					return "Stripe not configured in test env"
				}
				return "live Stripe customer setup not seeded in integration env"
			},
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/billing/portal", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/billing/portal", nil, c.freeJWT)
			},
		},
		{
			name:         "BillingWebhook",
			method:       http.MethodPost,
			path:         "/api/billing/webhook",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/billing/webhook", map[string]any{"event": "noop"}, "")
			},
		},
		{
			name:         "TeamList",
			method:       http.MethodGet,
			path:         "/api/team",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/team", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/team", nil, c.proJWT)
			},
		},
		{
			name:         "TeamCreate",
			method:       http.MethodPost,
			path:         "/api/team",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/team", map[string]any{"name": "Build Team"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/team", map[string]any{"name": "Build Team"}, c.proJWT)
			},
		},
		{
			name:         "TeamPatch",
			method:       http.MethodPatch,
			path:         "/api/team/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Old Name", "project", c.proUser.Plan)
				return makeRequest(http.MethodPatch, "/api/team/"+team.ID, map[string]any{"name": "New Name"}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Old Name", "project", c.proUser.Plan)
				return makeRequest(http.MethodPatch, "/api/team/"+team.ID, map[string]any{"name": "New Name"}, c.proJWT)
			},
		},
		{
			name:         "TeamDelete",
			method:       http.MethodDelete,
			path:         "/api/team/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Delete Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodDelete, "/api/team/"+team.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Delete Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodDelete, "/api/team/"+team.ID, nil, c.proJWT)
			},
		},
		{
			name:         "TeamMembersList",
			method:       http.MethodGet,
			path:         "/api/team/members",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/team/members", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Members Team", "project", c.proUser.Plan)
				if err := testDB.AddTeamMember(context.Background(), team.ID, c.proUser.ID, "owner"); err != nil {
					t.Fatalf("add team owner: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/team/members?team_id="+url.QueryEscape(team.ID), nil, c.proJWT)
			},
		},
		{
			name:         "TeamInvitationsList",
			method:       http.MethodGet,
			path:         "/api/team/invitations",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/team/invitations", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Invite Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodGet, "/api/team/invitations?team_id="+url.QueryEscape(team.ID), nil, c.proJWT)
			},
		},
		{
			name:         "TeamMemberDelete",
			method:       http.MethodDelete,
			path:         "/api/team/members/{userId}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Member Delete Team", "project", c.proUser.Plan)
				if err := testDB.AddTeamMember(context.Background(), team.ID, c.proUser.ID, "owner"); err != nil {
					t.Fatalf("add owner: %v", err)
				}
				if err := testDB.AddTeamMember(context.Background(), team.ID, c.freeUser.ID, "member"); err != nil {
					t.Fatalf("add member: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/team/members/"+c.freeUser.ID+"?team_id="+url.QueryEscape(team.ID), nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Member Delete Team", "project", c.proUser.Plan)
				if err := testDB.AddTeamMember(context.Background(), team.ID, c.proUser.ID, "owner"); err != nil {
					t.Fatalf("add owner: %v", err)
				}
				if err := testDB.AddTeamMember(context.Background(), team.ID, c.freeUser.ID, "member"); err != nil {
					t.Fatalf("add member: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/team/members/"+c.freeUser.ID+"?team_id="+url.QueryEscape(team.ID), nil, c.proJWT)
			},
		},
		{
			name:         "TeamInvitePost",
			method:       http.MethodPost,
			path:         "/api/team/invite",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Invite Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodPost, "/api/team/invite?team_id="+url.QueryEscape(team.ID), map[string]any{
					"email": c.freeUser.Email,
					"role":  "member",
				}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Invite Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodPost, "/api/team/invite?team_id="+url.QueryEscape(team.ID), map[string]any{
					"email": c.freeUser.Email,
					"role":  "member",
				}, c.proJWT)
			},
		},
		{
			name:         "TeamInviteCode",
			method:       http.MethodPost,
			path:         "/api/team/invite/code",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Code Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodPost, "/api/team/invite/code?team_id="+url.QueryEscape(team.ID), nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Code Team", "project", c.proUser.Plan)
				return makeRequest(http.MethodPost, "/api/team/invite/code?team_id="+url.QueryEscape(team.ID), nil, c.proJWT)
			},
		},
		{
			name:         "TeamInviteAccept",
			method:       http.MethodPost,
			path:         "/api/team/invite/accept",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Accept Team", "project", c.proUser.Plan)
				token, _ := mustSeedInvitation(t, team.ID, c.freeUser.Email, "member")
				return makeRequest(http.MethodPost, "/api/team/invite/accept", map[string]any{"token": token}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Accept Team", "project", c.proUser.Plan)
				token, _ := mustSeedInvitation(t, team.ID, c.freeUser.Email, "member")
				return makeRequest(http.MethodPost, "/api/team/invite/accept", map[string]any{"token": token}, c.freeJWT)
			},
		},
		{
			name:         "TeamInviteDelete",
			method:       http.MethodDelete,
			path:         "/api/team/invite/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Revoke Team", "project", c.proUser.Plan)
				_, inv := mustSeedInvitation(t, team.ID, c.freeUser.Email, "member")
				return makeRequest(http.MethodDelete, "/api/team/invite/"+inv.ID+"?team_id="+url.QueryEscape(team.ID), nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				team := mustSeedTeam(t, c.proUser.ID, "Revoke Team", "project", c.proUser.Plan)
				_, inv := mustSeedInvitation(t, team.ID, c.freeUser.Email, "member")
				return makeRequest(http.MethodDelete, "/api/team/invite/"+inv.ID+"?team_id="+url.QueryEscape(team.ID), nil, c.proJWT)
			},
		},
		{
			name:         "PlansPublic",
			method:       http.MethodGet,
			path:         "/api/plans",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/plans", nil, "")
			},
		},
		{
			name:         "ServerLimitsPublic",
			method:       http.MethodGet,
			path:         "/api/server-limits",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/server-limits", nil, "")
			},
		},
		{
			name:         "PartnersPublic",
			method:       http.MethodGet,
			path:         "/api/partners",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/partners", nil, "")
			},
		},
		{
			name:         "SponsorsPublic",
			method:       http.MethodGet,
			path:         "/api/sponsors",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/sponsors", nil, "")
			},
		},
		{
			name:         "NotificationsList",
			method:       http.MethodGet,
			path:         "/api/notifications",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/notifications", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/notifications", nil, c.freeJWT)
			},
		},
		{
			name:         "NotificationsReadAll",
			method:       http.MethodPatch,
			path:         "/api/notifications/read-all",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/notifications/read-all", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				_, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/notifications/read-all", nil, c.freeJWT)
			},
		},
		{
			name:         "NotificationsReadOne",
			method:       http.MethodPatch,
			path:         "/api/notifications/{id}/read",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				n, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/notifications/"+n.ID+"/read", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				n, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/notifications/"+n.ID+"/read", nil, c.freeJWT)
			},
		},
		{
			name:         "NotificationsDeleteAll",
			method:       http.MethodDelete,
			path:         "/api/notifications",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/notifications", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				_, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/notifications", nil, c.freeJWT)
			},
		},
		{
			name:         "NotificationsDeleteOne",
			method:       http.MethodDelete,
			path:         "/api/notifications/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				n, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/notifications/"+n.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				n, err := testDB.CreateNotification(context.Background(), c.freeUser.ID, "info", "Hello", "Body", "/x")
				if err != nil {
					t.Fatalf("create notification: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/notifications/"+n.ID, nil, c.freeJWT)
			},
		},
		{
			name:         "NotificationsStream",
			method:       http.MethodGet,
			path:         "/api/notifications/stream",
			expected:     http.StatusOK,
			authRequired: "Token query",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/notifications/stream", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				resp, body := mustReadStream(t, "/api/notifications/stream?token="+url.QueryEscape(c.freeJWT))
				if !strings.Contains(body, "event: connected") {
					t.Fatalf("expected connected event in notifications stream, got %q", body)
				}
				return resp
			},
		},
		{
			name:         "SubdomainsList",
			method:       http.MethodGet,
			path:         "/api/subdomains",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/subdomains", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/subdomains", nil, c.proJWT)
			},
		},
		{
			name:         "SubdomainsAnalytics",
			method:       http.MethodGet,
			path:         "/api/subdomains/analytics",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/subdomains/analytics", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/subdomains/analytics", nil, c.proJWT)
			},
		},
		{
			name:         "SubdomainsCreate",
			method:       http.MethodPost,
			path:         "/api/subdomains",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/subdomains", map[string]any{"subdomain": "myapp"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/subdomains", map[string]any{"subdomain": "myapp"}, c.proJWT)
			},
		},
		{
			name:         "SubdomainsDelete",
			method:       http.MethodDelete,
			path:         "/api/subdomains/{id}",
			expected:     http.StatusNoContent,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("delete-sub"))
				if err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/subdomains/"+sub.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("delete-sub"))
				if err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/subdomains/"+sub.ID, nil, c.proJWT)
			},
		},
		{
			name:         "SubdomainsRulePut",
			method:       http.MethodPut,
			path:         "/api/subdomains/{id}/rule",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("rule-sub"))
				if err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				return makeRequest(http.MethodPut, "/api/subdomains/"+sub.ID+"/rule", map[string]any{
					"enabled":         true,
					"rate_limit_rpm":  30,
					"max_connections": 3,
					"force_https":     true,
					"allowed_ips":     []string{"127.0.0.1"},
					"allowed_agents":  []string{"Go-http-client"},
					"custom_headers":  map[string]string{"X-Test": "yes"},
				}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				sub, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, uniqueSubdomain("rule-sub"))
				if err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				return makeRequest(http.MethodPut, "/api/subdomains/"+sub.ID+"/rule", map[string]any{
					"enabled":         true,
					"rate_limit_rpm":  30,
					"max_connections": 3,
					"force_https":     true,
					"allowed_ips":     []string{"127.0.0.1"},
					"allowed_agents":  []string{"Go-http-client"},
					"custom_headers":  map[string]string{"X-Test": "yes"},
				}, c.proJWT)
			},
		},
		{
			name:         "DomainsList",
			method:       http.MethodGet,
			path:         "/api/domains",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/domains", nil, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/domains", nil, c.proJWT)
			},
		},
		{
			name:         "DomainsCreate",
			method:       http.MethodPost,
			path:         "/api/domains",
			expected:     http.StatusCreated,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/domains", map[string]any{"domain": "app.localhost"}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/domains", map[string]any{"domain": "app.localhost"}, c.proJWT)
			},
		},
		{
			name:         "DomainsDelete",
			method:       http.MethodDelete,
			path:         "/api/domains/{id}",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("delete"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/domains/"+domain.ID, nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("delete"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/domains/"+domain.ID, nil, c.proJWT)
			},
		},
		{
			name:         "DomainsVerify",
			method:       http.MethodPost,
			path:         "/api/domains/{id}/verify",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("verify"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/domains/"+domain.ID+"/verify", nil, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("verify"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/domains/"+domain.ID+"/verify", nil, c.proJWT)
			},
		},
		{
			name:         "DomainsTarget",
			method:       http.MethodPatch,
			path:         "/api/domains/{id}/target",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				_, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target)
				if err != nil {
					t.Fatalf("create reserved subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("target"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, "")
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				_, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target)
				if err != nil {
					t.Fatalf("create reserved subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("target"))
				if err != nil {
					t.Fatalf("create custom domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, c.proJWT)
			},
		},
		{
			name:         "NewsletterSubscribe",
			method:       http.MethodPost,
			path:         "/api/newsletter/subscribe",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/newsletter/subscribe", map[string]any{"email": fmt.Sprintf("news-%d@example.com", testUserSeq.Add(1))}, "")
			},
		},
		{
			name:         "NewsletterUnsubscribe",
			method:       http.MethodGet,
			path:         "/api/newsletter/unsubscribe",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, c *caseContext) *http.Response {
				token := mustNewsletterToken(c.freeUser.ID)
				return makeRequest(http.MethodGet, "/api/newsletter/unsubscribe?token="+url.QueryEscape(token), nil, "")
			},
		},
		{
			name:         "NewsletterResubscribe",
			method:       http.MethodPost,
			path:         "/api/newsletter/resubscribe",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, c *caseContext) *http.Response {
				token := mustNewsletterToken(c.freeUser.ID)
				if err := testDB.SetNewsletterSubscribed(context.Background(), c.freeUser.ID, false); err != nil {
					t.Fatalf("disable newsletter first: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/newsletter/resubscribe?token="+url.QueryEscape(token), nil, "")
			},
		},
		{
			name:         "NewsletterToggle",
			method:       http.MethodPost,
			path:         "/api/newsletter/toggle",
			expected:     http.StatusOK,
			authRequired: "JWT",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/newsletter/toggle", map[string]any{"subscribed": true}, "")
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/newsletter/toggle", map[string]any{"subscribed": true}, c.freeJWT)
			},
		},
		{
			name:         "DonationsSubmit",
			method:       http.MethodPost,
			path:         "/api/donations/submit",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/donations/submit", map[string]any{
					"name":           "Donor",
					"email":          "donor@example.com",
					"amount":         "5.00",
					"currency":       "USD",
					"payment_method": "bakong",
				}, "")
			},
		},
		{
			name:         "DonationsList",
			method:       http.MethodGet,
			path:         "/api/donations",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, _ *caseContext) *http.Response {
				d, err := testDB.CreateDonation(context.Background(), &models.DonationSubmission{
					Name:          "Public Donor",
					Amount:        "10.00",
					Currency:      "USD",
					PaymentMethod: "card",
				})
				if err != nil {
					t.Fatalf("create donation: %v", err)
				}
				if _, err := testDB.UpdateDonation(context.Background(), d.ID, "approved", true); err != nil {
					t.Fatalf("approve donation: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/donations", nil, "")
			},
		},
		{
			name:         "UploadPost",
			method:       http.MethodPost,
			path:         "/api/upload",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeMultipartRequest(http.MethodPost, "/api/upload", "file", "avatar.png", "image/png", []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, "")
			},
		},
		{
			name:         "UploadGet",
			method:       http.MethodGet,
			path:         "/api/uploads/{filename}",
			expected:     http.StatusOK,
			authRequired: "No",
			run: func(t *testing.T, _ *caseContext) *http.Response {
				filename := "serve-test.txt"
				if err := os.WriteFile(filepath.Join(testUploadDir, filename), []byte("hello"), 0644); err != nil {
					t.Fatalf("write upload file: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/uploads/"+filename, nil, "")
			},
		},
	}

	cases = append(cases, buildAdminCases()...)
	return cases
}

func buildAdminCases() []endpointCase {
	return []endpointCase{
		{
			name:         "AdminStats",
			method:       http.MethodGet,
			path:         "/api/admin/stats",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/stats", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/stats", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/stats", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminUsersList",
			method:       http.MethodGet,
			path:         "/api/admin/users",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminUserGet",
			method:       http.MethodGet,
			path:         "/api/admin/users/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users/"+c.freeUser.ID, nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users/"+c.freeUser.ID, nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/users/"+c.freeUser.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminUserPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/users/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/admin/users/"+c.freeUser.ID, map[string]any{"plan": "student"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/admin/users/"+c.freeUser.ID, map[string]any{"plan": "student"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/admin/users/"+c.freeUser.ID, map[string]any{"plan": "student"}, c.adminJWT)
			},
		},
		{
			name:         "AdminUserResendVerify",
			method:       http.MethodPost,
			path:         "/api/admin/users/{id}/resend-verify",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				user := seedUserWithOptions("unverified-admin", map[string]any{"email_verified": false})
				return makeRequest(http.MethodPost, "/api/admin/users/"+user.ID+"/resend-verify", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				user := seedUserWithOptions("unverified-admin", map[string]any{"email_verified": false})
				return makeRequest(http.MethodPost, "/api/admin/users/"+user.ID+"/resend-verify", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				user := seedUserWithOptions("unverified-admin", map[string]any{"email_verified": false})
				return makeRequest(http.MethodPost, "/api/admin/users/"+user.ID+"/resend-verify", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminUserDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/users/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/admin/users/"+c.freeUser.ID, nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/admin/users/"+c.freeUser.ID, nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodDelete, "/api/admin/users/"+c.freeUser.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminTunnelsList",
			method:       http.MethodGet,
			path:         "/api/admin/tunnels",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/tunnels", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/tunnels", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				mustSeedTunnel(t, c.freeUser.ID, "admin-list-tunnel", "listsub")
				return makeRequest(http.MethodGet, "/api/admin/tunnels", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminTunnelDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/tunnels/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				mustSeedTunnel(t, seedUser("free").ID, "kill-tunnel", "killsub")
				return makeRequest(http.MethodDelete, "/api/admin/tunnels/kill-tunnel", nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				mustSeedTunnel(t, c.freeUser.ID, "kill-tunnel", "killsub")
				return makeRequest(http.MethodDelete, "/api/admin/tunnels/kill-tunnel", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				mustSeedTunnel(t, c.freeUser.ID, "kill-tunnel", "killsub")
				return makeRequest(http.MethodDelete, "/api/admin/tunnels/kill-tunnel", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDomainsList",
			method:       http.MethodGet,
			path:         "/api/admin/domains",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/domains", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/domains", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if _, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, "admin-list.localhost"); err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/domains", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDomainGet",
			method:       http.MethodGet,
			path:         "/api/admin/domains/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-get"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/domains/"+domain.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-get"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/domains/"+domain.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-get"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/domains/"+domain.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDomainVerify",
			method:       http.MethodPost,
			path:         "/api/admin/domains/{id}/verify",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-verify"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/domains/"+domain.ID+"/verify", nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-verify"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/domains/"+domain.ID+"/verify", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-verify"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/domains/"+domain.ID+"/verify", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDomainTarget",
			method:       http.MethodPatch,
			path:         "/api/admin/domains/{id}/target",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				if _, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target); err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-target"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				if _, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target); err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-target"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				target := uniqueSubdomain("myapp")
				if _, err := testDB.CreateReservedSubdomain(context.Background(), c.proUser.ID, target); err != nil {
					t.Fatalf("create subdomain: %v", err)
				}
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-target"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/domains/"+domain.ID+"/target", map[string]any{"target_subdomain": target}, c.adminJWT)
			},
		},
		{
			name:         "AdminDomainDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/domains/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-delete"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/domains/"+domain.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-delete"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/domains/"+domain.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				domain, err := testDB.CreateCustomDomain(context.Background(), c.proUser.ID, uniqueDomain("admin-delete"))
				if err != nil {
					t.Fatalf("create domain: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/domains/"+domain.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminPlansGet",
			method:       http.MethodGet,
			path:         "/api/admin/plans",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/plans", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/plans", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/plans", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminPlansPut",
			method:       http.MethodPut,
			path:         "/api/admin/plans",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/admin/plans", mustPlanConfigPayload(), "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/admin/plans", mustPlanConfigPayload(), c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPut, "/api/admin/plans", mustPlanConfigPayload(), c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationsList",
			method:       http.MethodGet,
			path:         "/api/admin/organizations",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/organizations", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/organizations", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/organizations", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationsPost",
			method:       http.MethodPost,
			path:         "/api/admin/organizations",
			expected:     http.StatusCreated,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/organizations", map[string]any{
					"name":        "Acme Org",
					"plan":        "org",
					"owner_email": c.proUser.Email,
				}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/organizations", map[string]any{
					"name":        "Acme Org",
					"plan":        "org",
					"owner_email": c.proUser.Email,
				}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/organizations", map[string]any{
					"name":        "Acme Org",
					"plan":        "org",
					"owner_email": c.proUser.Email,
				}, c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationGet",
			method:       http.MethodGet,
			path:         "/api/admin/organizations/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", "")
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationMembers",
			method:       http.MethodGet,
			path:         "/api/admin/organizations/{id}/members",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID+"/members", nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID+"/members", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodGet, "/api/admin/organizations/"+org.ID+"/members", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/organizations/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", "")
				return makeRequest(http.MethodPatch, "/api/admin/organizations/"+org.ID, map[string]any{"status": "active"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodPatch, "/api/admin/organizations/"+org.ID, map[string]any{"status": "active"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodPatch, "/api/admin/organizations/"+org.ID, map[string]any{"status": "active"}, c.adminJWT)
			},
		},
		{
			name:         "AdminOrganizationDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/organizations/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", "")
				return makeRequest(http.MethodDelete, "/api/admin/organizations/"+org.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodDelete, "/api/admin/organizations/"+org.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				org := mustSeedOrganization(t, "Acme Org", "acme.dev", "org", c.proUser.ID)
				return makeRequest(http.MethodDelete, "/api/admin/organizations/"+org.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminAbuseEventsList",
			method:       http.MethodGet,
			path:         "/api/admin/abuse/events",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/events", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/events", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/events", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminBlockedIPsList",
			method:       http.MethodGet,
			path:         "/api/admin/abuse/blocked",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/blocked", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/blocked", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/abuse/blocked", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminBlockedIPsPost",
			method:       http.MethodPost,
			path:         "/api/admin/abuse/blocked",
			expected:     http.StatusCreated,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/abuse/blocked", map[string]any{"ip": "203.0.113.10", "reason": "test"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/abuse/blocked", map[string]any{"ip": "203.0.113.10", "reason": "test"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/abuse/blocked", map[string]any{"ip": "203.0.113.10", "reason": "test"}, c.adminJWT)
			},
		},
		{
			name:         "AdminBlockedIPsDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/abuse/blocked/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				blocked, err := testDB.CreateBlockedIP(context.Background(), "203.0.113.11", "test", false, 0, 0, nil)
				if err != nil {
					t.Fatalf("create blocked ip: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/abuse/blocked/"+blocked.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				blocked, err := testDB.CreateBlockedIP(context.Background(), "203.0.113.11", "test", false, 0, 0, nil)
				if err != nil {
					t.Fatalf("create blocked ip: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/abuse/blocked/"+blocked.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				blocked, err := testDB.CreateBlockedIP(context.Background(), "203.0.113.11", "test", false, 0, 0, nil)
				if err != nil {
					t.Fatalf("create blocked ip: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/abuse/blocked/"+blocked.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestsList",
			method:       http.MethodGet,
			path:         "/api/admin/verify-requests",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/verify-requests", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/verify-requests", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if _, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf"); err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/verify-requests", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestGet",
			method:       http.MethodGet,
			path:         "/api/admin/verify-requests/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/verify-requests/"+vr.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/verify-requests/"+vr.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/verify-requests/"+vr.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/verify-requests/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/verify-requests/"+vr.ID, map[string]any{"status": "reviewing"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/verify-requests/"+vr.ID, map[string]any{"status": "reviewing"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPatch, "/api/admin/verify-requests/"+vr.ID, map[string]any{"status": "reviewing"}, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/verify-requests/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/verify-requests/"+vr.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/verify-requests/"+vr.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodDelete, "/api/admin/verify-requests/"+vr.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestNotify",
			method:       http.MethodPost,
			path:         "/api/admin/verify-requests/{id}/notify",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/notify", map[string]any{"message": "please resubmit"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/notify", map[string]any{"message": "please resubmit"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/notify", map[string]any{"message": "please resubmit"}, c.adminJWT)
			},
		},
		{
			name:         "AdminVerifyRequestReset",
			method:       http.MethodPost,
			path:         "/api/admin/verify-requests/{id}/reset",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/reset", map[string]any{"note": "send a clearer doc"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/reset", map[string]any{"note": "send a clearer doc"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				vr, err := testDB.UpsertVerifyRequest(context.Background(), c.freeUser.ID, "student", "", "", "doc.pdf")
				if err != nil {
					t.Fatalf("seed verify request: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/verify-requests/"+vr.ID+"/reset", map[string]any{"note": "send a clearer doc"}, c.adminJWT)
			},
		},
		{
			name:         "AdminRevenue",
			method:       http.MethodGet,
			path:         "/api/admin/revenue",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/revenue", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/revenue", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/revenue", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminBillingSubscribers",
			method:       http.MethodGet,
			path:         "/api/admin/billing/subscribers",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/billing/subscribers", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/billing/subscribers", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/billing/subscribers", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminBillingRefund",
			method:       http.MethodPost,
			path:         "/api/admin/billing/refund",
			expected:     http.StatusOK,
			authRequired: "Admin",
			skipIf: func(_ *caseContext) string {
				return "Stripe not configured in test env"
			},
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/refund", map[string]any{"payment_intent_id": "pi_test"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/refund", map[string]any{"payment_intent_id": "pi_test"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/refund", map[string]any{"payment_intent_id": "pi_test"}, c.adminJWT)
			},
		},
		{
			name:         "AdminBillingReceipt",
			method:       http.MethodPost,
			path:         "/api/admin/billing/receipt",
			expected:     http.StatusOK,
			authRequired: "Admin",
			skipIf: func(_ *caseContext) string {
				return "Stripe not configured in test env"
			},
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/receipt", map[string]any{"invoice_id": "in_test"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/receipt", map[string]any{"invoice_id": "in_test"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/billing/receipt", map[string]any{"invoice_id": "in_test"}, c.adminJWT)
			},
		},
		{
			name:         "AdminSystemGet",
			method:       http.MethodGet,
			path:         "/api/admin/system",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/system", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/system", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/system", nil, c.adminJWT)
			},
		},
		{
			name:               "AdminSystemStream",
			method:             http.MethodGet,
			path:               "/api/admin/system/stream",
			expected:           http.StatusOK,
			authRequired:       "Admin token query",
			unauthorizedStatus: http.StatusForbidden,
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/system/stream", nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				resp, body := mustReadStream(t, "/api/admin/system/stream?token="+url.QueryEscape(c.freeJWT))
				if resp.StatusCode != http.StatusForbidden && !strings.Contains(body, "forbidden") {
					t.Fatalf("expected forbidden admin system stream, got status=%d body=%q", resp.StatusCode, body)
				}
				return resp
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				resp, body := mustReadStream(t, "/api/admin/system/stream?token="+url.QueryEscape(c.adminJWT))
				if !strings.Contains(body, "{") {
					t.Fatalf("expected json payload in system stream, got %q", body)
				}
				return resp
			},
		},
		{
			name:         "AdminServerLimitsGet",
			method:       http.MethodGet,
			path:         "/api/admin/server-limits",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/server-limits", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/server-limits", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/server-limits", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminServerLimitsPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/server-limits",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/admin/server-limits", baselineServerCfg, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPatch, "/api/admin/server-limits", baselineServerCfg, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				cfg := *baselineServerCfg
				cfg.AnnouncementEnabled = true
				cfg.AnnouncementText = "Integration banner"
				return makeRequest(http.MethodPatch, "/api/admin/server-limits", cfg, c.adminJWT)
			},
		},
		{
			name:         "AdminPartnersList",
			method:       http.MethodGet,
			path:         "/api/admin/partners",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/partners", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/partners", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/partners", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminPartnersPost",
			method:       http.MethodPost,
			path:         "/api/admin/partners",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/partners", map[string]any{"name": "Partner A"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/partners", map[string]any{"name": "Partner A"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/partners", map[string]any{"name": "Partner A"}, c.adminJWT)
			},
		},
		{
			name:         "AdminPartnersPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/partners/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodPatch, "/api/admin/partners/"+p.ID, map[string]any{"name": "Partner B"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodPatch, "/api/admin/partners/"+p.ID, map[string]any{"name": "Partner B"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodPatch, "/api/admin/partners/"+p.ID, map[string]any{"name": "Partner B"}, c.adminJWT)
			},
		},
		{
			name:         "AdminPartnersDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/partners/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodDelete, "/api/admin/partners/"+p.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodDelete, "/api/admin/partners/"+p.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				p := mustSeedPartner(t, "Partner A")
				return makeRequest(http.MethodDelete, "/api/admin/partners/"+p.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminSponsorsList",
			method:       http.MethodGet,
			path:         "/api/admin/sponsors",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/sponsors", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/sponsors", nil, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/sponsors", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminSponsorsPost",
			method:       http.MethodPost,
			path:         "/api/admin/sponsors",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/sponsors", map[string]any{"title": "Sponsor A"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/sponsors", map[string]any{"title": "Sponsor A"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/sponsors", map[string]any{"title": "Sponsor A"}, c.adminJWT)
			},
		},
		{
			name:         "AdminSponsorsPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/sponsors/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodPatch, "/api/admin/sponsors/"+s.ID, map[string]any{"title": "Sponsor B"}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodPatch, "/api/admin/sponsors/"+s.ID, map[string]any{"title": "Sponsor B"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodPatch, "/api/admin/sponsors/"+s.ID, map[string]any{"title": "Sponsor B"}, c.adminJWT)
			},
		},
		{
			name:         "AdminSponsorsDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/sponsors/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodDelete, "/api/admin/sponsors/"+s.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodDelete, "/api/admin/sponsors/"+s.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				s := mustSeedSponsor(t, "Sponsor A")
				return makeRequest(http.MethodDelete, "/api/admin/sponsors/"+s.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminNewsletterPreview",
			method:       http.MethodPost,
			path:         "/api/admin/newsletter/preview",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/newsletter/preview", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/newsletter/preview", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/newsletter/preview", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, c.adminJWT)
			},
		},
		{
			name:         "AdminNewsletterSend",
			method:       http.MethodPost,
			path:         "/api/admin/newsletter/send",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/newsletter/send", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/newsletter/send", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if err := testDB.SetNewsletterSubscribed(context.Background(), c.freeUser.ID, true); err != nil {
					t.Fatalf("subscribe user to newsletter: %v", err)
				}
				return makeRequest(http.MethodPost, "/api/admin/newsletter/send", map[string]any{"subject": "Hello", "body_html": "<p>Hi</p>"}, c.adminJWT)
			},
		},
		{
			name:         "AdminNewsletterCampaigns",
			method:       http.MethodGet,
			path:         "/api/admin/newsletter/campaigns",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/newsletter/campaigns", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/newsletter/campaigns", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if err := testDB.SaveNewsletterCampaign(context.Background(), "Campaign", "<p>x</p>", c.adminUser.ID, 1); err != nil {
					t.Fatalf("seed newsletter campaign: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/newsletter/campaigns", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminNewsletterSubscribers",
			method:       http.MethodGet,
			path:         "/api/admin/newsletter/subscribers",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/newsletter/subscribers", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/newsletter/subscribers", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if err := testDB.SetNewsletterSubscribed(context.Background(), c.freeUser.ID, true); err != nil {
					t.Fatalf("subscribe user to newsletter: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/newsletter/subscribers", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDonationsList",
			method:       http.MethodGet,
			path:         "/api/admin/donations",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, _ *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/donations", nil, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodGet, "/api/admin/donations", nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				if _, err := testDB.CreateDonation(context.Background(), &models.DonationSubmission{Name: "Admin Donor", Amount: "20", Currency: "USD", PaymentMethod: "card"}); err != nil {
					t.Fatalf("seed donation: %v", err)
				}
				return makeRequest(http.MethodGet, "/api/admin/donations", nil, c.adminJWT)
			},
		},
		{
			name:         "AdminDonationsPatch",
			method:       http.MethodPatch,
			path:         "/api/admin/donations/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				d := mustSeedDonation(t, "Patch Donor")
				return makeRequest(http.MethodPatch, "/api/admin/donations/"+d.ID, map[string]any{"status": "approved", "show_on_home": true}, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				d := mustSeedDonation(t, "Patch Donor")
				return makeRequest(http.MethodPatch, "/api/admin/donations/"+d.ID, map[string]any{"status": "approved", "show_on_home": true}, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				d := mustSeedDonation(t, "Patch Donor")
				return makeRequest(http.MethodPatch, "/api/admin/donations/"+d.ID, map[string]any{"status": "approved", "show_on_home": true}, c.adminJWT)
			},
		},
		{
			name:         "AdminDonationsDelete",
			method:       http.MethodDelete,
			path:         "/api/admin/donations/{id}",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(t *testing.T, _ *caseContext) *http.Response {
				d := mustSeedDonation(t, "Delete Donor")
				return makeRequest(http.MethodDelete, "/api/admin/donations/"+d.ID, nil, "")
			},
			runForbidden: func(t *testing.T, c *caseContext) *http.Response {
				d := mustSeedDonation(t, "Delete Donor")
				return makeRequest(http.MethodDelete, "/api/admin/donations/"+d.ID, nil, c.freeJWT)
			},
			run: func(t *testing.T, c *caseContext) *http.Response {
				d := mustSeedDonation(t, "Delete Donor")
				return makeRequest(http.MethodDelete, "/api/admin/donations/"+d.ID, nil, c.adminJWT)
			},
		},
		{
			name:         "AdminUserTrialPost",
			method:       http.MethodPost,
			path:         "/api/admin/users/{id}/trial",
			expected:     http.StatusOK,
			authRequired: "Admin",
			runUnauthorized: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/users/"+c.freeUser.ID+"/trial", map[string]any{"days": 14}, "")
			},
			runForbidden: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/users/"+c.freeUser.ID+"/trial", map[string]any{"days": 14}, c.freeJWT)
			},
			run: func(_ *testing.T, c *caseContext) *http.Response {
				return makeRequest(http.MethodPost, "/api/admin/users/"+c.freeUser.ID+"/trial", map[string]any{"days": 14}, c.adminJWT)
			},
		},
	}
}

func newCaseContext() *caseContext {
	if err := cleanAndRestoreDB(); err != nil {
		panic(err)
	}

	freeUser := seedUser("free")
	proUser := seedUserWithOptions("pro", map[string]any{
		"plan":              "pro",
		"subscription_plan": "pro",
	})
	adminUser := seedUserWithOptions("admin", map[string]any{
		"plan":              "pro",
		"subscription_plan": "pro",
		"is_admin":          true,
	})

	freeJWT, _ := auth.GenerateAccessToken(&freeUser, testJWTSecret)
	proJWT, _ := auth.GenerateAccessToken(&proUser, testJWTSecret)
	adminJWT, _ := auth.GenerateAccessToken(&adminUser, testJWTSecret)

	freeAPIToken, _ := mustSeedAPIToken(freeUser.ID, "free-cli")
	proAPIToken, _ := mustSeedAPIToken(proUser.ID, "pro-cli")
	adminAPIToken, _ := mustSeedAPIToken(adminUser.ID, "admin-cli")

	return &caseContext{
		freeUser:      freeUser,
		proUser:       proUser,
		adminUser:     adminUser,
		freeJWT:       freeJWT,
		proJWT:        proJWT,
		adminJWT:      adminJWT,
		freeAPIToken:  freeAPIToken,
		proAPIToken:   proAPIToken,
		adminAPIToken: adminAPIToken,
	}
}

func makeRequest(method, path string, body any, token string) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, testBaseURL+path, bodyReader)
	if err != nil {
		panic(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doRequest(req)
}

func makeRequestWithCookies(method, path string, body any, token string, cookies []*http.Cookie) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, testBaseURL+path, bodyReader)
	if err != nil {
		panic(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return doRequest(req)
}

func makeMultipartRequest(method, path, fieldName, filename, contentType string, data []byte, token string) *http.Response {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		panic(err)
	}
	if _, err := part.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}

	req, err := http.NewRequest(method, testBaseURL+path, &buf)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if contentType != "" {
		req.Header.Set("X-Upload-Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doRequest(req)
}

func doRequest(req *http.Request) *http.Response {
	started := time.Now()
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		panic(err)
	}
	durationByResp.Store(resp, time.Since(started))
	return resp
}

func mustLogin(email, password string) string {
	resp := makeRequest(http.MethodPost, "/api/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, "")
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(resp))
		panic(fmt.Sprintf("mustLogin failed: status=%d body=%s", resp.StatusCode, body))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	decodeResponseData(resp, &payload)
	return payload.AccessToken
}

func seedUser(role string) models.User {
	return seedUserWithOptions(role, nil)
}

func seedUserWithOptions(role string, fields map[string]any) models.User {
	ctx := context.Background()
	n := testUserSeq.Add(1)
	email := fmt.Sprintf("%s-%d@example.com", role, n)
	name := strings.ToUpper(role[:1]) + role[1:] + " User"

	user, err := testDB.CreateUser(ctx, email, name, testPasswordHash)
	if err != nil {
		panic(err)
	}

	update := map[string]any{
		"email_verified": true,
	}
	for k, v := range fields {
		update[k] = v
	}
	user, err = testDB.UpdateUser(ctx, user.ID, update)
	if err != nil {
		panic(err)
	}
	return *user
}

func cleanDB() {
	if err := cleanAndRestoreDB(); err != nil {
		panic(err)
	}
}

func cleanAndRestoreDB() error {
	ctx := context.Background()
	rows, err := testDB.Pool.Query(ctx, `
		SELECT tablename
		FROM pg_tables
		WHERE schemaname = 'public' AND tablename <> 'schema_migrations'
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables = append(tables, fmt.Sprintf("public.%q", name))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Strings(tables)
	if len(tables) > 0 {
		if _, err := testDB.Pool.Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE"); err != nil {
			return err
		}
	}

	if err := testDB.EnsureServerConfig(ctx); err != nil {
		return err
	}
	if baselineServerCfg != nil {
		if _, err := testDB.UpdateServerConfig(ctx, *baselineServerCfg); err != nil {
			return err
		}
	}
	for _, cfg := range baselinePlanConfigs {
		var data map[string]any
		if err := json.Unmarshal(cfg.Config, &data); err != nil {
			return err
		}
		if err := testDB.UpsertPlanConfig(ctx, cfg.PlanID, data, ""); err != nil {
			return err
		}
	}
	return nil
}

func assertStatus(t *testing.T, resp *http.Response, expected int, label string) {
	t.Helper()
	defer closeResponse(resp)

	dur := responseDuration(resp)
	if resp.StatusCode == expected {
		recordPass(label, resp.StatusCode, dur)
		return
	}

	body := strings.TrimSpace(string(mustReadBody(resp)))
	msg := body
	var env apiEnvelope
	if json.Unmarshal([]byte(body), &env) == nil && env.Error != "" {
		msg = env.Error
	}
	recordFail(label, resp.StatusCode, expected, msg, dur)
	t.Errorf("%s expected %d, got %d", label, expected, resp.StatusCode)
}

func labelFor(method, path string) string {
	return fmt.Sprintf("%-6s %s", method, path)
}

func recordPass(label string, status int, dur time.Duration) {
	resultMu.Lock()
	results.passed++
	resultMu.Unlock()
	fmt.Printf("%s[PASS]%s %-44s %3d  %s\n", "\033[32m", "\033[0m", label, status, shortDuration(dur))
}

func recordFail(label string, status, expected int, detail string, dur time.Duration) {
	resultMu.Lock()
	results.failed++
	resultMu.Unlock()
	if detail == "" {
		detail = "unexpected status"
	}
	fmt.Printf("%s[FAIL]%s %-44s %3d  expected %d  → %s (%s)\n", "\033[31m", "\033[0m", label, status, expected, detail, shortDuration(dur))
}

func recordSkip(label, reason string) {
	resultMu.Lock()
	results.skipped++
	resultMu.Unlock()
	fmt.Printf("%s[SKIP]%s %-44s      → %s\n", "\033[33m", "\033[0m", label, reason)
}

func printSummary(dur time.Duration) {
	resultMu.Lock()
	defer resultMu.Unlock()
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf(" Results:  %d passed  |  %d failed  |  %d skipped\n", results.passed, results.failed, results.skipped)
	fmt.Printf(" Duration: %s\n", dur.Round(10*time.Millisecond))
	fmt.Println("─────────────────────────────────────────")
}

func resetResults() {
	resultMu.Lock()
	defer resultMu.Unlock()
	results = suiteResults{}
}

func responseDuration(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	if v, ok := durationByResp.Load(resp); ok {
		if d, ok := v.(time.Duration); ok {
			return d
		}
	}
	return 0
}

func shortDuration(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}
	if d < time.Millisecond {
		return "1ms"
	}
	return d.Round(time.Millisecond).String()
}

func closeResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func mustReadBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

func decodeResponseData(resp *http.Response, target any) {
	body := mustReadBody(resp)
	var env apiEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		panic(err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return
	}
	if err := json.Unmarshal(env.Data, target); err != nil {
		panic(err)
	}
}

func mustRefreshCookie(userID string) *http.Cookie {
	raw, err := auth.GenerateSecureToken()
	if err != nil {
		panic(err)
	}
	if err := testDB.CreateRefreshToken(context.Background(), userID, auth.HashToken(raw), time.Now().Add(24*time.Hour)); err != nil {
		panic(err)
	}
	return &http.Cookie{
		Name:  "mekong_refresh",
		Value: raw,
		Path:  "/api/auth/refresh",
	}
}

func mustPasswordResetToken(userID string) string {
	raw, err := auth.GenerateSecureToken()
	if err != nil {
		panic(err)
	}
	if err := testDB.CreatePasswordResetToken(context.Background(), userID, auth.HashToken(raw), time.Now().Add(time.Hour)); err != nil {
		panic(err)
	}
	return raw
}

func mustEmailVerifyToken(userID string) string {
	raw, err := auth.GenerateSecureToken()
	if err != nil {
		panic(err)
	}
	if err := testDB.CreateEmailVerifyToken(context.Background(), userID, auth.HashToken(raw), time.Now().Add(time.Hour)); err != nil {
		panic(err)
	}
	return raw
}

func mustSeedAPIToken(userID, name string) (string, *models.ApiToken) {
	fullToken, prefix, hash, err := auth.GenerateAPIToken()
	if err != nil {
		panic(err)
	}
	record, err := testDB.CreateAPIToken(context.Background(), userID, name, hash, prefix)
	if err != nil {
		panic(err)
	}
	return fullToken, record
}

func mustSeedTunnel(t *testing.T, userID, id, subdomain string) {
	t.Helper()
	uid := userID
	if err := testDB.UpsertTunnel(context.Background(), &models.Tunnel{
		ID:        id,
		UserID:    &uid,
		Subdomain: subdomain,
		LocalPort: 3000,
		RemoteIP:  "127.0.0.1",
		Status:    "active",
		StartedAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}
}

func mustSeedTeam(t *testing.T, ownerID, name, teamType, plan string) *models.Team {
	t.Helper()
	team, err := testDB.CreateTeam(context.Background(), name, teamType, plan, ownerID)
	if err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := testDB.AddTeamMember(context.Background(), team.ID, ownerID, "owner"); err != nil {
		t.Fatalf("seed team owner: %v", err)
	}
	return team
}

func mustSeedInvitation(t *testing.T, teamID, email, role string) (string, *models.Invitation) {
	t.Helper()
	token, err := auth.GenerateSecureToken()
	if err != nil {
		t.Fatalf("generate invitation token: %v", err)
	}
	inv, err := testDB.CreateInvitation(context.Background(), teamID, email, role, auth.HashToken(token), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	return token, inv
}

func mustSeedOrganization(t *testing.T, name, domain, plan, ownerID string) *models.Organization {
	t.Helper()
	org, err := testDB.CreateOrganization(context.Background(), name, domain, plan, ownerID, "school", 100, nil)
	if err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	return org
}

func TestReportTunnelStopsOlderActiveDuplicateAndListDedupes(t *testing.T) {
	cleanDB()

	user := seedUser("free")
	jwtToken, err := auth.GenerateAccessToken(&user, testJWTSecret)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	uid := user.ID
	if err := testDB.UpsertTunnel(context.Background(), &models.Tunnel{
		ID:        "old-dup",
		UserID:    &uid,
		Subdomain: "dup-sub",
		LocalPort: 3000,
		RemoteIP:  "127.0.0.1",
		Status:    "active",
		StartedAt: time.Now().Add(-2 * time.Minute).UTC(),
	}); err != nil {
		t.Fatalf("seed old duplicate tunnel: %v", err)
	}

	resp := makeRequest(http.MethodPost, "/api/tunnels", map[string]any{
		"id":         "new-dup",
		"user_id":    user.ID,
		"subdomain":  "dup-sub",
		"local_port": 3000,
		"remote_ip":  "127.0.0.1",
		"status":     "active",
		"started_at": time.Now().UTC().Format(time.RFC3339),
	}, "")
	defer closeResponse(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/tunnels status = %d, body = %s", resp.StatusCode, strings.TrimSpace(string(mustReadBody(resp))))
	}

	var oldStatus string
	var oldEndedAt *time.Time
	if err := testDB.Pool.QueryRow(context.Background(),
		`SELECT status, ended_at FROM tunnels WHERE id = $1`, "old-dup").
		Scan(&oldStatus, &oldEndedAt); err != nil {
		t.Fatalf("load old duplicate tunnel: %v", err)
	}
	if oldStatus != "stopped" {
		t.Fatalf("old duplicate tunnel status = %q, want stopped", oldStatus)
	}
	if oldEndedAt == nil {
		t.Fatal("old duplicate tunnel ended_at = nil, want timestamp")
	}

	listResp := makeRequest(http.MethodGet, "/api/tunnels?status=active", nil, jwtToken)
	defer closeResponse(listResp)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/tunnels?status=active status = %d, body = %s", listResp.StatusCode, strings.TrimSpace(string(mustReadBody(listResp))))
	}

	var listed []*models.Tunnel
	decodeResponseData(listResp, &listed)
	if len(listed) != 1 {
		t.Fatalf("active tunnel count = %d, want 1", len(listed))
	}
	if listed[0].ID != "new-dup" {
		t.Fatalf("active tunnel id = %q, want new-dup", listed[0].ID)
	}
}

func TestTeamSubdomainAssignmentControlsWhoCanClaimRoute(t *testing.T) {
	cleanDB()

	owner := seedUserWithOptions("owner", map[string]any{
		"plan":              "pro",
		"subscription_plan": "pro",
	})
	member := seedUser("member")
	other := seedUser("other")

	ownerJWT, err := auth.GenerateAccessToken(&owner, testJWTSecret)
	if err != nil {
		t.Fatalf("generate owner token: %v", err)
	}

	team := mustSeedTeam(t, owner.ID, "Assignments", "custom", "pro")
	if err := testDB.AddTeamMember(context.Background(), team.ID, member.ID, "member"); err != nil {
		t.Fatalf("add team member: %v", err)
	}
	if err := testDB.AddTeamMember(context.Background(), team.ID, other.ID, "member"); err != nil {
		t.Fatalf("add other member: %v", err)
	}

	sub, err := testDB.CreateReservedSubdomainByScope(context.Background(), "", team.ID, uniqueSubdomain("teamapp"))
	if err != nil {
		t.Fatalf("create team subdomain: %v", err)
	}

	assignResp := makeRequest(http.MethodPatch, "/api/subdomains/"+sub.ID+"/assignment?team_id="+url.QueryEscape(team.ID), map[string]any{
		"assigned_user_id": member.ID,
	}, ownerJWT)
	defer closeResponse(assignResp)
	if assignResp.StatusCode != http.StatusOK {
		t.Fatalf("assign subdomain status = %d, body = %s", assignResp.StatusCode, strings.TrimSpace(string(mustReadBody(assignResp))))
	}

	var assigned models.ReservedSubdomain
	decodeResponseData(assignResp, &assigned)
	if assigned.AssignedUserID == nil || *assigned.AssignedUserID != member.ID {
		t.Fatalf("assigned_user_id = %v, want %q", assigned.AssignedUserID, member.ID)
	}

	listResp := makeRequest(http.MethodGet, "/api/subdomains?team_id="+url.QueryEscape(team.ID), nil, ownerJWT)
	defer closeResponse(listResp)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list subdomains status = %d, body = %s", listResp.StatusCode, strings.TrimSpace(string(mustReadBody(listResp))))
	}

	var listed struct {
		Subdomains []*models.ReservedSubdomain `json:"subdomains"`
	}
	decodeResponseData(listResp, &listed)
	if len(listed.Subdomains) != 1 {
		t.Fatalf("team subdomain count = %d, want 1", len(listed.Subdomains))
	}
	if listed.Subdomains[0].AssignedUserID == nil || *listed.Subdomains[0].AssignedUserID != member.ID {
		t.Fatalf("listed assigned_user_id = %v, want %q", listed.Subdomains[0].AssignedUserID, member.ID)
	}

	got, err := testDB.GetReservedSubdomainForUser(context.Background(), member.ID, sub.Subdomain)
	if err != nil {
		t.Fatalf("assigned member lookup: %v", err)
	}
	if got != sub.Subdomain {
		t.Fatalf("assigned member lookup = %q, want %q", got, sub.Subdomain)
	}

	got, err = testDB.GetReservedSubdomainForUser(context.Background(), other.ID, sub.Subdomain)
	if err != nil {
		t.Fatalf("other member lookup: %v", err)
	}
	if got != "" {
		t.Fatalf("other member lookup = %q, want empty when route is assigned away", got)
	}

	clearResp := makeRequest(http.MethodPatch, "/api/subdomains/"+sub.ID+"/assignment?team_id="+url.QueryEscape(team.ID), map[string]any{
		"assigned_user_id": nil,
	}, ownerJWT)
	defer closeResponse(clearResp)
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("clear assignment status = %d, body = %s", clearResp.StatusCode, strings.TrimSpace(string(mustReadBody(clearResp))))
	}

	got, err = testDB.GetReservedSubdomainForUser(context.Background(), other.ID, sub.Subdomain)
	if err != nil {
		t.Fatalf("other member lookup after clear: %v", err)
	}
	if got != sub.Subdomain {
		t.Fatalf("other member lookup after clear = %q, want %q", got, sub.Subdomain)
	}
}

func TestCreateTeamScopedSubdomainUsesTeamOwnershipOnly(t *testing.T) {
	cleanDB()

	owner := seedUserWithOptions("owner", map[string]any{
		"plan":              "student",
		"subscription_plan": "student",
	})
	ownerJWT, err := auth.GenerateAccessToken(&owner, testJWTSecret)
	if err != nil {
		t.Fatalf("generate owner token: %v", err)
	}

	team := mustSeedTeam(t, owner.ID, "Student Team", "custom", "student")
	subdomain := uniqueSubdomain("team-owned")

	resp := makeRequest(http.MethodPost, "/api/subdomains?team_id="+url.QueryEscape(team.ID), map[string]any{
		"subdomain": subdomain,
	}, ownerJWT)
	defer closeResponse(resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create team subdomain status = %d, body = %s", resp.StatusCode, strings.TrimSpace(string(mustReadBody(resp))))
	}

	var created models.ReservedSubdomain
	decodeResponseData(resp, &created)
	if created.TeamID == nil || *created.TeamID != team.ID {
		t.Fatalf("team_id = %v, want %q", created.TeamID, team.ID)
	}
	if created.UserID != "" {
		t.Fatalf("user_id = %q, want empty for team-owned route", created.UserID)
	}
}

func mustPlanConfigPayload() []map[string]any {
	payload := make([]map[string]any, 0, len(baselinePlanConfigs))
	for _, cfg := range baselinePlanConfigs {
		var data map[string]any
		if err := json.Unmarshal(cfg.Config, &data); err != nil {
			panic(err)
		}
		data["id"] = cfg.PlanID
		payload = append(payload, data)
	}
	return payload
}

func mustNewsletterToken(userID string) string {
	token, err := testDB.EnsureNewsletterUnsubscribeToken(context.Background(), userID)
	if err != nil {
		panic(err)
	}
	return token
}

func TestAdminNewsletterPreviewRendersConcreteUnsubscribeLink(t *testing.T) {
	ctx := newCaseContext()
	wantToken := mustNewsletterToken(ctx.adminUser.ID)

	resp := makeRequest(http.MethodPost, "/api/admin/newsletter/preview", map[string]any{
		"subject":   "Hello",
		"body_html": `<p>Hi</p><a href="{{unsubscribe_url}}">Unsubscribe</a>`,
	}, ctx.adminJWT)
	defer closeResponse(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", resp.StatusCode, strings.TrimSpace(string(mustReadBody(resp))))
	}

	var payload struct {
		HTML             string `json:"html"`
		UnsubscribeToken string `json:"unsubscribe_token"`
		UnsubscribeURL   string `json:"unsubscribe_url"`
		AutoAppended     bool   `json:"auto_appended_unsubscribe"`
	}
	decodeResponseData(resp, &payload)

	if payload.UnsubscribeToken != wantToken {
		t.Fatalf("unsubscribe_token = %q, want %q", payload.UnsubscribeToken, wantToken)
	}
	if payload.AutoAppended {
		t.Fatalf("auto_appended_unsubscribe = true, want false")
	}
	if !strings.Contains(payload.HTML, payload.UnsubscribeURL) {
		t.Fatalf("expected rendered html to contain unsubscribe url %q, got %q", payload.UnsubscribeURL, payload.HTML)
	}
	if strings.Contains(payload.HTML, "{{unsubscribe_url}}") {
		t.Fatalf("expected preview html to replace placeholder, got %q", payload.HTML)
	}
}

func mustSeedDonation(t *testing.T, name string) *models.DonationSubmission {
	t.Helper()
	d, err := testDB.CreateDonation(context.Background(), &models.DonationSubmission{
		Name:          name,
		Amount:        "15.00",
		Currency:      "USD",
		PaymentMethod: "card",
	})
	if err != nil {
		t.Fatalf("seed donation: %v", err)
	}
	return d
}

func mustSeedPartner(t *testing.T, name string) *models.Partner {
	t.Helper()
	p, err := testDB.CreatePartner(context.Background(), &models.Partner{Name: name})
	if err != nil {
		t.Fatalf("seed partner: %v", err)
	}
	return p
}

func mustSeedSponsor(t *testing.T, title string) *models.Sponsor {
	t.Helper()
	s, err := testDB.CreateSponsor(context.Background(), &models.Sponsor{Title: title})
	if err != nil {
		t.Fatalf("seed sponsor: %v", err)
	}
	return s
}

func mustReadStream(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testBaseURL+path, nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	started := time.Now()
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("do stream request: %v", err)
	}
	buf := make([]byte, 512)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read stream response: %v", err)
	}
	raw := buf[:n]
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	durationByResp.Store(resp, time.Since(started))
	return resp, string(raw)
}

func uniqueSubdomain(prefix string) string {
	base := strings.ToLower(prefix)
	base = strings.ReplaceAll(base, "_", "-")
	base = strings.ReplaceAll(base, ".", "-")
	return fmt.Sprintf("%s-%d", base, testUserSeq.Add(1))
}

func uniqueDomain(prefix string) string {
	return fmt.Sprintf("%s-%d.localhost", strings.ToLower(strings.ReplaceAll(prefix, ".", "-")), testUserSeq.Add(1))
}

func testMigrationsDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "migrations"
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations")
}
