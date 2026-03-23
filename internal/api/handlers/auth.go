// Package handlers contains all HTTP request handlers for MekongTunnel API.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

var emailRE = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// AuthHandler handles all /api/auth/* endpoints.
type AuthHandler struct {
	DB                  *db.DB
	JWTSecret           string
	RefreshSecret       string
	GitHubClientID      string
	GitHubClientSecret  string
	GitHubCallbackURL   string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleCallbackURL   string
	FrontendURL         string
	Notify              *notify.Service
	Mailer              *mailer.Mailer
}

// ─── helpers ─────────────────────────────────────────────────

func sanitizeUser(u *models.User) map[string]any {
	return map[string]any{
		"id":                u.ID,
		"email":             u.Email,
		"name":              u.Name,
		"avatar_url":        u.AvatarURL,
		"plan":              u.Plan,
		"subscription_plan": u.SubscriptionPlan,
		"account_type":      u.AccountType,
		"email_verified":    u.EmailVerified,
		"totp_enabled":      u.TOTPEnabled,
		"is_admin":          u.IsAdmin,
		"suspended":         u.Suspended,
		"github_login":      u.GithubLogin,
		"google_id":         u.GoogleID,
		"created_at":        u.CreatedAt,
		"updated_at":        u.UpdatedAt,
		"last_seen_at":      u.LastSeenAt,
	}
}


// ─── Register ─────────────────────────────────────────────────

// Register handles POST /api/auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		AccountType string `json:"account_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	body.Name = strings.TrimSpace(body.Name)

	if !emailRE.MatchString(body.Email) {
		response.BadRequest(w, "invalid email address")
		return
	}
	if len(body.Password) < 8 {
		response.BadRequest(w, "password must be at least 8 characters")
		return
	}
	if body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}

	// Check for duplicate email.
	existing, _ := h.DB.GetUserByEmail(r.Context(), body.Email)
	if existing != nil {
		response.Error(w, http.StatusConflict, "email already registered")
		return
	}

	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	user, err := h.DB.CreateUser(r.Context(), body.Email, body.Name, hash)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Update account_type if provided.
	if body.AccountType != "" && body.AccountType != "personal" {
		updated, err := h.DB.UpdateUser(r.Context(), user.ID, map[string]any{"account_type": body.AccountType})
		if err == nil {
			user = updated
		}
	}

	// Issue tokens.
	accessToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	refreshHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if err := h.DB.CreateRefreshToken(r.Context(), user.ID, refreshHash, expiresAt); err != nil {
		response.InternalError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	// Send email verification token.
	verifyToken, err := auth.GenerateSecureToken()
	if err == nil {
		verifyHash := auth.HashToken(verifyToken)
		_ = h.DB.CreateEmailVerifyToken(r.Context(), user.ID, verifyHash, time.Now().Add(24*time.Hour))
		if h.Mailer != nil {
			go h.Mailer.SendVerification(user.Email, user.Name, verifyToken, h.FrontendURL)
		} else {
			log.Printf("[auth] email verify token for %s: %s", user.Email, verifyToken)
		}
	}

	// Notify admins about new registration.
	if h.Notify != nil {
		go h.Notify.SendToAdmins(context.Background(), "user_registered",
			"New user registered",
			user.Name+" ("+user.Email+") just signed up",
			"/admin/users")
	}

	response.Created(w, map[string]any{
		"access_token": accessToken,
		"user":         sanitizeUser(user),
	})
}

// ─── Login ────────────────────────────────────────────────────

// Login handles POST /api/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	body.Email = strings.ToLower(strings.TrimSpace(body.Email))

	user, err := h.DB.GetUserByEmail(r.Context(), body.Email)
	if err != nil || user == nil {
		response.Unauthorized(w, "invalid credentials")
		return
	}

	if user.Suspended {
		response.Error(w, http.StatusForbidden, "account suspended")
		return
	}

	if !user.EmailVerified {
		response.Error(w, http.StatusForbidden, "email_not_verified")
		return
	}

	if user.PasswordHash == nil || !auth.CheckPassword(*user.PasswordHash, body.Password) {
		response.Unauthorized(w, "invalid credentials")
		return
	}

	_ = h.DB.UpdateLastSeen(r.Context(), user.ID)

	// If 2FA is enabled, return a temporary token instead.
	if user.TOTPEnabled {
		tempToken, err := auth.GenerateTemp2FAToken(user.ID, user.Email, h.JWTSecret)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		response.Success(w, map[string]any{
			"requires_2fa": true,
			"temp_token":   tempToken,
		})
		return
	}

	accessToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	refreshHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if err := h.DB.CreateRefreshToken(r.Context(), user.ID, refreshHash, expiresAt); err != nil {
		response.InternalError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	response.Success(w, map[string]any{
		"access_token": accessToken,
		"user":         sanitizeUser(user),
	})
}

// ─── Logout ───────────────────────────────────────────────────

// Logout handles POST /api/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("mekong_refresh")
	if err == nil && cookie.Value != "" {
		hash := auth.HashToken(cookie.Value)
		_ = h.DB.RevokeRefreshToken(r.Context(), hash)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    "",
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	response.Success(w, map[string]any{"message": "logged out"})
}

// ─── Me ───────────────────────────────────────────────────────

// Me handles GET /api/auth/me.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	_ = h.DB.UpdateLastSeen(r.Context(), user.ID)
	response.Success(w, sanitizeUser(user))
}

// TokenInfo handles GET /api/auth/token-info.
// Accepts an API token (mkt_xxx) in the Authorization: Bearer header — NOT a JWT.
// Used by `mekong whoami` and `mekong test` to verify a saved CLI token.
func (h *AuthHandler) TokenInfo(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 8 || hdr[:7] != "Bearer " {
		response.Unauthorized(w, "Bearer token required")
		return
	}
	rawToken := hdr[7:]

	userID, err := h.DB.ValidateToken(r.Context(), rawToken)
	if err != nil {
		response.Unauthorized(w, "invalid or expired token")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), userID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	response.Success(w, sanitizeUser(user))
}

// ─── Refresh ──────────────────────────────────────────────────

// Refresh handles POST /api/auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("mekong_refresh")
	if err != nil || cookie.Value == "" {
		response.Unauthorized(w, "no refresh token")
		return
	}

	hash := auth.HashToken(cookie.Value)
	rt, err := h.DB.GetRefreshToken(r.Context(), hash)
	if err != nil {
		response.Unauthorized(w, "invalid refresh token")
		return
	}

	if rt.RevokedAt != nil {
		response.Unauthorized(w, "refresh token revoked")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		response.Unauthorized(w, "refresh token expired")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), rt.UserID)
	if err != nil {
		response.Unauthorized(w, "user not found")
		return
	}

	if user.Suspended {
		response.Error(w, http.StatusForbidden, "account suspended")
		return
	}

	// Rotate: revoke old, issue new.
	_ = h.DB.RevokeRefreshToken(r.Context(), hash)

	accessToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	newHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if err := h.DB.CreateRefreshToken(r.Context(), user.ID, newHash, expiresAt); err != nil {
		response.InternalError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	response.Success(w, map[string]any{
		"access_token": accessToken,
	})
}

// ─── ForgotPassword ───────────────────────────────────────────

// ForgotPassword handles POST /api/auth/forgot-password.
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))

	// Don't reveal if the email exists.
	user, _ := h.DB.GetUserByEmail(r.Context(), body.Email)
	if user != nil {
		token, err := auth.GenerateSecureToken()
		if err == nil {
			hash := auth.HashToken(token)
			expiresAt := time.Now().Add(1 * time.Hour)
			if err := h.DB.CreatePasswordResetToken(r.Context(), user.ID, hash, expiresAt); err == nil {
				if h.Mailer != nil {
					go h.Mailer.SendPasswordReset(user.Email, user.Name, token, h.FrontendURL)
				} else {
					log.Printf("[auth] password reset token for %s: %s", user.Email, token)
				}
			}
		}
	}

	response.Success(w, map[string]any{
		"message": "if that email is registered, a reset link has been sent",
	})
}

// ─── ResetPassword ────────────────────────────────────────────

// ResetPassword handles POST /api/auth/reset-password.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Token == "" {
		response.BadRequest(w, "token is required")
		return
	}
	if len(body.Password) < 8 {
		response.BadRequest(w, "password must be at least 8 characters")
		return
	}

	hash := auth.HashToken(body.Token)
	rt, err := h.DB.GetPasswordResetToken(r.Context(), hash)
	if err != nil {
		response.BadRequest(w, "invalid or expired reset token")
		return
	}

	if rt.UsedAt != nil {
		response.BadRequest(w, "reset token already used")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		response.BadRequest(w, "reset token expired")
		return
	}

	passwordHash, err := auth.HashPassword(body.Password)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	if err := h.DB.UpdatePassword(r.Context(), rt.UserID, passwordHash); err != nil {
		response.InternalError(w, err)
		return
	}

	_ = h.DB.MarkPasswordResetTokenUsed(r.Context(), hash)

	response.Success(w, map[string]any{"message": "password updated"})
}

// ─── VerifyEmail ──────────────────────────────────────────────

// VerifyEmail handles POST /api/auth/verify-email.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Token == "" {
		response.BadRequest(w, "token is required")
		return
	}

	hash := auth.HashToken(body.Token)
	vt, err := h.DB.GetEmailVerifyToken(r.Context(), hash)
	if err != nil {
		response.BadRequest(w, "invalid or expired verification token")
		return
	}

	if vt.UsedAt != nil {
		response.BadRequest(w, "token already used")
		return
	}
	if time.Now().After(vt.ExpiresAt) {
		response.BadRequest(w, "verification token expired")
		return
	}

	if err := h.DB.SetEmailVerified(r.Context(), vt.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	_ = h.DB.MarkEmailVerifyTokenUsed(r.Context(), hash)

	response.Success(w, map[string]any{"message": "email verified"})
}

// ─── ResendVerify ─────────────────────────────────────────────

// ResendVerify handles POST /api/auth/resend-verify.
// Public endpoint — takes an email address and sends a fresh verification link.
func (h *AuthHandler) ResendVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if body.Email == "" {
		response.BadRequest(w, "email is required")
		return
	}

	// Always return success to avoid email enumeration.
	user, _ := h.DB.GetUserByEmail(r.Context(), body.Email)
	if user != nil && !user.EmailVerified {
		token, err := auth.GenerateSecureToken()
		if err == nil {
			tokenHash := auth.HashToken(token)
			_ = h.DB.CreateEmailVerifyToken(r.Context(), user.ID, tokenHash, time.Now().Add(24*time.Hour))
			if h.Mailer != nil {
				go h.Mailer.SendVerification(user.Email, user.Name, token, h.FrontendURL)
			} else {
				log.Printf("[auth] resend verify token for %s: %s", user.Email, token)
			}
		}
	}

	response.Success(w, map[string]any{"message": "if your email is registered and unverified, a new link has been sent"})
}

// ─── RequestAdminVerify ───────────────────────────────────────

// RequestAdminVerify handles POST /api/auth/request-admin-verify.
// Lets an unverified user ask admins to manually verify their account.
func (h *AuthHandler) RequestAdminVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if body.Email == "" {
		response.BadRequest(w, "email is required")
		return
	}

	// Always return success to avoid enumeration.
	user, _ := h.DB.GetUserByEmail(r.Context(), body.Email)
	if user != nil && !user.EmailVerified {
		if h.Notify != nil {
			msg := body.Message
			if msg == "" {
				msg = "User requests manual email verification"
			}
			go h.Notify.SendToAdmins(context.Background(), "verify_admin_request",
				"Manual verification requested",
				user.Name+" ("+user.Email+") is asking an admin to manually verify their account. "+msg,
				"/admin/users/"+user.ID)
		}
		log.Printf("[auth] admin verify request from %s", user.Email)
	}

	response.Success(w, map[string]any{"message": "your request has been sent to the admin team"})
}

// ─── GitHub OAuth ─────────────────────────────────────────────

// GitHubOAuth handles GET /api/auth/github — redirects to GitHub.
func (h *AuthHandler) GitHubOAuth(w http.ResponseWriter, r *http.Request) {
	state, _ := auth.GenerateSecureToken()
	authURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email&state=%s",
		h.GitHubClientID,
		url.QueryEscape(h.GitHubCallbackURL),
		state,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GitHubCallback handles GET /api/auth/github/callback.
func (h *AuthHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		response.BadRequest(w, "missing code")
		return
	}

	accessToken, err := auth.GetGitHubAccessToken(code, h.GitHubClientID, h.GitHubClientSecret, h.GitHubCallbackURL)
	if err != nil {
		response.InternalError(w, fmt.Errorf("github token: %w", err))
		return
	}

	ghUser, err := auth.GetGitHubUser(accessToken)
	if err != nil {
		response.InternalError(w, fmt.Errorf("github user: %w", err))
		return
	}

	githubIDStr := fmt.Sprintf("%d", ghUser.ID)

	// Find existing user by GitHub ID.
	user, err := h.DB.GetUserByGithubID(r.Context(), githubIDStr)
	if err != nil {
		// Try by email.
		if ghUser.Email != "" {
			user, _ = h.DB.GetUserByEmail(r.Context(), strings.ToLower(ghUser.Email))
		}
		if user == nil {
			// Create new user.
			email := strings.ToLower(ghUser.Email)
			if email == "" {
				email = fmt.Sprintf("github_%d@noreply.mekongtunnel.dev", ghUser.ID)
			}
			name := ghUser.Name
			if name == "" {
				name = ghUser.Login
			}
			user, err = h.DB.CreateUser(r.Context(), email, name, "")
			if err != nil {
				response.InternalError(w, err)
				return
			}
			// Mark email verified for OAuth users.
			_ = h.DB.SetEmailVerified(r.Context(), user.ID)
		}
		// Link GitHub account.
		_ = h.DB.LinkGithubAccount(r.Context(), user.ID, githubIDStr, ghUser.Login)
		user, _ = h.DB.GetUserByID(r.Context(), user.ID)
	}

	if user.Suspended {
		http.Redirect(w, r, h.FrontendURL+"/auth/suspended", http.StatusFound)
		return
	}

	_ = h.DB.UpdateLastSeen(r.Context(), user.ID)

	jwtToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	refreshHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_ = h.DB.CreateRefreshToken(r.Context(), user.ID, refreshHash, expiresAt)

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	redirectURL := h.FrontendURL + "/auth/callback?token=" + url.QueryEscape(jwtToken)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ─── Google OAuth ─────────────────────────────────────────────

// GoogleOAuth handles GET /api/auth/google.
func (h *AuthHandler) GoogleOAuth(w http.ResponseWriter, r *http.Request) {
	state, _ := auth.GenerateSecureToken()
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
		h.GoogleClientID,
		url.QueryEscape(h.GoogleCallbackURL),
		state,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GoogleCallback handles GET /api/auth/google/callback.
func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		response.BadRequest(w, "missing code")
		return
	}

	accessToken, err := auth.GetGoogleAccessToken(code, h.GoogleClientID, h.GoogleClientSecret, h.GoogleCallbackURL)
	if err != nil {
		response.InternalError(w, fmt.Errorf("google token: %w", err))
		return
	}

	gUser, err := auth.GetGoogleUser(accessToken)
	if err != nil {
		response.InternalError(w, fmt.Errorf("google user: %w", err))
		return
	}

	// Find by Google Sub.
	user, err := h.DB.GetUserByGoogleID(r.Context(), gUser.Sub)
	if err != nil {
		// Try by email.
		if gUser.Email != "" {
			user, _ = h.DB.GetUserByEmail(r.Context(), strings.ToLower(gUser.Email))
		}
		if user == nil {
			email := strings.ToLower(gUser.Email)
			user, err = h.DB.CreateUser(r.Context(), email, gUser.Name, "")
			if err != nil {
				response.InternalError(w, err)
				return
			}
			_ = h.DB.SetEmailVerified(r.Context(), user.ID)
			// Update avatar.
			if gUser.Picture != "" {
				user, _ = h.DB.UpdateUser(r.Context(), user.ID, map[string]any{"avatar_url": gUser.Picture})
			}
		}
		_ = h.DB.LinkGoogleAccount(r.Context(), user.ID, gUser.Sub)
		user, _ = h.DB.GetUserByID(r.Context(), user.ID)
	}

	if user.Suspended {
		http.Redirect(w, r, h.FrontendURL+"/auth/suspended", http.StatusFound)
		return
	}

	_ = h.DB.UpdateLastSeen(r.Context(), user.ID)

	jwtToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	refreshHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_ = h.DB.CreateRefreshToken(r.Context(), user.ID, refreshHash, expiresAt)

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	redirectURL := h.FrontendURL + "/auth/callback?token=" + url.QueryEscape(jwtToken)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ─── 2FA ──────────────────────────────────────────────────────

// Setup2FA handles POST /api/auth/2fa/setup (requires auth).
func (h *AuthHandler) Setup2FA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	secret, otpauthURL, qrBase64, err := auth.GenerateTOTPSecret(user.Email, "MekongTunnel")
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Store the (unconfirmed) secret.
	if err := h.DB.SetTOTPSecret(r.Context(), user.ID, secret); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"secret":        secret,
		"otpauth_url":   otpauthURL,
		"qr_code_base64": qrBase64,
	})
}

// Enable2FA handles POST /api/auth/2fa/enable (requires auth).
func (h *AuthHandler) Enable2FA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if user.TOTPSecret == nil {
		response.BadRequest(w, "run /api/auth/2fa/setup first")
		return
	}

	if !auth.ValidateTOTP(*user.TOTPSecret, body.Code) {
		response.BadRequest(w, "invalid TOTP code")
		return
	}

	if err := h.DB.EnableTOTP(r.Context(), user.ID); err != nil {
		response.InternalError(w, err)
		return
	}

	plains, hashes, err := auth.GenerateBackupCodes(8)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	if err := h.DB.SaveBackupCodes(r.Context(), user.ID, hashes); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"backup_codes": plains,
	})
}

// Disable2FA handles POST /api/auth/2fa/disable (requires auth).
func (h *AuthHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == nil {
		response.BadRequest(w, "2FA is not enabled")
		return
	}

	if !auth.ValidateTOTP(*user.TOTPSecret, body.Code) {
		response.BadRequest(w, "invalid TOTP code")
		return
	}

	if err := h.DB.DisableTOTP(r.Context(), user.ID); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "2FA disabled"})
}

// Verify2FA handles POST /api/auth/2fa/verify.
func (h *AuthHandler) Verify2FA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TempToken string `json:"temp_token"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.TempToken == "" || body.Code == "" {
		response.BadRequest(w, "temp_token and code are required")
		return
	}

	claims, err := auth.ValidateToken(body.TempToken, h.JWTSecret)
	if err != nil {
		response.Unauthorized(w, "invalid or expired temp token")
		return
	}

	if !claims.Temp2FA {
		response.Unauthorized(w, "not a 2FA temp token")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if user.Suspended {
		response.Error(w, http.StatusForbidden, "account suspended")
		return
	}

	// Try TOTP code.
	validCode := user.TOTPSecret != nil && auth.ValidateTOTP(*user.TOTPSecret, body.Code)

	// Try backup code.
	if !validCode {
		codeHash := auth.HashToken(body.Code)
		if err := h.DB.UseBackupCode(r.Context(), user.ID, codeHash); err == nil {
			validCode = true
		}
	}

	if !validCode {
		response.Unauthorized(w, "invalid 2FA code")
		return
	}

	_ = h.DB.UpdateLastSeen(r.Context(), user.ID)

	accessToken, err := auth.GenerateAccessToken(user, h.JWTSecret)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	rawRefresh, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	refreshHash := auth.HashToken(rawRefresh)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if err := h.DB.CreateRefreshToken(r.Context(), user.ID, refreshHash, expiresAt); err != nil {
		response.InternalError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "mekong_refresh",
		Value:    rawRefresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.FrontendURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	response.Success(w, map[string]any{
		"access_token": accessToken,
		"user":         sanitizeUser(user),
	})
}
