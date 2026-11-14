package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// PasskeyHandler implements passkey (WebAuthn) registration and sign-in.
//
// Ceremony state (the challenge) lives in memory for a few minutes. That is
// fine for a single API instance; run several and it would need Redis.
type PasskeyHandler struct {
	Auth     *AuthHandler
	WebAuthn *webauthn.WebAuthn
	sessions *ceremonyStore
}

// NewPasskeyHandler configures WebAuthn from the frontend URL: the relying
// party ID is the site's hostname (e.g. mekongtunnel.dev, or localhost in dev).
// WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS (comma-separated) override the defaults.
func NewPasskeyHandler(a *AuthHandler) (*PasskeyHandler, error) {
	frontend := strings.TrimRight(a.FrontendURL, "/")
	u, err := url.Parse(frontend)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("passkeys: invalid FRONTEND_URL %q", a.FrontendURL)
	}

	rpID := strings.TrimSpace(os.Getenv("WEBAUTHN_RP_ID"))
	if rpID == "" {
		rpID = strings.TrimPrefix(u.Hostname(), "www.")
	}
	origins := []string{frontend}
	if extra := strings.TrimSpace(os.Getenv("WEBAUTHN_ORIGINS")); extra != "" {
		origins = nil
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
				origins = append(origins, o)
			}
		}
	} else if u.Hostname() != "localhost" {
		// Accept both the apex and the www host.
		alt := *u
		if strings.HasPrefix(u.Host, "www.") {
			alt.Host = strings.TrimPrefix(u.Host, "www.")
		} else {
			alt.Host = "www." + u.Host
		}
		origins = append(origins, strings.TrimRight(alt.String(), "/"))
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Mekong Tunnel",
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &PasskeyHandler{Auth: a, WebAuthn: wa, sessions: newCeremonyStore(5 * time.Minute)}, nil
}

// ─── webauthn.User adapter ───────────────────────────────────

type passkeyUser struct {
	user  *models.User
	creds []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte          { return []byte(u.user.ID) }
func (u *passkeyUser) WebAuthnName() string        { return u.user.Email }
func (u *passkeyUser) WebAuthnDisplayName() string { return firstNonEmpty(u.user.Name, u.user.Email) }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func credentialKey(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// loadPasskeyUser loads a user together with their stored credentials.
func (h *PasskeyHandler) loadPasskeyUser(r *http.Request, userID string) (*passkeyUser, error) {
	user, err := h.Auth.DB.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	stored, err := h.Auth.DB.ListPasskeys(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	pu := &passkeyUser{user: user}
	for _, p := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(p.Credential, &c); err != nil {
			log.Printf("[passkey] skipping unreadable credential %s: %v", p.ID, err)
			continue
		}
		pu.creds = append(pu.creds, c)
	}
	return pu, nil
}

// ─── Registration (signed-in user adds a passkey) ────────────

// BeginRegistration handles POST /api/auth/passkeys/register/begin.
func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	pu, err := h.loadPasskeyUser(r, claims.UserID)
	if err != nil {
		response.Unauthorized(w, "user not found")
		return
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(pu.creds))
	for _, c := range pu.creds {
		exclusions = append(exclusions, c.Descriptor())
	}

	creation, session, err := h.WebAuthn.BeginRegistration(pu,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	h.sessions.put("reg:"+claims.UserID, session)
	response.Success(w, map[string]any{"options": creation.Response})
}

// FinishRegistration handles POST /api/auth/passkeys/register/finish?name=…
// The body is the browser's registration response JSON.
func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	session, ok := h.sessions.take("reg:" + claims.UserID)
	if !ok {
		response.BadRequest(w, "passkey setup expired — please try again")
		return
	}
	pu, err := h.loadPasskeyUser(r, claims.UserID)
	if err != nil {
		response.Unauthorized(w, "user not found")
		return
	}

	cred, err := h.WebAuthn.FinishRegistration(pu, *session, r)
	if err != nil {
		log.Printf("[passkey] registration failed for %s: %v", claims.UserID, err)
		response.BadRequest(w, "could not verify passkey")
		return
	}

	raw, err := json.Marshal(cred)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	id := credentialKey(cred.ID)
	if err := h.Auth.DB.CreatePasskey(r.Context(), claims.UserID, id, name, raw); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"id": id, "name": name})
}

// ─── Manage ──────────────────────────────────────────────────

// List handles GET /api/auth/passkeys.
func (h *PasskeyHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	keys, err := h.Auth.DB.ListPasskeys(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, keys)
}

// Rename handles PATCH /api/auth/passkeys/{id} with {"name": "..."}.
func (h *PasskeyHandler) Rename(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		response.BadRequest(w, "name is required")
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) > 60 {
		name = name[:60]
	}
	if err := h.Auth.DB.RenamePasskey(r.Context(), claims.UserID, r.PathValue("id"), name); err != nil {
		if errors.Is(err, db.ErrPasskeyNotFound) {
			response.NotFound(w, "passkey not found")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// Delete handles DELETE /api/auth/passkeys/{id}.
func (h *PasskeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if err := h.Auth.DB.DeletePasskey(r.Context(), claims.UserID, r.PathValue("id")); err != nil {
		if errors.Is(err, db.ErrPasskeyNotFound) {
			response.NotFound(w, "passkey not found")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// ─── Sign in with a passkey ──────────────────────────────────

// BeginLogin handles POST /api/auth/passkeys/login/begin. No email needed:
// the browser offers the user's saved passkeys (discoverable credentials).
func (h *PasskeyHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := h.WebAuthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	sessionID, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	h.sessions.put("login:"+sessionID, session)
	response.Success(w, map[string]any{"options": assertion.Response, "session_id": sessionID})
}

// FinishLogin handles POST /api/auth/passkeys/login/finish?session_id=…&remember=1
// The body is the browser's authentication response JSON.
func (h *PasskeyHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	session, ok := h.sessions.take("login:" + q.Get("session_id"))
	if !ok {
		response.BadRequest(w, "passkey sign-in expired — please try again")
		return
	}

	var loaded *passkeyUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		ownerID, err := h.Auth.DB.PasskeyOwner(r.Context(), credentialKey(rawID))
		if err != nil {
			return nil, err
		}
		if ownerID != string(userHandle) {
			return nil, errors.New("passkey does not belong to this user")
		}
		pu, err := h.loadPasskeyUser(r, ownerID)
		if err != nil {
			return nil, err
		}
		loaded = pu
		return pu, nil
	}

	_, cred, err := h.WebAuthn.FinishPasskeyLogin(handler, *session, r)
	if err != nil || loaded == nil {
		log.Printf("[passkey] sign-in failed: %v", err)
		response.Unauthorized(w, "passkey not recognised")
		return
	}
	if cred.Authenticator.CloneWarning {
		log.Printf("[passkey] clone warning for user %s credential %s", loaded.user.ID, credentialKey(cred.ID))
		response.Unauthorized(w, "passkey rejected — please remove and re-add it")
		return
	}

	user := loaded.user
	if user.Suspended {
		response.Error(w, http.StatusForbidden, "account suspended")
		return
	}

	if raw, err := json.Marshal(cred); err == nil {
		_ = h.Auth.DB.UpdatePasskeyAfterLogin(r.Context(), credentialKey(cred.ID), raw)
	}

	remember := q.Get("remember") != "0"
	accessToken, err := h.Auth.issueSession(w, r.Context(), user, remember)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{
		"access_token":        accessToken,
		"user":                sanitizeUser(user),
		"must_reset_password": user.ForcePasswordReset,
	})
}

// ─── In-memory ceremony store ────────────────────────────────

type ceremonyEntry struct {
	session *webauthn.SessionData
	expires time.Time
}

type ceremonyStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]ceremonyEntry
}

func newCeremonyStore(ttl time.Duration) *ceremonyStore {
	return &ceremonyStore{ttl: ttl, m: map[string]ceremonyEntry{}}
}

func (s *ceremonyStore) put(key string, session *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.m { // opportunistic cleanup
		if now.After(e.expires) {
			delete(s.m, k)
		}
	}
	s.m[key] = ceremonyEntry{session: session, expires: now.Add(s.ttl)}
}

// take returns and removes a session, so each challenge is single-use.
func (s *ceremonyStore) take(key string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	delete(s.m, key)
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.session, true
}
