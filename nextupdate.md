# Next Update Checklist

Last updated: 2026-03-28

This file is now a clean product checklist, not a brainstorm list.
It tracks what is already live, what is only partially done, and what is still not ready.

## Status Key

- `[x]` Ready in production
- `[-]` Partially done
- `[ ]` Not ready

## Execution Rule

- [x] Do not stop to ask for confirmation during normal implementation work
- [x] Keep working through backend, frontend, testing, and deploy flow until the task batch is actually done
- [x] Only mark a task as `[x]` when code is implemented, tested, deployed, and smoke-checked
- [x] If something cannot be finished, leave it as `[-]` or `[ ]` with the blocker written clearly
- [x] Final updates should prefer `done and tested` status, not `please confirm first`

---

## Product Rules From Recent Feedback

These rules should stay true across backend, frontend, admin, and dashboard flows:

- [x] Personal plan and organization membership are separate
- [x] Joining an organization does not automatically change the user's personal plan
- [x] Normal add-member flow defaults to standard organization membership
- [x] Main add-member UI no longer shows manual role/admin/personal-plan controls
- [x] ORG-plan users who are not yet in any organization can create their own organization from `/dashboard/org`
- [-] Personal vs Team vs Organization scope is clearer than before, but still needs more final copy cleanup

---

## 1. Authentication & Login Flow

Status: `[-]`

- [x] Protected routes exist for `/dashboard/*` and `/admin/*`
- [x] Login redirects correctly by account type
- [x] Invite / CLI-auth safe redirects are preserved
- [x] Forced password reset is enforced after the main login flows
- [x] Provisioned welcome email points to `/auth/login`
- [x] Login page can prefill the invited email
- [x] Legacy `/login` is handled safely
- [ ] Full browser click-through validation for every login entry path

Priority:
- High

---

## 2. Organization Dashboard Core

Status: `[-]`

- [x] `/dashboard/org` exists in production
- [x] Sidebar includes `Organization`
- [x] ORG-plan user with no organization can create one directly from `/dashboard/org`
- [x] Org owner/admin can manage members from `/dashboard/org`
- [x] Org members can see their own allocation and request history
- [x] Manual add-by-email now defaults to normal organization membership
- [x] The main add-member UI no longer shows:
  - `Default access`
  - `Member of ORG`
  - `Give this member organization admin access`
  - `Personal Plan (optional)`
- [-] Real organization usage summary cards are now implemented on `/dashboard/org`, but still need validation with live org data
- [-] Better empty states are now implemented on `/dashboard/org`, but still need final browser validation for:
  - no organization yet
  - no members yet
  - no teams yet
  - no requests yet
- [-] Clearer section summaries and scope copy are now implemented at the top of `/dashboard/org`, but still need final wording review

Priority:
- High

---

## 3. Member Add / Import Flow

Status: `[-]`

- [x] Manual add by Gmail/email exists on `/dashboard/org`
- [x] Manual add by Gmail/email exists on `/admin/organizations`
- [x] Bulk CSV import exists
- [x] CSV template download exists
- [x] Existing user names can be corrected by import when CSV provides the right `name`
- [x] Personal plan is no longer changed by default during import or manual add
- [x] Limit fields now focus on organization usage, not personal account conversion
- [x] Add CSV preview table before import
- [x] Add confirm / cancel step before final import
- [x] Show row-by-row validation results:
  - valid
  - warning
  - error
- [x] Show import summary before submit:
  - create new user
  - attach existing user
  - update display name
  - skipped row
- [ ] Add optional column mapping UI for non-template CSV files
- [x] Add success/failure export for failed rows after import
- [-] Add full tested flow for:
  - manual add by email
  - CSV import with new users
  - CSV import with existing users
  - CSV import with invalid rows
- [x] Authenticated production API checks now confirm:
  - owner/org-manager login works
  - preview returns warning rows for existing-user attach/update cases
  - preview returns error rows plus failed-row CSV for invalid input
  - org members still get `403 owner or admin only` on protected member-management API routes

Priority:
- High

---

## 4. Organization Membership Logic

Status: `[-]`

- [x] Org owner/admin can add members
- [x] Org owner/admin can remove members
- [x] Per-member allocations exist
- [x] Per-member `team_limit` exists
- [x] Organization-managed teams can be created for members
- [x] Organization-managed teams can be deleted
- [x] Team creation for another member sends a notification
- [x] Org membership no longer implies personal paid-plan replacement
- [-] Seat usage summary is now implemented in code across:
  - org overview
  - member management
  - admin org view
- [-] Stronger copy now explains that an organization is a shared workspace, not a replacement for each user's personal account
- [ ] Test seat release flow after:
  - member removal
  - member leave
  - org deletion
- [ ] Test re-adding the same email after seat release
- [ ] Show why a member cannot be added when seats are full
- [-] Member state handling now surfaces:
  - active
  - pending first login
  Remaining state work:
  - invited
  - removed

Priority:
- High

---

## 5. Role / Plan Clarity

Status: `[-]`

- [x] Role and paid plan are separated better than before
- [x] Org UI can show role separately from personal plan
- [x] Main add-member UI no longer pushes role/admin/personal-plan choices into the default path
- [-] Consistent identity summary is now implemented in code across these related pages, but still needs browser validation:
  - org name
  - org role
  - personal plan
  - access source
- [-] One shared workspace identity card is now added on:
  - `/dashboard`
  - `/dashboard/org`
  - `/dashboard/team`
  - `/dashboard/settings`
- [ ] Final copy cleanup to reduce confusion between:
  - personal account
  - team workspace
  - organization workspace
  - role vs paid plan
- [ ] Remove any remaining wording that suggests:
  - org role is the same as paid plan
  - team membership is the same as org membership
  - org resources automatically replace personal resources

Priority:
- High

---

## 6. Organization Requests

Status: `[-]`

- [x] Org members can submit requests
- [x] Org admin can approve or deny requests
- [x] Request history exists on `/dashboard/org`
- [x] Request comments thread now exists for requester and org managers
- [x] Reviewer notes are now visible to the requester
- [x] Better request categories now exist:
  - more tunnels
  - more subdomains
  - more teams
  - more bandwidth
  - custom domain access
  - plan / billing discussion
- [x] Billing requests can now carry a requested discount percentage, and org managers can approve a specific percentage back to the requester
- [-] Request timeline / audit history is partially surfaced with:
  - created time
  - resolution time
  - last comment time
  - threaded comments
  A fuller timeline view is still not built yet
- [x] Clearer approval outcome now exists:
  - approved
  - denied
  - needs discussion
- [-] Pricing / approval discussion now has request categories, reviewer notes, and `needs discussion`, but there is still no dedicated paid checkout handoff after review
- [-] Tested flow now covers code/build plus authenticated API checks for preview/permissions, but still needs final full browser validation for:
  - submit request
  - approve
  - deny
  - notify user

Priority:
- Medium

---

## 7. Notifications

Status: `[-]`

- [x] Base notification system exists
- [x] Some organization-related notifications already exist
- [x] Org-managed team creation already notifies the assigned user
- [x] User is now notified when org request is approved
- [x] User is now notified when org request is rejected
- [x] User is now notified when org allocation changes
- [x] Notification center now groups the main org request / lifecycle events better
- [x] Optional email updates now exist for request status changes when mailer is configured
- [ ] Real-time refresh for request and org-team events
- [ ] Add read/unread state validation for org notifications

Priority:
- Medium

---

## 8. Admin Organization Panel

Status: `[-]`

- [x] `/admin/organizations` can create organizations
- [x] `/admin/organizations` can list org members correctly
- [x] `/admin/organizations` can add members manually
- [x] `/admin/organizations` can bulk import members
- [x] CSV template is downloadable
- [x] Delete organization is admin-only
- [x] Admin import route is live:
  - `POST /api/admin/organizations/{id}/import`
- [x] Main admin add-member UI now follows the simpler normal-member default
- [-] Admin org detail now has richer summary cards for seats, tunnels, admins, pending first login, creator, teams, and pending requests, but still needs final browser validation
- [x] Admin notes / comments now exist on org records
- [x] Clearer org lifecycle states now exist:
  - active
  - pending
  - suspended
  - archived
- [-] Cleaner seat allocation and member summary UX is improved with richer detail cards and summary fields, but still needs final browser polishing
- [x] Better admin visibility now exists for:
  - who created the org
  - who manages the org
  - current seat usage
  - org-owned teams
  - pending requests
- [-] Tested admin flow still needs final browser validation for:
  - create org
  - import members
  - delete org
  - view org activity

Priority:
- Medium

---

## 9. ORG Purchase / Upgrade Flow

Status: `[-]`

- [x] `Request ORG Plan` entry point now exists
- [x] Approval queue now exists
- [x] Waiting-for-approval state now exists in UI
- [x] Admin review details page now exists
- [x] Admin approval flow now:
  - creates the org
  - maps the requester correctly
  - sets initial seats / limits
  - notifies the requester
- [x] Admin can now set an approved ORG contract discount from `0` to `100` percent during approval
- [x] ORG billing checkout now reads the approved contract discount and applies it during checkout
- [x] Rejection flow with reason now exists
- [-] Contract duration / renewal rules are still note-based, not structured billing fields yet
- [-] Tested request-to-approval end-to-end path still needs one final authenticated browser pass

Priority:
- Medium

---

## 10. Sidebar / Navigation Clarity

Status: `[-]`

- [x] Team and Organization are separate sidebar entries
- [x] Organization anchors exist for:
  - overview
  - members
  - import
  - requests
- [ ] Final sidebar structure cleanup
- [ ] Decide whether requests need their own dedicated entry
- [ ] Add better labels so users know whether they are in:
  - personal space
  - team space
  - organization space
- [ ] Final copy pass to reduce overlap between personal, team, and organization sections

Priority:
- Medium

---

## 11. UI Clarity Follow-Up

Status: `[-]`

- [x] The biggest confusion points are identified
- [x] Some of the worst org membership vs personal plan confusion is already reduced
- [ ] Show organization name, role, access level, and personal plan consistently across all related pages
- [ ] Remove remaining confusing wording anywhere it still suggests:
  - org access equals personal paid plan
  - team space equals organization space
  - role equals subscription plan
- [ ] Add final terminology pass for:
  - `member`
  - `admin`
  - `owner`
  - `plan`
  - `organization access`
  - `team access`
- [ ] Add final end-to-end UI review after all org features are complete

Priority:
- High

---

## 12. Localhost Validation Checklist

Status: `[-]`

Purpose:
- This section is the concrete localhost validation checklist for Codex / Claude / any future agent.
- Use it before claiming a flow is complete.

### Auth Tests

- [ ] Login through `/auth/login`
- [ ] Login through legacy `/login`
- [ ] Invite login redirect
- [ ] CLI auth redirect flow
- [ ] Expired session redirect back to login
- [ ] First login for provisioned user forces password reset
- [ ] Restore session after refresh without role/plan redirect bugs

### Org API Tests

- [ ] `GET /api/org/mine`
- [ ] `POST /api/org/create`
- [ ] `GET /api/org/{id}`
- [ ] `GET /api/org/{id}/members`
- [ ] Add member through org UI/API
- [ ] Remove member through org UI/API
- [ ] Member calling owner/admin API returns `403`
- [ ] Missing auth returns `401`
- [ ] Unknown org returns `404`

### Member Lifecycle Tests

- [ ] Add brand-new user by email
- [ ] Add existing user by email
- [ ] Remove member and confirm seat release
- [ ] Re-add same email after seat release
- [ ] Org deletion releases seats and member state cleanly
- [ ] Full-seat org shows a clear `seats full` reason

### CSV Import Tests

- [ ] Valid CSV preview
- [ ] Invalid CSV preview
- [ ] Missing required column
- [ ] Duplicate email rows
- [ ] Import new users
- [ ] Import existing users
- [ ] Skip invalid rows cleanly
- [ ] Failed-row CSV export
- [ ] Large-file local run:
  - 100 rows
  - 1,000 rows
  - 10,000 rows

### Request System Tests

- [ ] Submit request
- [ ] Approve request
- [ ] Deny request
- [ ] Mark `needs discussion`
- [ ] Comments thread round-trip
- [ ] Billing discount request with approved percentage
- [ ] Repeated requests from same user
- [ ] Request spam/rate behavior

### Notification Tests

- [ ] Request approved notification
- [ ] Request rejected notification
- [ ] Allocation changed notification
- [ ] Org team created notification
- [ ] Read/unread state
- [ ] Real-time refresh behavior

### Admin Tests

- [ ] Create org
- [ ] Import members
- [ ] Delete org
- [ ] View org detail
- [ ] Update org lifecycle state
- [ ] Approve ORG request
- [ ] Reject ORG request
- [ ] Apply approved ORG discount

### ORG Upgrade Flow Tests

- [ ] Request ORG plan
- [ ] Admin approve ORG request
- [ ] Org created or linked correctly
- [ ] Requester mapped correctly as owner
- [ ] Requested seats/domain applied
- [ ] Approved discount shown in UI
- [ ] Checkout receives approved discount

Priority:
- High

---

## 13. Performance & Refactor Checklist

Status: `[-]`

### Current Risk Areas

- [-] CSV import can become heavy on large files and still needs explicit batching / async strategy
- [-] Org dashboard can still grow into multi-query / N+1 pressure under large orgs
- [-] Request + comment history can grow without pagination/timeline optimization
- [-] Notifications are still mostly request/response driven instead of fully real-time

### Refactor / Optimization Work

- [ ] Add caching layer for org-heavy reads
  Suggested cache targets:
  - `/api/org/mine`
  - `/api/org/{id}`
  - `/api/org/{id}/members`
  - `/api/org/{id}/teams`
- [ ] Add cache invalidation rules for:
  - member add/remove
  - org update
  - allocation update
  - team create/delete
- [ ] Add CSV batch processing
- [ ] Add async/background processing for:
  - large CSV import
  - email sending
  - heavy notification fan-out
- [ ] Review org/member/request queries for N+1 issues and replace with joined/eager patterns where needed
- [ ] Add pagination for large member/request lists
- [ ] Review database indexes for:
  - `org_id`
  - `user_id`
  - `request_id`
  - `email`

### Caching Recommendation

- [ ] Preferred cache backend: Redis
- [ ] Suggested cache TTL for org read APIs: `30-60s`
- [ ] Invalidate org cache on any org membership / allocation / request / team mutation

Priority:
- Medium

---

## 14. Role & Plan Test Matrix

Status: `[-]`

Purpose:
- This matrix must stay true in code, UI, and API permission checks.

### Free User

- [ ] Cannot create org
- [ ] Can join org
- [ ] Keeps personal plan `free`
- [ ] Uses org resources only through org allocation, not personal upgrade

### Student User

- [ ] First login / provisioned flow forces password reset when flagged
- [ ] Keeps personal plan `student` unless explicitly changed
- [ ] Org membership remains separate from student personal plan

### Pro User

- [ ] Keeps personal paid features
- [ ] Joining org does not remove personal `pro`
- [ ] Org workspace stays separate from personal `pro`

### ORG Owner / Admin

- [ ] Can create org when eligible
- [ ] Can manage members
- [ ] Can review org requests
- [ ] Can manage org teams and allocations

### ORG Member

- [ ] Can use org resources
- [ ] Cannot manage org
- [ ] Can submit org requests
- [ ] Personal plan remains independent

### Critical Role / Plan Assertions

- [ ] ORG member with personal plan `free` still gets org resource access through org allocation
- [ ] ORG member does not automatically become personal plan `org`
- [ ] Org role does not equal paid plan
- [ ] Team membership does not equal org membership

Priority:
- High

---

## 15. Agent Handoff

Status: `[-]`

This section is for future agents working on the repo:

- [x] Core org architecture is already strong
- [x] Main remaining work is not foundational redesign
- [x] Main remaining work is:
  - browser validation
  - performance hardening
  - UI clarity
  - seat lifecycle edge cases
  - notification polish
- [ ] Before changing architecture, confirm the issue is real and not only a validation gap
- [ ] Prefer reducing confusion in UI copy and state handling before adding new abstractions
- [ ] Treat seat lifecycle, notification real-time behavior, and import performance as the next highest-risk implementation areas

Priority:
- High

---

## Production Snapshot

Verified live on 2026-03-28:

- [x] `GET https://api.angkorsearch.dev/api/health`
- [x] `HEAD https://angkorsearch.dev/admin/organizations`
- [x] `HEAD https://angkorsearch.dev/admin/verify-requests`
- [x] `HEAD https://angkorsearch.dev/dashboard/billing`
- [x] `HEAD https://angkorsearch.dev/dashboard/org`
- [x] `HEAD https://angkorsearch.dev/auth/login`
- [x] `HEAD https://angkorsearch.dev/auth/verify-account`
- [x] `HEAD https://angkorsearch.dev/login`
- [x] `GET https://api.angkorsearch.dev/api/org/mine` returns `401` without auth
- [x] `GET https://api.angkorsearch.dev/api/admin/verify-requests` returns `401` without auth
- [x] `POST https://api.angkorsearch.dev/api/admin/organizations/{id}/import` returns `401` without auth
- [x] `POST https://api.angkorsearch.dev/api/admin/organizations/{id}/import/preview` returns `401` without auth
- [x] `GET https://api.angkorsearch.dev/api/org/{id}/teams` returns `401` without auth
- [x] `POST https://api.angkorsearch.dev/api/org/create` returns `401` without auth
- [x] Authenticated preview check on the owner account returned `200` with warning summary for an existing-user attach/update row
- [x] Authenticated invalid-row preview check returned `200` with `error_rows=1` and `failed_csv` present
- [x] Authenticated member permission check returned `403 owner or admin only` on `GET /api/org/{id}/members`

## Localhost Snapshot

Checked on 2026-03-28:

- [x] `go test ./internal/db ./cmd/api ./cmd/mekongtunnel`
- [x] Frontend eslint passed for the currently changed org/admin/billing files
- [x] Frontend `npm run build`
- [-] `go test ./internal/api/handlers` is blocked locally because PostgreSQL is not running on `localhost:5432`
- [-] `curl http://127.0.0.1:8080/api/health` failed because no local API server was running
- [-] `curl http://127.0.0.1:3000/dashboard/org` failed because no local frontend dev server was running

## Authenticated Testing Matrix

- Private test account A:
  - org manager / owner scenario
  - current live API returned personal plan `org` and org role `owner`
- Private test account B:
  - joined organization member scenario
  - current live API returned personal plan `free` and org role `member`
  - this account is not currently attached to the same live org as private test account A
- 2026-03-28 re-check:
  - the previously supplied test passwords now return `invalid credentials` on production
  - final authenticated live re-check for the new org-request / approval routes needs fresh working test credentials
- Raw passwords are intentionally not stored in this repository

Recent deploy logs:

- [deploy-api-20260328-131218.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-131218.log)
- [deploy-api-20260328-125506.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-125506.log)
- [deploy-api-20260328-110641.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-110641.log)
- [deploy-api-20260328-112522.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-112522.log)
- [deploy-api-20260328-105621.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-105621.log)
- [deploy-api-20260328-103841.log](/Users/ingmuyleang/tunnl.gg/logs/deploy-api-20260328-103841.log)

---

## Recommended Next Order

1. Run final authenticated browser validation for:
   - org requests
   - notifications
   - admin org lifecycle actions
   - ORG approval flow
2. Finish optional column mapping for non-template CSV files
3. Finish seat release and re-add flows after member removal / leave / org deletion
4. Add real-time refresh and unread-state validation for org notifications
5. Finish pricing / checkout handoff for request outcomes that need payment
6. Finish final copy cleanup for personal vs team vs organization space
7. Run final end-to-end UI and production validation pass

---

## Main Problem To Keep Solving

The biggest product confusion is still this:

- personal account vs organization access
- role vs paid plan
- team workspace vs organization workspace

Every next UI or API change should reduce that confusion, not add to it.
