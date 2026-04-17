package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/customdomain"
)

type customDomainRecord struct {
	ID                string                   `json:"id"`
	UserID            string                   `json:"user_id"`
	Domain            string                   `json:"domain"`
	Status            string                   `json:"status"`
	VerificationToken string                   `json:"verification_token"`
	TargetSubdomain   *string                  `json:"target_subdomain,omitempty"`
	CreatedAt         string                   `json:"created_at"`
	VerifiedAt        *string                  `json:"verified_at,omitempty"`
	CNAMETarget       string                   `json:"cname_target"`
	TXTName           string                   `json:"txt_name"`
	TXTValue          string                   `json:"txt_value"`
	DNSMode           string                   `json:"dns_mode"`
	PrimaryRecords    []customdomain.DNSRecord `json:"primary_records,omitempty"`
	FallbackRecords   []customdomain.DNSRecord `json:"fallback_records,omitempty"`
	DNSNote           string                   `json:"dns_note,omitempty"`
}

type customDomainVerifyResult struct {
	Verified        bool                     `json:"verified"`
	Status          string                   `json:"status"`
	CNAMEOK         bool                     `json:"cname_ok"`
	TXTOK           bool                     `json:"txt_ok"`
	AddressOK       bool                     `json:"address_ok"`
	CNAMETarget     string                   `json:"cname_target"`
	TXTName         string                   `json:"txt_name"`
	TXTValue        string                   `json:"txt_value"`
	HTTPSOK         bool                     `json:"https_ok"`
	HTTPSError      string                   `json:"https_error"`
	Ready           bool                     `json:"ready"`
	ReadinessStatus string                   `json:"readiness_status"`
	Message         string                   `json:"message"`
	DNSMode         string                   `json:"dns_mode"`
	PrimaryRecords  []customdomain.DNSRecord `json:"primary_records,omitempty"`
	FallbackRecords []customdomain.DNSRecord `json:"fallback_records,omitempty"`
	DNSNote         string                   `json:"dns_note,omitempty"`
}

func normalizeCustomDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")
	if err := customdomain.ValidateDomain(domain); err != nil {
		return "", err
	}
	return domain, nil
}

func fetchCustomDomains(token string) ([]customDomainRecord, error) {
	b, status, err := apiRequest(http.MethodGet, "/api/cli/domains", nil, token)
	if err != nil {
		return nil, fmt.Errorf("list custom domains: %w", err)
	}
	if status != http.StatusOK {
		return nil, apiError(status, b)
	}

	var data []customDomainRecord
	if err := unwrapData(b, &data); err != nil {
		return nil, fmt.Errorf("unexpected response: %w", err)
	}
	return data, nil
}

func createCustomDomain(token, domain string) (customDomainRecord, error) {
	b, status, err := apiRequest(http.MethodPost, "/api/cli/domains", map[string]string{
		"domain": domain,
	}, token)
	if err != nil {
		return customDomainRecord{}, fmt.Errorf("create custom domain: %w", err)
	}
	if status != http.StatusCreated {
		return customDomainRecord{}, apiError(status, b)
	}

	var created customDomainRecord
	if err := unwrapData(b, &created); err != nil {
		return customDomainRecord{}, fmt.Errorf("unexpected response: %w", err)
	}
	return created, nil
}

func verifyCustomDomain(token, id string) (customDomainVerifyResult, error) {
	b, status, err := apiRequest(http.MethodPost, "/api/cli/domains/"+url.PathEscape(id)+"/verify", nil, token)
	if err != nil {
		return customDomainVerifyResult{}, fmt.Errorf("verify custom domain: %w", err)
	}
	if status != http.StatusOK {
		return customDomainVerifyResult{}, apiError(status, b)
	}

	var result customDomainVerifyResult
	if err := unwrapData(b, &result); err != nil {
		return customDomainVerifyResult{}, fmt.Errorf("unexpected response: %w", err)
	}
	return result, nil
}

func setCustomDomainTarget(token, id, subdomain string) error {
	b, status, err := apiRequest(http.MethodPatch, "/api/cli/domains/"+url.PathEscape(id)+"/target", map[string]string{
		"target_subdomain": subdomain,
	}, token)
	if err != nil {
		return fmt.Errorf("set custom domain target: %w", err)
	}
	if status != http.StatusOK {
		return apiError(status, b)
	}
	return nil
}

func findCustomDomain(list []customDomainRecord, domain string) (customDomainRecord, bool) {
	normalized, _ := normalizeCustomDomain(domain)
	for _, item := range list {
		if item.Domain == normalized {
			return item, true
		}
	}
	return customDomainRecord{}, false
}

func formatAPITimestamp(raw string) string {
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Format("2006-01-02 15:04")
}

func ensureDomainDNS(record customDomainRecord) customDomainRecord {
	if record.CNAMETarget == "" {
		record.CNAMETarget = "proxy.mekongtunnel.dev"
	}
	if record.TXTName == "" {
		record.TXTName = "_mekongtunnel-verify." + record.Domain
	}
	if record.TXTValue == "" && record.VerificationToken != "" {
		record.TXTValue = "mekong-verify=" + record.VerificationToken
	}
	if len(record.PrimaryRecords) > 0 || len(record.FallbackRecords) > 0 {
		return record
	}

	dns := customdomain.BuildDNSInstructions(record.Domain, record.CNAMETarget, record.VerificationToken, nil)
	record.DNSMode = dns.Mode
	record.PrimaryRecords = dns.PrimaryRecords
	record.FallbackRecords = dns.FallbackRecords
	record.DNSNote = dns.Note
	return record
}

func applyVerifyDNS(record customDomainRecord, result customDomainVerifyResult) customDomainRecord {
	record.CNAMETarget = result.CNAMETarget
	record.TXTName = result.TXTName
	record.TXTValue = result.TXTValue
	record.DNSMode = result.DNSMode
	record.PrimaryRecords = result.PrimaryRecords
	record.FallbackRecords = result.FallbackRecords
	record.DNSNote = result.DNSNote
	return ensureDomainDNS(record)
}

func printDNSRecords(title string, records []customdomain.DNSRecord) {
	if len(records) == 0 {
		return
	}
	fmt.Printf(gray+"  %s"+reset+"\n", title)
	fmt.Printf(gray + "  Type    Name                                Value" + reset + "\n")
	for _, record := range records {
		fmt.Printf(yellow+"  %-7s "+reset+purple+"%-35s "+reset+cyan+"%s"+reset+"\n",
			record.Type, record.Name, record.Value)
	}
}

func printCustomDomainDNS(domain customDomainRecord) {
	domain = ensureDomainDNS(domain)

	primaryTitle := "Primary DNS record"
	if domain.DNSMode == customdomain.ModeApex {
		primaryTitle = "Primary DNS records for the root domain"
	} else if domain.DNSMode == customdomain.ModeSubdomain {
		primaryTitle = "Primary DNS record for the subdomain"
	}

	printDNSRecords(primaryTitle, domain.PrimaryRecords)
	if len(domain.PrimaryRecords) > 0 && len(domain.FallbackRecords) > 0 {
		fmt.Printf("\n")
	}
	printDNSRecords("Fallback ownership record", domain.FallbackRecords)
	if domain.DNSNote != "" {
		fmt.Printf("\n")
		fmt.Printf(gray+"  Note    "+reset+purple+"%s"+reset+"\n", domain.DNSNote)
	}
}

func domainCommandUsage() string {
	return "mekong domain <add|connect|verify|wait|target|delete> ..."
}

func compactDomainWaitMessage(message string) string {
	if message == "" {
		return ""
	}
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "dns verification failed"):
		return "DNS not ready yet. Keep the required CNAME, A/AAAA, or TXT records in place."
	case strings.Contains(lower, "https") && strings.Contains(lower, "ready"):
		return "DNS is verified. Waiting for HTTPS to finish provisioning."
	default:
		return message
	}
}

func boolLabel(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func domainWaitStatusLine(attempt, maxAttempts int, result customDomainVerifyResult) string {
	return fmt.Sprintf("  Checking [%02d/%02d] stage=%s verified=%s ready=%s https=%s",
		attempt, maxAttempts, result.ReadinessStatus, boolLabel(result.Verified), boolLabel(result.Ready), boolLabel(result.HTTPSOK))
}

func doctorCNAMECheck(record customDomainRecord, cnameValue string, cnameErr error) (testResult, bool) {
	if customdomain.IsApexDomain(record.Domain) {
		return testResult{
			name:    "CNAME record",
			skipped: true,
			detail:  "root domains normally use A or AAAA records instead of CNAME",
		}, false
	}

	expected := strings.ToLower(record.CNAMETarget)
	if cnameErr == nil && cnameValue == expected {
		return testResult{
			name:   "CNAME record",
			ok:     true,
			detail: fmt.Sprintf("%s → %s", record.Domain, cnameValue),
		}, true
	}

	detail := record.CNAMETarget
	if cnameErr != nil {
		detail = cnameErr.Error()
	} else {
		detail = fmt.Sprintf("got %s, want %s", cnameValue, record.CNAMETarget)
	}
	return testResult{name: "CNAME record", detail: detail}, false
}

func doctorAddressCheck(cnameOK bool, record customDomainRecord) (testResult, bool) {
	if cnameOK {
		return testResult{
			name:    "A/AAAA record",
			skipped: true,
			detail:  "optional because the CNAME record already points to the proxy",
		}, false
	}

	domainIPs, err := net.LookupIP(record.Domain)
	if err != nil {
		return testResult{name: "A/AAAA record", detail: err.Error()}, false
	}
	targetIPs, err := net.LookupIP(record.CNAMETarget)
	if err != nil {
		return testResult{name: "A/AAAA record", detail: err.Error()}, false
	}

	targetSet := make(map[string]struct{}, len(targetIPs))
	for _, ip := range targetIPs {
		targetSet[ip.String()] = struct{}{}
	}
	for _, ip := range domainIPs {
		if _, ok := targetSet[ip.String()]; ok {
			return testResult{name: "A/AAAA record", ok: true, detail: fmt.Sprintf("%s → %s", record.Domain, ip.String())}, true
		}
	}

	got := make([]string, 0, len(domainIPs))
	for _, ip := range domainIPs {
		got = append(got, ip.String())
	}
	return testResult{name: "A/AAAA record", detail: fmt.Sprintf("got %s, want same IPs as %s", strings.Join(got, ", "), record.CNAMETarget)}, false
}

func doctorTXTCheck(dnsOK bool, record customDomainRecord, txtRecords []string, txtErr error) testResult {
	txtOK := false
	for _, rec := range txtRecords {
		if strings.Contains(rec, record.TXTValue) {
			txtOK = true
			break
		}
	}
	if txtOK {
		return testResult{name: "TXT record", ok: true, detail: record.TXTValue}
	}
	if dnsOK {
		return testResult{
			name:    "TXT record",
			skipped: true,
			detail:  "optional because the domain already verifies via CNAME or A/AAAA",
		}
	}

	detail := record.TXTValue
	if txtErr != nil {
		detail = txtErr.Error()
	}
	return testResult{name: "TXT record", detail: detail}
}

func runDomainsCommand(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: mekong domains")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	fmt.Printf(gray + "  Custom domains" + reset + "\n")
	fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	if len(list) == 0 {
		fmt.Printf(gray + "  None yet. Create one with " + reset + cyan + "mekong domain add app.example.com" + reset + "\n\n")
		return nil
	}

	for _, item := range list {
		fmt.Printf(gray+"  Domain  "+reset+yellow+"%s"+reset+"\n", item.Domain)
		fmt.Printf(gray+"  Status  "+reset+purple+"%s"+reset+"\n", item.Status)
		if item.TargetSubdomain != nil && *item.TargetSubdomain != "" {
			fmt.Printf(gray+"  Target  "+reset+yellow+"%s"+reset+"\n", *item.TargetSubdomain)
			fmt.Printf(gray+"  Route   "+reset+cyan+"mekong 3000 --subdomain %s"+reset+"\n", *item.TargetSubdomain)
		} else {
			fmt.Printf(gray + "  Target  " + reset + yellow + "(not set)" + reset + "\n")
		}
		fmt.Printf(gray+"  Verify  "+reset+cyan+"mekong domain verify %s"+reset+"\n", item.Domain)
		fmt.Printf(gray+"  Delete  "+reset+cyan+"mekong domain delete %s"+reset+"\n", item.Domain)
		fmt.Printf(gray+"  Added   "+reset+purple+"%s"+reset+"\n", formatAPITimestamp(item.CreatedAt))
		printCustomDomainDNS(item)
		fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	}
	fmt.Printf("\n")
	return nil
}

func runDomainCommand(args []string) error {
	if len(args) == 0 {
		printDomainHelp()
		return nil
	}

	switch args[0] {
	case "list", "ls":
		return runDomainsCommand(args[1:])
	case "add", "create":
		return runDomainAddCommand(args[1:])
	case "connect", "setup":
		return runDomainConnectCommand(args[1:])
	case "verify":
		return runDomainVerifyCommand(args[1:])
	case "wait":
		return runDomainWaitCommand(args[1:])
	case "target", "use", "point":
		return runDomainTargetCommand(args[1:])
	case "delete", "remove", "rm":
		return runDomainDeleteCommand(args[1:])
	default:
		return fmt.Errorf("usage: %s", domainCommandUsage())
	}
}

func runDomainAddCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong domain add <domain>")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	created, err := createCustomDomain(token, domain)
	if err != nil {
		return err
	}
	created = ensureDomainDNS(created)

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Custom domain added" + reset + "\n")
	fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", created.Domain)
	fmt.Printf(gray+"     Status  "+reset+purple+"%s"+reset+"\n", created.Status)
	fmt.Printf(gray + "     Verify  " + reset + cyan + "running initial verification check" + reset + "\n")

	if result, verifyErr := verifyCustomDomain(token, created.ID); verifyErr != nil {
		fmt.Printf(gray+"     Alert   "+reset+purple+"could not verify right now: %v"+reset+"\n", verifyErr)
		fmt.Printf(gray+"     Next    "+reset+cyan+"mekong domain verify %s"+reset+"\n", created.Domain)
		fmt.Printf(gray+"     Doctor  "+reset+cyan+"mekong doctor %s"+reset+"\n\n", created.Domain)
	} else {
		created = applyVerifyDNS(created, result)
		fmt.Printf(gray+"     Stage   "+reset+purple+"%s"+reset+"\n", result.ReadinessStatus)
		if result.Message != "" {
			fmt.Printf(gray+"     Notes   "+reset+purple+"%s"+reset+"\n", result.Message)
		}
		if result.Ready {
			fmt.Printf(gray+"     Next    "+reset+cyan+"mekong domain target %s myapp"+reset+"\n\n", created.Domain)
		} else if result.Verified {
			fmt.Printf(gray+"     Wait    "+reset+cyan+"mekong domain wait %s"+reset+"\n\n", created.Domain)
		} else {
			fmt.Printf(gray+"     Watch   "+reset+cyan+"mekong domain wait %s"+reset+"\n", created.Domain)
			fmt.Printf(gray+"     Doctor  "+reset+cyan+"mekong doctor %s"+reset+"\n\n", created.Domain)
		}
	}

	printCustomDomainDNS(created)
	fmt.Printf("\n")
	return nil
}

func runDomainVerifyCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong domain verify <domain>")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}
	target, ok := findCustomDomain(list, domain)
	if !ok {
		return fmt.Errorf("custom domain %q not found", domain)
	}

	result, err := verifyCustomDomain(token, target.ID)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	if result.Verified {
		fmt.Printf(green + "  ✔  Custom domain verified" + reset + "\n")
	} else {
		fmt.Printf(red + "  ✖  Custom domain not verified yet" + reset + "\n")
	}
	fmt.Printf(gray+"     Domain   "+reset+yellow+"%s"+reset+"\n", target.Domain)
	fmt.Printf(gray+"     Status   "+reset+purple+"%s"+reset+"\n", result.Status)
	fmt.Printf(gray+"     CNAME    "+reset+yellow+"%s"+reset+"\n", boolLabel(result.CNAMEOK))
	fmt.Printf(gray+"     Address  "+reset+yellow+"%s"+reset+"\n", boolLabel(result.AddressOK))
	fmt.Printf(gray+"     TXT      "+reset+yellow+"%s"+reset+"\n", boolLabel(result.TXTOK))
	fmt.Printf(gray+"     HTTPS    "+reset+yellow+"%s"+reset+"\n", boolLabel(result.HTTPSOK))
	fmt.Printf(gray+"     Ready    "+reset+yellow+"%s"+reset+"\n", boolLabel(result.Ready))
	fmt.Printf(gray+"     Stage    "+reset+purple+"%s"+reset+"\n", result.ReadinessStatus)
	fmt.Printf(gray+"     Message  "+reset+purple+"%s"+reset+"\n", result.Message)
	if result.Ready {
		fmt.Printf(gray+"     Next     "+reset+cyan+"mekong domain target %s myapp"+reset+"\n\n", target.Domain)
	} else if result.Verified {
		fmt.Printf(gray+"     Wait     "+reset+cyan+"mekong domain wait %s"+reset+"\n\n", target.Domain)
	} else {
		fmt.Printf(gray+"     Doctor   "+reset+cyan+"mekong doctor %s"+reset+"\n\n", target.Domain)
	}
	target = applyVerifyDNS(target, result)
	printCustomDomainDNS(target)
	fmt.Printf("\n")
	return nil
}

func runDomainWaitCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong domain wait <domain>")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}
	target, ok := findCustomDomain(list, domain)
	if !ok {
		return fmt.Errorf("custom domain %q not found", domain)
	}

	return waitForCustomDomainReady(token, target)
}

func waitForCustomDomainReady(token string, target customDomainRecord) error {
	const (
		maxAttempts = 30
		waitStep    = 3 * time.Second
	)
	target = ensureDomainDNS(target)
	var lastResult customDomainVerifyResult
	printedDNS := false

	fmt.Printf("\n")
	fmt.Printf(gray+"  Waiting for domain verification and HTTPS readiness on "+reset+yellow+"%s"+reset+"\n", target.Domain)
	fmt.Printf(gray+"  Polling every %s for up to %s\n\n"+reset, waitStep, time.Duration(maxAttempts)*waitStep)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		b, status, err := apiRequest(http.MethodPost, "/api/cli/domains/"+url.PathEscape(target.ID)+"/verify", nil, token)
		if err != nil {
			return fmt.Errorf("check custom domain readiness: %w", err)
		}
		if status != http.StatusOK {
			return apiError(status, b)
		}

		var result customDomainVerifyResult
		if err := unwrapData(b, &result); err != nil {
			return fmt.Errorf("unexpected response: %w", err)
		}
		prevResult := lastResult
		target = applyVerifyDNS(target, result)

		statusLine := domainWaitStatusLine(attempt, maxAttempts, result)
		fmt.Printf("\r\033[K%s%s%s", gray, statusLine, reset)
		message := compactDomainWaitMessage(result.Message)
		shouldPrintDetail := attempt == 1
		if attempt > 1 {
			shouldPrintDetail = prevResult.ReadinessStatus != result.ReadinessStatus || compactDomainWaitMessage(prevResult.Message) != message
		}
		if shouldPrintDetail {
			fmt.Printf("\r\033[K%s%s%s\n", gray, statusLine, reset)
			if message != "" {
				fmt.Printf(gray+"           %s"+reset+"\n", message)
			}
		}
		if !result.Verified && !printedDNS {
			fmt.Printf("\n")
			printCustomDomainDNS(target)
			fmt.Printf("\n")
			printedDNS = true
		}

		if result.Ready {
			fmt.Printf("\r\033[K")
			fmt.Printf("\n")
			fmt.Printf(green + "  ✔  Custom domain is ready" + reset + "\n")
			fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", target.Domain)
			fmt.Printf(gray+"     URL     "+reset+purple+"https://%s"+reset+"\n\n", target.Domain)
			return nil
		}

		if attempt < maxAttempts {
			time.Sleep(waitStep)
		}

		lastResult = result
	}

	fmt.Printf("\r\033[K")
	fmt.Printf("\n")
	if !lastResult.Verified {
		fmt.Printf(yellow + "  ⚠  Timed out waiting for DNS verification" + reset + "\n")
		printCustomDomainDNS(target)
		fmt.Printf("\n")
	} else {
		fmt.Printf(yellow + "  ⚠  Timed out waiting for HTTPS readiness" + reset + "\n")
	}
	fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", target.Domain)
	fmt.Printf(gray+"     Check   "+reset+cyan+"mekong doctor %s"+reset+"\n\n", target.Domain)
	return fmt.Errorf("domain %q is not ready yet", target.Domain)
}

func runDomainConnectCommand(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: mekong domain connect <domain> <reserved-subdomain>")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	subdomain, err := normalizeRequestedSubdomain(args[1])
	if err != nil {
		return err
	}
	if subdomain == "" {
		return fmt.Errorf("reserved subdomain is required")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}

	record, exists := findCustomDomain(list, domain)
	if !exists {
		record, err = createCustomDomain(token, domain)
		if err != nil {
			return err
		}
		fmt.Printf("\n")
		fmt.Printf(green + "  ✔  Custom domain added" + reset + "\n")
		fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", record.Domain)
		fmt.Printf(gray+"     Status  "+reset+purple+"%s"+reset+"\n\n", record.Status)
	} else {
		fmt.Printf("\n")
		fmt.Printf(green + "  ✔  Custom domain found" + reset + "\n")
		fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", record.Domain)
		fmt.Printf(gray+"     Status  "+reset+purple+"%s"+reset+"\n\n", record.Status)
	}

	result, err := verifyCustomDomain(token, record.ID)
	if err != nil {
		return err
	}
	record = applyVerifyDNS(record, result)

	if err := setCustomDomainTarget(token, record.ID, subdomain); err != nil {
		return err
	}
	record.TargetSubdomain = &subdomain

	fmt.Printf(green + "  ✔  Reserved target connected" + reset + "\n")
	fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", record.Domain)
	fmt.Printf(gray+"     Target  "+reset+yellow+"%s"+reset+"\n", subdomain)
	fmt.Printf(gray+"     URL     "+reset+purple+"https://%s"+reset+"\n", record.Domain)
	fmt.Printf(gray+"     Stage   "+reset+purple+"%s"+reset+"\n", result.ReadinessStatus)
	if result.Message != "" {
		fmt.Printf(gray+"     Notes   "+reset+purple+"%s"+reset+"\n", result.Message)
	}
	fmt.Printf("\n")

	if result.Ready {
		fmt.Printf(green + "  ✔  Custom domain is ready" + reset + "\n")
		fmt.Printf(gray+"     Use     "+reset+cyan+"mekong 3000 --subdomain %s"+reset+"\n", subdomain)
		fmt.Printf(gray+"     URL     "+reset+purple+"https://%s"+reset+"\n\n", record.Domain)
		return nil
	}

	return waitForCustomDomainReady(token, record)
}

func runDomainTargetCommand(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: mekong domain target <domain> <reserved-subdomain>")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	subdomain, err := normalizeRequestedSubdomain(args[1])
	if err != nil {
		return err
	}
	if subdomain == "" {
		return fmt.Errorf("reserved subdomain is required")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}
	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}
	target, ok := findCustomDomain(list, domain)
	if !ok {
		return fmt.Errorf("custom domain %q not found", domain)
	}

	if err := setCustomDomainTarget(token, target.ID, subdomain); err != nil {
		return err
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Custom domain target updated" + reset + "\n")
	fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", domain)
	fmt.Printf(gray+"     Target  "+reset+yellow+"%s"+reset+"\n", subdomain)
	fmt.Printf(gray+"     Use     "+reset+cyan+"mekong 3000 --subdomain %s"+reset+"\n", subdomain)
	fmt.Printf(gray+"     URL     "+reset+purple+"https://%s"+reset+"\n\n", domain)
	return nil
}

func runDomainDeleteCommand(args []string) error {
	yes, args := parseYesFlag(args)
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong domain delete <domain> [--yes]")
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		return err
	}
	token, err := requireAPIToken("")
	if err != nil {
		return err
	}
	list, err := fetchCustomDomains(token)
	if err != nil {
		return err
	}
	target, ok := findCustomDomain(list, domain)
	if !ok {
		return fmt.Errorf("custom domain %q not found", domain)
	}

	if !yes {
		if !confirmPrompt(fmt.Sprintf("Delete custom domain %q?", domain)) {
			fmt.Printf("  Aborted.\n\n")
			return nil
		}
	}

	_, status, err := apiRequest(http.MethodDelete, "/api/cli/domains/"+url.PathEscape(target.ID), nil, token)
	if err != nil {
		return fmt.Errorf("delete custom domain: %w", err)
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("delete custom domain: server returned %d", status)
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Custom domain deleted" + reset + "\n")
	fmt.Printf(gray+"     Domain  "+reset+yellow+"%s"+reset+"\n", domain)
	if target.TargetSubdomain != nil && *target.TargetSubdomain != "" {
		fmt.Printf(gray+"     Target  "+reset+yellow+"%s"+reset+"\n", *target.TargetSubdomain)
	}
	fmt.Printf(gray + "     Route   " + reset + purple + "removed from MekongTunnel" + reset + "\n")
	fmt.Printf(gray + "     DNS     " + reset + purple + "not changed at your DNS provider" + reset + "\n")
	fmt.Printf(gray + "     HTTPS   " + reset + purple + "the app route is removed; if DNS still points here, a shared or existing certificate may still validate, but the hostname will no longer route to your app" + reset + "\n")
	fmt.Printf(gray + "     Cleanup " + reset + cyan + "remove or change the DNS record if you want the hostname fully disconnected" + reset + "\n\n")
	return nil
}

func runDoctorCommand(args []string, apiToken string) int {
	if len(args) == 0 {
		return runSelfTest(apiToken)
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "  error: usage: mekong doctor [domain]")
		return 1
	}

	domain, err := normalizeCustomDomain(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		return 1
	}
	if apiToken == "" {
		fmt.Fprintln(os.Stderr, "  error: no API token found; run 'mekong login' first")
		return 1
	}

	list, err := fetchCustomDomains(apiToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		return 1
	}
	record, ok := findCustomDomain(list, domain)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error: custom domain %q not found\n", domain)
		return 1
	}

	fmt.Println()
	fmt.Printf("  Mekong Custom Domain Doctor — %s\n", record.Domain)
	fmt.Println("  ──────────────────────────────────────────")
	fmt.Println()

	cnameValue, cnameErr := net.LookupCNAME(record.Domain)
	cnameValue = strings.TrimSuffix(strings.ToLower(cnameValue), ".")
	txtRecords, txtErr := net.LookupTXT(record.TXTName)

	results := []testResult{
		{name: "Domain exists in your account", ok: true, detail: fmt.Sprintf("status=%s", record.Status)},
	}

	cnameResult, cnameOK := doctorCNAMECheck(record, cnameValue, cnameErr)
	results = append(results, cnameResult)
	addressResult, addressOK := doctorAddressCheck(cnameOK, record)
	results = append(results, addressResult)
	results = append(results, doctorTXTCheck(cnameOK || addressOK, record, txtRecords, txtErr))

	verifyResp, verifyStatus, err := apiRequest(http.MethodPost, "/api/cli/domains/"+url.PathEscape(record.ID)+"/verify", nil, apiToken)
	if err != nil {
		results = append(results, testResult{name: "API verification", detail: err.Error()})
	} else if verifyStatus != http.StatusOK {
		results = append(results, testResult{name: "API verification", detail: apiError(verifyStatus, verifyResp).Error()})
	} else {
		var verifyResult customDomainVerifyResult
		if err := unwrapData(verifyResp, &verifyResult); err != nil {
			results = append(results, testResult{name: "API verification", detail: err.Error()})
		} else {
			record.Status = verifyResult.Status
			results = append(results, testResult{name: "API verification", ok: verifyResult.Verified, detail: verifyResult.Message})
		}
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://" + record.Domain)
	if err != nil {
		results = append(results, testResult{name: "HTTPS reachability", detail: err.Error()})
	} else {
		_ = resp.Body.Close()
		results = append(results, testResult{name: "HTTPS reachability", ok: resp.StatusCode < 500, detail: fmt.Sprintf("HTTP %d", resp.StatusCode)})
	}

	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		r.print()
		if r.skipped {
			skipped++
		} else if r.ok {
			passed++
		} else {
			failed++
		}
	}

	fmt.Println()
	fmt.Println("  DNS records to copy")
	fmt.Println("  ──────────────────────────────────────────")
	fmt.Println()
	printCustomDomainDNS(record)
	fmt.Println()
	fmt.Printf("  Results: %d passed · %d failed · %d skipped\n\n", passed, failed, skipped)

	if failed > 0 {
		return 1
	}
	return 0
}
