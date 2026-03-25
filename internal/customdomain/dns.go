package customdomain

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	ModeApex      = "apex"
	ModeSubdomain = "subdomain"
)

type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	FQDN  string `json:"fqdn,omitempty"`
}

type DNSInstructions struct {
	Mode            string      `json:"dns_mode"`
	PrimaryRecords  []DNSRecord `json:"primary_records,omitempty"`
	FallbackRecords []DNSRecord `json:"fallback_records,omitempty"`
	Note            string      `json:"dns_note,omitempty"`
}

type LookupIPFunc func(host string) ([]net.IP, error)

var commonMultiLabelSuffixes = map[string]struct{}{
	"ac.jp":  {},
	"ac.uk":  {},
	"co.jp":  {},
	"co.uk":  {},
	"com.au": {},
	"com.br": {},
	"com.kh": {},
	"com.mx": {},
	"com.sg": {},
	"edu.kh": {},
	"gov.kh": {},
	"net.au": {},
	"org.au": {},
	"org.kh": {},
	"org.uk": {},
}

func BuildDNSInstructions(domain, cnameTarget, verificationToken string, lookupIP LookupIPFunc) DNSInstructions {
	domain = normalizeDomain(domain)
	name := relativeRecordName(domain)
	txtName := prefixedRecordName(domain, "_mekongtunnel-verify")
	txtValue := "mekong-verify=" + verificationToken
	txtFQDN := "_mekongtunnel-verify." + domain

	instructions := DNSInstructions{
		FallbackRecords: []DNSRecord{{
			Type:  "TXT",
			Name:  txtName,
			Value: txtValue,
			FQDN:  txtFQDN,
		}},
	}

	if IsApexDomain(domain) {
		instructions.Mode = ModeApex
		instructions.PrimaryRecords = buildAddressRecords(name, domain, cnameTarget, lookupIP)
		if len(instructions.PrimaryRecords) == 0 {
			instructions.PrimaryRecords = []DNSRecord{{
				Type:  "A",
				Name:  name,
				Value: "same IP as " + cnameTarget,
				FQDN:  domain,
			}}
		}
		instructions.Note = "Root domains usually use A or AAAA records. If your DNS provider does not accept @, enter the full domain name instead."
		return instructions
	}

	instructions.Mode = ModeSubdomain
	instructions.PrimaryRecords = []DNSRecord{{
		Type:  "CNAME",
		Name:  name,
		Value: cnameTarget,
		FQDN:  domain,
	}}
	instructions.Note = "The Name column is relative to your DNS zone. If your DNS provider asks for a full host, enter the full domain name instead."
	return instructions
}

func IsApexDomain(domain string) bool {
	_, name := zoneAndRecordName(domain)
	return name == "@"
}

func ValidateDomain(domain string) error {
	domain = normalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("invalid domain name")
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return fmt.Errorf("invalid domain name")
	}
	if len(domain) > 253 {
		return fmt.Errorf("invalid domain name")
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("invalid domain name")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid domain name")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid domain name")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("invalid domain name")
			}
		}
	}
	return nil
}

func normalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(domain), ". ")
}

func buildAddressRecords(name, fqdn, target string, lookupIP LookupIPFunc) []DNSRecord {
	if lookupIP == nil {
		lookupIP = net.LookupIP
	}
	ips, err := lookupIP(target)
	if err != nil {
		return nil
	}

	v4 := make([]string, 0, len(ips))
	v6 := make([]string, 0, len(ips))
	seen4 := make(map[string]struct{}, len(ips))
	seen6 := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			s := ipv4.String()
			if _, ok := seen4[s]; ok {
				continue
			}
			seen4[s] = struct{}{}
			v4 = append(v4, s)
			continue
		}
		s := ip.String()
		if _, ok := seen6[s]; ok {
			continue
		}
		seen6[s] = struct{}{}
		v6 = append(v6, s)
	}

	sort.Strings(v4)
	sort.Strings(v6)

	records := make([]DNSRecord, 0, len(v4)+len(v6))
	for _, ip := range v4 {
		records = append(records, DNSRecord{
			Type:  "A",
			Name:  name,
			Value: ip,
			FQDN:  fqdn,
		})
	}
	for _, ip := range v6 {
		records = append(records, DNSRecord{
			Type:  "AAAA",
			Name:  name,
			Value: ip,
			FQDN:  fqdn,
		})
	}
	return records
}

func prefixedRecordName(domain, prefix string) string {
	name := relativeRecordName(domain)
	if name == "@" {
		return prefix
	}
	return prefix + "." + name
}

func relativeRecordName(domain string) string {
	_, name := zoneAndRecordName(domain)
	return name
}

func zoneAndRecordName(domain string) (zone string, name string) {
	domain = normalizeDomain(domain)
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return domain, domain
	}

	zoneLen := 2
	if len(labels) >= 3 {
		suffix := strings.Join(labels[len(labels)-2:], ".")
		if _, ok := commonMultiLabelSuffixes[suffix]; ok {
			zoneLen = 3
		}
	}
	if len(labels) <= zoneLen {
		return domain, "@"
	}

	return strings.Join(labels[len(labels)-zoneLen:], "."), strings.Join(labels[:len(labels)-zoneLen], ".")
}
