// Package domain generates and validates memorable random subdomains
// in the format adjective-noun-hexsuffix (e.g. "happy-tiger-a1b2c3d4").
//
// Entropy: 32 adjectives × 32 nouns × 4,294,967,296 hex values ≈ 4.4 trillion unique subdomains.
// Validation uses a strict whitelist to prevent injection or enumeration attacks.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// adjectives is the whitelist of allowed adjective words used in subdomain generation.
var adjectives = []string{
	"happy", "sunny", "swift", "calm", "bold", "bright", "cool", "warm",
	"quick", "clever", "brave", "gentle", "kind", "proud", "wise", "keen",
	"fresh", "crisp", "pure", "clear", "wild", "free", "silent", "quiet",
	"golden", "silver", "coral", "amber", "jade", "ruby", "pearl", "onyx",
}

// nouns is the whitelist of allowed noun words used in subdomain generation.
var nouns = []string{
	"tiger", "eagle", "wolf", "bear", "hawk", "fox", "deer", "owl",
	"river", "mountain", "forest", "ocean", "meadow", "valley", "canyon", "island",
	"star", "moon", "cloud", "storm", "wind", "flame", "wave", "stone",
	"maple", "cedar", "pine", "oak", "willow", "birch", "aspen", "elm",
}

// Generate creates a cryptographically random memorable subdomain.
// Format: <adjective>-<noun>-<8 hex chars>
// Example: "happy-tiger-a1b2c3d4"
//
// All random bytes come from crypto/rand so the output is safe to use as
// a public identifier without predictability concerns.
func Generate() (string, error) {
	adjIdx := make([]byte, 1)
	nounIdx := make([]byte, 1)
	hexBytes := make([]byte, 4) // 4 bytes = 8 hex chars

	if _, err := rand.Read(adjIdx); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	if _, err := rand.Read(nounIdx); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	if _, err := rand.Read(hexBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	adj := adjectives[int(adjIdx[0])%len(adjectives)]
	noun := nouns[int(nounIdx[0])%len(nouns)]
	hexSuffix := hex.EncodeToString(hexBytes)

	return fmt.Sprintf("%s-%s-%s", adj, noun, hexSuffix), nil
}

// IsValid returns true if s is a validly formatted subdomain produced by Generate.
// It checks that:
//  1. The string has exactly three dash-separated parts
//  2. Part 0 is in the adjectives whitelist
//  3. Part 1 is in the nouns whitelist
//  4. Part 2 is exactly 8 lowercase hexadecimal characters
//
// This strict whitelist validation prevents path-traversal and injection attacks.
func IsValid(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}

	adjValid := false
	for _, adj := range adjectives {
		if parts[0] == adj {
			adjValid = true
			break
		}
	}
	if !adjValid {
		return false
	}

	nounValid := false
	for _, noun := range nouns {
		if parts[1] == noun {
			nounValid = true
			break
		}
	}
	if !nounValid {
		return false
	}

	if len(parts[2]) != 8 {
		return false
	}
	for _, c := range parts[2] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}
