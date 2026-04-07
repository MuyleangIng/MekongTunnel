package handlers

import (
	"strings"
	"testing"
)

func TestRenderNewsletterBodyHTMLReplacesUnsubscribePlaceholders(t *testing.T) {
	const token = "preview-token"
	html, autoAppended := renderNewsletterBodyHTML(
		"https://angkorsearch.dev",
		`<p>Hello</p><a href="{{unsubscribe_url}}">Unsubscribe</a><span>{{unsubscribe_token}}</span>`,
		token,
	)

	if autoAppended {
		t.Fatalf("autoAppended = true, want false")
	}
	if strings.Contains(html, newsletterPlaceholderUnsubscribeURL) || strings.Contains(html, newsletterPlaceholderUnsubscribeToken) {
		t.Fatalf("expected placeholders to be replaced, got %q", html)
	}
	if !strings.Contains(html, "/unsubscribe?token="+token) {
		t.Fatalf("expected unsubscribe token in rendered html, got %q", html)
	}
}

func TestRenderNewsletterBodyHTMLAutoAppendsFooterBeforeClosingBody(t *testing.T) {
	const token = "preview-token"
	html, autoAppended := renderNewsletterBodyHTML(
		"https://angkorsearch.dev",
		`<html><body><p>Hello</p></body></html>`,
		token,
	)

	if !autoAppended {
		t.Fatalf("autoAppended = false, want true")
	}
	if !strings.Contains(html, "/unsubscribe?token="+token) {
		t.Fatalf("expected unsubscribe footer, got %q", html)
	}
	if strings.Index(html, "/unsubscribe?token="+token) > strings.Index(strings.ToLower(html), "</body>") {
		t.Fatalf("expected footer before closing body, got %q", html)
	}
}
