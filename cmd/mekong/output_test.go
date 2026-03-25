package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	outCh := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		outCh <- b.String()
	}()

	fn()
	_ = w.Close()
	out := <-outCh
	_ = r.Close()
	return out
}

func TestStreamOutputSuppressesDuplicateServerBanner(t *testing.T) {
	input := "\r\n" +
		"\033[1;36m  ███╗   ███╗███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗ \033[0m\r\n" +
		"  ████╗ ████║██╔════╝██║ ██╔╝██╔═══██╗████╗  ██║██╔════╝ \r\n" +
		"\033[38;5;245m  by \033[1;33mIng Muyleang\033[38;5;245m · Founder of \033[1;33mKhmerStack\033[0m\r\n" +
		"\033[38;5;245m  ─────────────────────────────────────────────────────\033[0m\r\n" +
		"\033[1;32m  ✔  Tunnel is live!\033[0m\r\n" +
		"\033[38;5;245m     URL      \033[38;5;141mhttps://myapp.proxy.angkorsearch.dev\033[0m\r\n" +
		"\033[38;5;245m     Expires  Mar 25, 2026 at 16:55 UTC (or 1d idle)\033[0m\r\n"

	urlCh := make(chan string, 1)
	done := make(chan struct{})
	var status streamStatus

	output := captureStdout(t, func() {
		streamOutput(strings.NewReader(input), urlCh, &status, done, "")
		<-done
	})

	if strings.Contains(output, "███╗") {
		t.Fatalf("output should not contain duplicated ASCII banner: %q", output)
	}
	if strings.Contains(output, "Founder of KhmerStack") {
		t.Fatalf("output should not contain duplicated author line: %q", output)
	}
	if !strings.Contains(output, "Tunnel is live!") {
		t.Fatalf("output should keep tunnel status line: %q", output)
	}
	if !strings.Contains(output, "https://myapp.proxy.angkorsearch.dev") {
		t.Fatalf("output should keep tunnel URL: %q", output)
	}

	gotURL, ok := <-urlCh
	if !ok {
		t.Fatal("urlCh closed without yielding the tunnel URL")
	}
	if gotURL != "https://myapp.proxy.angkorsearch.dev" {
		t.Fatalf("url = %q, want %q", gotURL, "https://myapp.proxy.angkorsearch.dev")
	}
}
