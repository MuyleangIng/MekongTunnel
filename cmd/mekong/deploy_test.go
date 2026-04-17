package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── parseDeployFlags — pure unit tests (no auth, no network) ─────────────────

func TestParseFlagsHelp(t *testing.T) {
	for _, a := range []string{"-h", "--help", "help", "?"} {
		// Help is handled before parseDeployFlags; just check runDeployCommand returns nil
		err := runDeployCommand([]string{a})
		if err != nil {
			t.Errorf("help flag %q returned error: %v", a, err)
		}
	}
}

func TestParseFlagsExpireValid(t *testing.T) {
	cases := []struct{ arg, want string }{
		{"30m", "30m"},
		{"1h", "1h"},
		{"48h", "48h"},
		{"134", "134"},   // bare hours
		{"1d", "1d"},
		{"7d", "7d"},
		{"14d", "14d"},
		{"1w", "1w"},
		{"2w", "2w"},
		{"1mo", "1mo"},
		{"6mo", "6mo"},
		{"12mo", "12mo"},
	}
	for _, c := range cases {
		f, err := parseDeployFlags([]string{"--expire", c.arg, "."})
		if err != nil {
			t.Errorf("--expire %s: unexpected error: %v", c.arg, err)
			continue
		}
		if f.Expire != c.want {
			t.Errorf("--expire %s: Expire=%q, want %q", c.arg, f.Expire, c.want)
		}
	}
}

func TestParseFlagsExpireEqualForm(t *testing.T) {
	f, err := parseDeployFlags([]string{"--expire=7d", "."})
	if err != nil || f.Expire != "7d" {
		t.Errorf("--expire=7d: err=%v Expire=%q", err, f.Expire)
	}
}

func TestParseFlagsExpireInvalidFormat(t *testing.T) {
	bad := []string{
		"1mdadasd", "banana", "abc123", "???",
		"week", "month",   // bare units without number
		"0", "0d", "0h",   // zero
		"-1h", "-7d",       // negative
		"1xz",              // unknown unit
		"",                 // empty (via --expire=)
	}
	for _, v := range bad {
		var f deployFlags
		var err error
		if v == "" {
			f, err = parseDeployFlags([]string{"--expire=", "."})
		} else {
			f, err = parseDeployFlags([]string{"--expire", v, "."})
		}
		_ = f
		if err == nil {
			t.Errorf("--expire %q should fail but got no error", v)
		}
	}
}

func TestParseFlagsExpireTooShort(t *testing.T) {
	cases := []string{
		"1min",    // 1 minute
		"5min",    // 5 minutes
		"29min",   // 29 minutes — just under 30m limit
	}
	for _, v := range cases {
		_, err := parseDeployFlags([]string{"--expire", v, "."})
		if err == nil {
			t.Errorf("--expire %q should be too short but got no error", v)
		} else if !strings.Contains(err.Error(), "too short") {
			t.Errorf("--expire %q: expected 'too short' error, got: %v", v, err)
		}
	}
}

func TestParseFlagsExpireTooLong(t *testing.T) {
	cases := []string{
		"13444",  // hours >> 1 year
		"400d",   // 400 days
		"53w",    // 53 weeks
		"13mo",   // 13 months
	}
	for _, v := range cases {
		_, err := parseDeployFlags([]string{"--expire", v, "."})
		if err == nil {
			t.Errorf("--expire %q should be too long but got no error", v)
		} else if !strings.Contains(err.Error(), "too long") {
			t.Errorf("--expire %q: expected 'too long' error, got: %v", v, err)
		}
	}
}

func TestParseFlagsExpireMissingValue(t *testing.T) {
	cases := [][]string{
		{"--expire"},                  // nothing after
		{"-e"},                        // nothing after
		{"--expire", "--all"},         // next is a flag
		{"-e", "-a"},                  // next is a flag
		{"--expire="},                 // empty = form
	}
	for _, args := range cases {
		_, err := parseDeployFlags(args)
		if err == nil {
			t.Errorf("args %v should fail but got no error", args)
		} else if !strings.Contains(err.Error(), "--expire") {
			t.Errorf("args %v: error should mention --expire, got: %v", args, err)
		}
	}
}

func TestParseFlagsExpireDuplicateRejected(t *testing.T) {
	cases := [][]string{
		{"-e", "7d", ".", "-e", "1900"},
		{"--expire", "7d", "--expire", "2w"},
		{"-e", "1d", "--expire=2d"},
	}
	for _, args := range cases {
		_, err := parseDeployFlags(args)
		if err == nil {
			t.Errorf("duplicate --expire %v should fail but got no error", args)
		} else if !strings.Contains(err.Error(), "once") {
			t.Errorf("duplicate --expire %v: expected 'once' error, got: %v", args, err)
		}
	}
}

func TestParseFlagsAllFlag(t *testing.T) {
	for _, a := range []string{"--all", "-a"} {
		f, err := parseDeployFlags([]string{a, "stop"})
		if err != nil {
			t.Errorf("%s: unexpected error: %v", a, err)
		}
		if !f.All {
			t.Errorf("%s: All should be true", a)
		}
	}
}

func TestParseFlagsPositionalArgs(t *testing.T) {
	f, err := parseDeployFlags([]string{"-e", "7d", "./mydir"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Expire != "7d" {
		t.Errorf("Expire=%q want 7d", f.Expire)
	}
	if len(f.Args) != 1 || f.Args[0] != "./mydir" {
		t.Errorf("Args=%v want [./mydir]", f.Args)
	}
}

// ── runDeployCommand — subcommand usage errors (no auth needed for these) ─────

func runDeploy(args ...string) string {
	err := runDeployCommand(args)
	if err == nil {
		return ""
	}
	return err.Error()
}

func errContains(t *testing.T, label, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("[%s]\n  got:  %q\n  want: contains %q", label, got, want)
	}
}

func TestDeployStopMissingSubdomain(t *testing.T) {
	got := runDeploy("stop")
	errContains(t, "stop missing subdomain", got, "usage: mekong deploy stop")
}

func TestDeployDeleteMissingSubdomain(t *testing.T) {
	for _, cmd := range []string{"delete", "rm", "del"} {
		got := runDeploy(cmd)
		errContains(t, cmd+" missing subdomain", got, "usage: mekong deploy delete")
	}
}

func TestDeployLogMissingSubdomain(t *testing.T) {
	for _, cmd := range []string{"log", "logs"} {
		got := runDeploy(cmd)
		errContains(t, cmd+" missing subdomain", got, "usage: mekong deploy log")
	}
}

func TestDeployRedeployMissingArgs(t *testing.T) {
	for _, cmd := range []string{"redeploy", "update", "push"} {
		got := runDeploy(cmd)
		errContains(t, cmd+" missing args", got, "usage: mekong deploy redeploy")

		got2 := runDeploy(cmd, "mysite") // missing path
		errContains(t, cmd+" missing path", got2, "usage: mekong deploy redeploy")
	}
}

func TestDeployOpenMissingSubdomain(t *testing.T) {
	errContains(t, "open", runDeploy("open"), "usage: mekong deploy open")
}

func TestDeployInfoMissingSubdomain(t *testing.T) {
	for _, cmd := range []string{"info", "status"} {
		errContains(t, cmd, runDeploy(cmd), "usage: mekong deploy info")
	}
}

// ── Random garbage — must never panic ────────────────────────────────────────

func TestDeployRandomInputsNoPanic(t *testing.T) {
	inputs := [][]string{
		{},
		{""},
		{"@@@"},
		{"--"},
		{"---expire"},
		{"--expire", "--expire"},
		{"-e", "-e"},
		{strings.Repeat("a", 500)},
		{"--expire", strings.Repeat("x", 500)},
		{"-e", "9999999999999d"},
		{"-e", "0.0001h"},
		{"stop", "x", "y", "z"},
		{"delete", "", ""},
		{"log", ""},
		{"info", ""},
		{"open", ""},
		{"redeploy", "x"},
	}
	for _, args := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on args %v: %v", args, r)
				}
			}()
			_ = runDeployCommand(args)
		}()
	}
}

// ── zipDir ────────────────────────────────────────────────────────────────────

func TestZipDirEmpty(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	n, err := zipDir(dir, &b, "static")
	if err != nil {
		t.Fatalf("zipDir empty: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 files, got %d", n)
	}
}

func TestZipDirSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Hi</h1>"), 0644)
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("x"), 0644)
	var b strings.Builder
	n, err := zipDir(dir, &b, "static")
	if err != nil {
		t.Fatalf("zipDir: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 file (node_modules skipped), got %d", n)
	}
}

func TestZipDirSkipsHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Hi</h1>"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0644)
	os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte(""), 0644)
	var b strings.Builder
	n, err := zipDir(dir, &b, "static")
	if err != nil {
		t.Fatalf("zipDir: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 file (.env .DS_Store skipped), got %d", n)
	}
}

// ── detectDeployType ──────────────────────────────────────────────────────────

func TestDetectStatic(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Hi</h1>"), 0644)
	if d := detectDeployType(dir); d.Type != "static" {
		t.Errorf("got %q want static", d.Type)
	}
}

func TestDetectDocs(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644)
	os.WriteFile(filepath.Join(dir, "guide.md"), []byte("# Guide"), 0644)
	if d := detectDeployType(dir); d.Type != "docs" {
		t.Errorf("got %q want docs", d.Type)
	}
}

func TestDetectDocsWithIndexHTML(t *testing.T) {
	// index.html present → static, not docs
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Hi</h1>"), 0644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644)
	if d := detectDeployType(dir); d.Type != "static" {
		t.Errorf("got %q want static (index.html overrides .md)", d.Type)
	}
}

func TestDetectPHP(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php echo 1; ?>"), 0644)
	if d := detectDeployType(dir); d.Type != "php" {
		t.Errorf("got %q want php", d.Type)
	}
}

func TestDetectNextJS(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".next"), 0755)
	if d := detectDeployType(dir); d.Type != "nextjs" {
		t.Errorf("got %q want nextjs", d.Type)
	}
}

func TestDetectNextJSWithAPI(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".next"), 0755)
	os.MkdirAll(filepath.Join(dir, "pages", "api"), 0755)
	if d := detectDeployType(dir); d.Type != "nextjs-api" {
		t.Errorf("got %q want nextjs-api", d.Type)
	}
}

func TestDetectVue(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vue.config.js"), []byte("module.exports={}"), 0644)
	if d := detectDeployType(dir); d.Type != "vue" {
		t.Errorf("got %q want vue", d.Type)
	}
}

func TestDetectReactVite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vite.config.ts"), []byte("export default {}"), 0644)
	if d := detectDeployType(dir); d.Type != "react-vite" {
		t.Errorf("got %q want react-vite", d.Type)
	}
}

// ── fmtBytes ──────────────────────────────────────────────────────────────────

func TestFmtBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{100 * 1024 * 1024, "100.0 MB"},
	}
	for _, c := range cases {
		if got := fmtBytes(c.in); got != c.want {
			t.Errorf("fmtBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
