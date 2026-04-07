// mekong — CLI client for MekongTunnel.
// Exposes a local port to the internet via MekongTunnel:
//
//	mekong 3000
//	mekong -d 3000          (background/daemon mode)
//	mekong logs             (show daemon logs)
//	mekong logs -f          (follow daemon logs)
//	mekong status           (show your active tunnels)
//	mekong status 3000      (filter by port)
//	mekong stop 3000        (stop one background tunnel)
//	mekong stop --all       (stop all background tunnels)
//
// Features: auto-reconnect, QR code, clipboard copy, daemon mode, logs, and per-port stop commands.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"github.com/mdp/qrterminal/v3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/expiry"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

const daemonEnvName = "MEKONG_DAEMON"

const (
	updateHTTPTimeout = 2 * time.Minute
	updateMaxAttempts = 3
	localDialTimeout  = time.Second
)

// errBlocked is returned by connect() when the server reports the IP is blocked.
var errBlocked = errors.New("IP is blocked")

// errExpired is returned by connect() when the server closes the tunnel because it expired.
var errExpired = errors.New("Tunnel expired")

// errExpireUnsupported is returned when the server does not support expiry requests yet.
var errExpireUnsupported = errors.New("Server does not support tunnel expiry yet")

const (
	reset  = "\033[0m"
	cyan   = "\033[1;36m"
	yellow = "\033[1;33m"
	green  = "\033[1;32m"
	gray   = "\033[38;5;245m"
	purple = "\033[38;5;141m"
	red    = "\033[1;31m"
)

var (
	ansiRe    = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	urlRe     = regexp.MustCompile(`https?://[^\s\r\n]+`)
	localDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, address, timeout)
	}
)

// tcpIPForwardReq is the SSH wire payload for the "tcpip-forward" global request.
type tcpIPForwardReq struct {
	BindAddr string
	BindPort uint32
}

// forwardedTCPIPData is the SSH wire payload for the "forwarded-tcpip" channel open.
type forwardedTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// ---- state file ----

type tunnelState struct {
	PID       int       `json:"pid,omitempty"`
	URL       string    `json:"url"`
	LocalPort int       `json:"local_port"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// stateFile is the legacy aggregate daemon state format kept for compatibility.
type stateFile struct {
	PID     int           `json:"pid"`
	Tunnels []tunnelState `json:"tunnels"`
}

func mekongDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".mekong"
	}
	return filepath.Join(home, ".mekong")
}

func stateFilePath() string { return filepath.Join(mekongDir(), "state.json") }
func logFilePath() string   { return filepath.Join(mekongDir(), "mekong.log") }
func tunnelStateDir() string {
	return filepath.Join(mekongDir(), "tunnels")
}
func tunnelStatePath(port int) string {
	return filepath.Join(tunnelStateDir(), fmt.Sprintf("%d.json", port))
}

func writeState(s stateFile) {
	_ = os.MkdirAll(mekongDir(), 0755)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(stateFilePath(), b, 0600)
}

func removeState() { _ = os.Remove(stateFilePath()) }

func readTunnelStateForPort(port int) (tunnelState, error) {
	b, err := os.ReadFile(tunnelStatePath(port))
	if err != nil {
		return tunnelState{}, err
	}
	var ts tunnelState
	return ts, json.Unmarshal(b, &ts)
}

func writeTunnelState(ts tunnelState) {
	_ = os.MkdirAll(tunnelStateDir(), 0755)
	b, _ := json.MarshalIndent(ts, "", "  ")
	_ = os.WriteFile(tunnelStatePath(ts.LocalPort), b, 0600)
}

func removeTunnelStateFile(localPort int) {
	_ = os.Remove(tunnelStatePath(localPort))
}

func removePIDStateFiles(pid int, states []tunnelState) {
	for _, t := range states {
		if t.PID == pid {
			removeTunnelStateFile(t.LocalPort)
		}
	}
	removeState()
}

func removeTunnelFromState(localPort int, s *stateFile, mu *sync.Mutex) {
	removeTunnelStateFile(localPort)

	mu.Lock()
	defer mu.Unlock()
	filtered := s.Tunnels[:0]
	for _, t := range s.Tunnels {
		if t.LocalPort != localPort {
			filtered = append(filtered, t)
		}
	}
	s.Tunnels = filtered
}

func readState() (stateFile, error) {
	b, err := os.ReadFile(stateFilePath())
	if err != nil {
		return stateFile{}, err
	}
	var s stateFile
	return s, json.Unmarshal(b, &s)
}

func readTunnelStates() ([]tunnelState, error) {
	entries, err := os.ReadDir(tunnelStateDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	states := make([]tunnelState, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		b, err := os.ReadFile(filepath.Join(tunnelStateDir(), entry.Name()))
		if err != nil {
			continue
		}

		var ts tunnelState
		if err := json.Unmarshal(b, &ts); err != nil {
			continue
		}
		states = append(states, ts)
	}
	return states, nil
}

func readActiveTunnelStates() ([]tunnelState, error) {
	states, err := readTunnelStates()
	if err != nil {
		return nil, err
	}
	if len(states) > 0 {
		return states, nil
	}

	legacy, err := readState()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	states = make([]tunnelState, 0, len(legacy.Tunnels))
	for _, ts := range legacy.Tunnels {
		if ts.PID == 0 {
			ts.PID = legacy.PID
		}
		states = append(states, ts)
	}
	return states, nil
}

// isPIDAlive is defined in platform_unix.go / platform_windows.go

func resolveTunnelSessionToken(apiToken, requestedSubdomain string) string {
	if strings.TrimSpace(requestedSubdomain) == "" {
		return ""
	}
	return strings.TrimSpace(apiToken)
}

// reorderArgs moves flags (and their values) before positional arguments so
// that flag.Parse() works regardless of where flags appear on the command line.
// e.g. ["3000", "--no-qr"] → ["--no-qr", "3000"]
func reorderArgs(args []string) []string {
	// Flags that consume the next token as their value.
	valueFlags := map[string]bool{
		"--server": true, "-server": true,
		"--ssh-port": true, "-ssh-port": true,
		"--port": true, "-port": true,
		"--expire": true, "-expire": true,
		"--subdomain": true, "-subdomain": true,
		"--token": true, "-token": true,
		"--upstream-host": true,
		"--host-header":   true,
		"-e":              true,
		"-p":              true,
		"-sd":             true,
	}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && !strings.Contains(a, "=") {
			flags = append(flags, a)
			if valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

// ---- command prefix resolver + typo suggestions ----

var knownCommands = []string{
	"logs", "status", "ps", "stop", "update", "login", "logout", "whoami",
	"subdomains", "subdomain", "domains", "domain", "help", "detect", "init",
	"reserve", "delete", "unreserve", "test", "doctor", "version", "rm",
	"completion", "sd", "dm",
}

// resolveCommand returns the full command name for the given input, supporting
// unique prefix matching (e.g. "dom" → "domain", "sub" → "subdomain").
// If the input matches exactly or is ambiguous / unknown, it is returned as-is.
func resolveCommand(input string) string {
	for _, cmd := range knownCommands {
		if cmd == input {
			return cmd
		}
	}
	var matches []string
	for _, cmd := range knownCommands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return input
}

// levenshtein returns the edit distance between two strings.
func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	row := make([]int, len(b)+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= len(a); i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= len(b); j++ {
			tmp := row[j]
			if a[i-1] == b[j-1] {
				row[j] = prev
			} else {
				row[j] = 1 + minInt(prev, minInt(row[j], row[j-1]))
			}
			prev = tmp
		}
	}
	return row[len(b)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// suggestCommand returns the closest known command if within edit distance 2.
func suggestCommand(input string) string {
	candidates := []string{
		"logs", "status", "ps", "stop", "update", "login", "logout", "whoami",
		"subdomain", "domain", "help", "detect", "init", "doctor", "version", "rm",
	}
	best, bestDist := "", 999
	for _, cmd := range candidates {
		if d := levenshtein(input, cmd); d < bestDist {
			bestDist = d
			best = cmd
		}
	}
	if bestDist <= 2 {
		return best
	}
	return ""
}

// isRandomSubdomain returns true for auto-generated adjective-noun-8hex names.
var randomSubRe = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9a-f]{8}$`)

func isRandomSubdomain(sub string) bool {
	return randomSubRe.MatchString(sub)
}

// ---- main ----

func main() {
	if len(os.Args) > 1 {
		os.Args[1] = resolveCommand(os.Args[1])
		switch os.Args[1] {
		case "logs":
			if err := runLogsCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "status":
			// Optional filter: mekong status 3000  OR  mekong status onlyanime
			portFilter := 0
			if len(os.Args) > 2 {
				arg := os.Args[2]
				if p, err := strconv.Atoi(arg); err == nil {
					portFilter = p
				} else {
					// Treat as subdomain name — resolve to port.
					if states, _ := readActiveTunnelStates(); len(states) > 0 {
						for _, t := range states {
							if tunnelShortID(t.URL) == arg {
								portFilter = t.LocalPort
								break
							}
						}
					}
				}
			}
			runStatus(portFilter)
			return
		case "ps":
			runPS()
			return
		case "rm":
			if err := runRMCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "stop":
			if err := runStopCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "update":
			selfUpdate()
			return
		case "login":
			if err := runLogin(); err != nil {
				fmt.Fprintf(os.Stderr, "%s  ✖  Login failed: %v%s\n", red, err, reset)
				os.Exit(1)
			}
			return
		case "logout":
			runLogout()
			return
		case "whoami":
			runWhoami()
			return
		case "subdomains", "sd":
			if err := runSubdomainsCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "subdomain":
			if err := runSubdomainCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				printSubdomainHelp()
				os.Exit(1)
			}
			return
		case "domains":
			if err := runDomainsCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "help":
			if err := runHelpCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "detect":
			if err := runDetectCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "init":
			if err := runInitCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "domain", "dm":
			if err := runDomainCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				printDomainHelp()
				os.Exit(1)
			}
			return
		case "reserve":
			if err := runReserveCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "delete", "unreserve":
			if err := runDeleteCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "test":
			// Resolve token before flags are parsed (env > saved config).
			tok := resolveAPIToken("")
			code := runSelfTest(tok)
			os.Exit(code)
			return
		case "doctor":
			tok := resolveAPIToken("")
			code := runDoctorCommand(os.Args[2:], tok)
			os.Exit(code)
			return
		case "version", "--version", "-v":
			fmt.Printf("mekong %s\n", version)
			return
		case "completion":
			runCompletionCommand(os.Args[2:])
			return
		case "__tunnels":
			// Hidden helper: prints active tunnel names for shell completion.
			states, _ := readActiveTunnelStates()
			for _, t := range states {
				fmt.Println(tunnelShortID(t.URL))
			}
			return
		case "__subdomains":
			// Hidden helper: prints reserved subdomain names for shell completion.
			tok := resolveAPIToken("")
			if tok != "" {
				if data, err := fetchReservedSubdomains(tok); err == nil {
					for _, s := range data.Subdomains {
						fmt.Println(s.Subdomain)
					}
				}
			}
			return
		}

		// Unknown command — but only if it looks like a word, not a flag or port.
		arg := os.Args[1]
		if !strings.HasPrefix(arg, "-") {
			if _, err := strconv.Atoi(arg); err != nil {
				msg := fmt.Sprintf("unknown command %q", arg)
				if s := suggestCommand(arg); s != "" {
					msg += fmt.Sprintf("\n\n  Did you mean:  mekong %s", s)
				}
				fmt.Fprintf(os.Stderr, "\n  error: %s\n\n", msg)
				os.Exit(1)
			}
		}
	}

	var (
		serverFlag       = flag.String("server", tunnelDomain, "MekongTunnel server hostname")
		sshPortFlag      = flag.Int("ssh-port", 22, "SSH server port")
		localPortFlag    = flag.Int("port", 0, "Local port to expose (alternative to positional arg)")
		expireFlag       = flag.String("expire", "", "Tunnel lifetime (examples: 30m, 48h, 2d, 1w, or bare hours like 48)")
		subdomainFlag    = flag.String("subdomain", "", "Pick a specific reserved subdomain (saved login or token required)")
		tokenFlag        = flag.String("token", "", "API token override (flag > env > saved login)")
		upstreamHostFlag = flag.String("upstream-host", "", "Override Host header sent to the local app (useful for Laragon/XAMPP/WAMP vhosts)")
		detachFlag       = flag.Bool("d", false, "Run tunnel in background (daemon mode)")
		noQR             = flag.Bool("no-qr", false, "Disable QR code display")
		noClip           = flag.Bool("no-clipboard", false, "Disable auto clipboard copy")
		noReconnect      = flag.Bool("no-reconnect", false, "Disable auto-reconnect on disconnect")
		skipWarningFlag  = flag.Bool("skip-browser-warning", false, "Skip the browser warning page for this tunnel")
	)
	flag.IntVar(localPortFlag, "p", 0, "Local port to expose (shorthand for --port)")
	flag.StringVar(expireFlag, "e", "", "Shorthand for --expire")
	flag.StringVar(upstreamHostFlag, "host-header", "", "Alias for --upstream-host")
	flag.BoolVar(skipWarningFlag, "no-warning", false, "Alias for --skip-browser-warning")
	flag.StringVar(subdomainFlag, "sd", "", "Shorthand for --subdomain")
	flag.Usage = func() {
		printMainHelp()
	}
	// Go's flag package stops at the first non-flag argument, so
	// `mekong 3000 --subdomain myapp` would leave "--subdomain" as a
	// positional arg. Reorder so flags always come before port numbers.
	os.Args = append(os.Args[:1], reorderArgs(os.Args[1:])...)
	flag.Parse()

	// Resolve API token: flag > env var > saved login (~/.mekong/config.json).
	apiToken := resolveAPIToken(*tokenFlag)
	projectCfg, err := loadProjectConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}

	upstreamHost, err := normalizeUpstreamHost(*upstreamHostFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
	if upstreamHost == "" && projectCfg != nil {
		upstreamHost, err = normalizeUpstreamHost(projectCfg.UpstreamHost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  error: invalid upstream_host in .mekong.json: %v\n", err)
			os.Exit(1)
		}
	}

	// Resolve subdomain early so we can apply the correct lifetime limits.
	requestedSubdomain, err := normalizeRequestedSubdomain(*subdomainFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}

	// Determine lifetime limits: reserved-subdomain tunnels allow up to 1 month.
	maxLifetime := config.MaxTunnelLifetime
	defaultLifetime := config.DefaultTunnelLifetime
	if requestedSubdomain != "" {
		maxLifetime = config.ReservedMaxTunnelLifetime
		defaultLifetime = config.ReservedDefaultTunnelLifetime
	}

	requestedLifetime := defaultLifetime
	if strings.TrimSpace(*expireFlag) != "" {
		d, err := expiry.Parse(*expireFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", err)
			os.Exit(1)
		}
		if d > maxLifetime {
			fmt.Fprintf(os.Stderr, "  error: requested expiry %s exceeds max %s\n", expiry.Format(d), expiry.Format(maxLifetime))
			if requestedSubdomain != "" {
				fmt.Fprintf(os.Stderr, "  note: reserved subdomains allow up to %s\n", expiry.Format(config.ReservedMaxTunnelLifetime))
			} else {
				fmt.Fprintf(os.Stderr, "  note: use --subdomain to allow up to %s\n", expiry.Format(config.ReservedMaxTunnelLifetime))
			}
			os.Exit(1)
		}
		requestedLifetime = d
	}

	if requestedSubdomain != "" && apiToken == "" {
		fmt.Fprintf(os.Stderr, "  error: --subdomain requires login or --token\n")
		os.Exit(1)
	}
	tunnelToken := resolveTunnelSessionToken(apiToken, requestedSubdomain)

	ports, err := resolvePorts(*localPortFlag, flag.Args(), projectCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
	if len(ports) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if requestedSubdomain != "" && len(ports) != 1 {
		fmt.Fprintf(os.Stderr, "  error: --subdomain can only be used with a single local port\n")
		os.Exit(1)
	}
	if upstreamHost != "" && len(ports) != 1 {
		fmt.Fprintf(os.Stderr, "  error: --upstream-host can only be used with a single local port\n")
		os.Exit(1)
	}
	for _, port := range ports {
		if err := ensureLocalPortReady(port); err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", augmentLocalPortError(port, err, projectCfg))
			os.Exit(1)
		}
	}

	// --- Daemon mode ---
	// Re-exec self without -d, redirect output to log file, detach from terminal.
	if *detachFlag {
		if err := spawnDaemon(ports, *serverFlag, *sshPortFlag, requestedLifetime, tunnelToken, requestedSubdomain, upstreamHost, *noReconnect); err != nil {
			fmt.Fprintf(os.Stderr, "%s  ✖  Failed to start daemon: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		return
	}

	state := stateFile{PID: os.Getpid()}
	var stateMu sync.Mutex

	// Graceful Ctrl+C / SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Printf("\n%s\n\n", formatOutputForPorts(ports, yellow+"  ✖  Disconnected. Goodbye!"+reset))
		removePIDStateFiles(os.Getpid(), state.Tunnels)
		removeState()
		os.Exit(0)
	}()

	printBanner(*serverFlag, ports, requestedLifetime)
	if upstreamHost != "" {
		fmt.Println(formatOutputForPorts(ports, fmt.Sprintf(gray+"  Upstream   "+purple+"%s"+reset, upstreamHost)))
		fmt.Printf("\n")
	}

	addTunnelState := func(ts tunnelState) {
		stateMu.Lock()
		defer stateMu.Unlock()
		state.Tunnels = append(state.Tunnels, ts)
	}

	var wg sync.WaitGroup
	for _, localPort := range ports {
		localPort := localPort
		wg.Add(1)
		go func() {
			defer wg.Done()
			backoff := 2 * time.Second
			attempt := 0
			for {
				attempt++
				if attempt > 1 {
					fmt.Printf("%s  ↺  [:%d] Reconnecting in %s...%s\n", yellow, localPort, backoff, reset)
					time.Sleep(backoff)
					if backoff < 60*time.Second {
						backoff *= 2
					}
				} else {
					backoff = 2 * time.Second
				}

				_, err := connect(*serverFlag, *sshPortFlag, localPort, requestedLifetime, tunnelToken, requestedSubdomain, upstreamHost, !*noQR, !*noClip, *skipWarningFlag, func(u string) {
					// Preserve the original StartedAt across reconnects.
					existing, readErr := readTunnelStateForPort(localPort)
					startedAt := time.Now()
					if readErr == nil && !existing.StartedAt.IsZero() {
						startedAt = existing.StartedAt
					}
					ts := tunnelState{
						PID:       os.Getpid(),
						URL:       u,
						LocalPort: localPort,
						StartedAt: startedAt,
						ExpiresAt: time.Now().Add(requestedLifetime),
					}
					writeTunnelState(ts)
					addTunnelState(ts)
				})
				// Only remove state on permanent exit; keep it during reconnect
				// so mekong ps stays accurate during brief disconnect windows.
				if err != nil {
					fmt.Printf("%s  ✖  [:%d] %v%s\n", red, localPort, err, reset)
					if errors.Is(err, errBlocked) {
						removeTunnelFromState(localPort, &state, &stateMu)
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — wait for the block to expire.%s\n\n", red, localPort, reset)
						return
					}
					if errors.Is(err, errExpired) {
						removeTunnelFromState(localPort, &state, &stateMu)
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — tunnel lifetime reached.%s\n\n", red, localPort, reset)
						return
					}
					if errors.Is(err, errExpireUnsupported) {
						removeTunnelFromState(localPort, &state, &stateMu)
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — update the mekongtunnel server to v1.4.4 or newer.%s\n\n", red, localPort, reset)
						return
					}
				}
				if *noReconnect {
					removeTunnelFromState(localPort, &state, &stateMu)
					return
				}
			}
		}()
	}

	wg.Wait()
	removeState()
}

// spawnDaemon re-execs the current binary without the -d flag, detached from
// the terminal. Stdout/stderr are redirected to ~/.mekong/mekong.log.
func spawnDaemon(ports []int, server string, sshPort int, requestedLifetime time.Duration, apiToken, requestedSubdomain, upstreamHost string, noReconnect bool) error {
	_ = os.MkdirAll(mekongDir(), 0755)
	for _, port := range ports {
		if err := pruneLogFile(port, false); err != nil {
			return fmt.Errorf("clean log for port %d: %w", port, err)
		}
	}

	logFile, err := os.OpenFile(logFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}
	defer logFile.Close()

	baseArgs := []string{
		"--server", server,
		"--ssh-port", strconv.Itoa(sshPort),
	}
	// Force no-qr and no-clipboard in daemon mode (terminal is detached).
	baseArgs = append(baseArgs, "--no-qr", "--no-clipboard")
	if requestedLifetime != config.DefaultTunnelLifetime {
		baseArgs = append(baseArgs, "--expire", expiry.Format(requestedLifetime))
	}
	if noReconnect {
		baseArgs = append(baseArgs, "--no-reconnect")
	}
	if apiToken != "" {
		baseArgs = append(baseArgs, "--token", apiToken)
	}
	if requestedSubdomain != "" {
		baseArgs = append(baseArgs, "--subdomain", requestedSubdomain)
	}
	if upstreamHost != "" {
		baseArgs = append(baseArgs, "--upstream-host", upstreamHost)
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate binary: %w", err)
	}

	type daemonProc struct {
		port int
		pid  int
	}
	processes := make([]daemonProc, 0, len(ports))

	for _, port := range ports {
		args := append(append([]string{}, baseArgs...), strconv.Itoa(port))
		cmd := exec.Command(self, args...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		cmd.Env = append(os.Environ(), daemonEnvName+"=1")
		detachProcess(cmd) // platform-specific: detach from terminal
		if err := cmd.Start(); err != nil {
			return err
		}
		processes = append(processes, daemonProc{port: port, pid: cmd.Process.Pid})
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  mekong running in background" + reset + "\n")
	for _, proc := range processes {
		fmt.Printf(gray+"     PID     "+purple+"%d"+reset+gray+"  [:%d]"+reset+"\n", proc.pid, proc.port)
	}
	fmt.Printf(gray+"     Logs    "+purple+"%s"+reset+"\n", logFilePath())
	if upstreamHost != "" {
		fmt.Printf(gray+"     Host    "+purple+"%s"+reset+"\n", upstreamHost)
	}
	if len(ports) == 1 {
		fmt.Printf(gray+"     View    "+purple+"mekong logs %d"+reset+"\n", ports[0])
		fmt.Printf(gray+"     Follow  "+purple+"mekong logs -f %d"+reset+"\n", ports[0])
		fmt.Printf(gray+"     Stop    "+purple+"mekong stop %d"+reset+"\n", ports[0])
	} else {
		fmt.Printf(gray + "     View    " + purple + "mekong logs [port]" + reset + "\n")
		fmt.Printf(gray + "     Follow  " + purple + "mekong logs -f [port]" + reset + "\n")
		fmt.Printf(gray + "     Stop    " + purple + "mekong stop [port]" + reset + "\n")
	}
	fmt.Printf(gray + "     StopAll " + purple + "mekong stop --all" + reset + "\n")
	fmt.Printf(gray + "     Status  " + purple + "mekong status" + reset + "\n")
	fmt.Printf("\n")

	return nil
}

// printBanner prints the startup header.
func printBanner(server string, ports []int, requestedLifetime time.Duration) {
	localTargets := make([]string, len(ports))
	for i, p := range ports {
		localTargets[i] = fmt.Sprintf("localhost:%d", p)
	}
	lines := []string{
		cyan + "  Mekong Tunnel" + reset,
		gray + "  ─────────────────────────────────────────" + reset,
		fmt.Sprintf(gray+"  Server   "+purple+"%s"+reset, server),
		fmt.Sprintf(gray+"  Local    "+purple+"%s"+reset, strings.Join(localTargets, ", ")),
		fmt.Sprintf(gray+"  Expires  "+purple+"%s"+reset, expiry.Format(requestedLifetime)),
		gray + "  Tips     " + reset + cyan + "Ctrl+C" + reset + gray + " stop | " + reset + cyan + "mekong status" + reset + gray + " | " + reset + cyan + "mekong logs" + reset,
		gray + "  ─────────────────────────────────────────" + reset,
	}

	fmt.Printf("\n")
	for _, line := range lines {
		fmt.Println(formatOutputForPorts(ports, line))
	}
	fmt.Printf("\n")
}

// connect establishes one SSH tunnel session. Returns the tunnel URL and any error.
// onURL is called as soon as the tunnel URL is received from the server (while still connected).
func connect(server string, sshPort, localPort int, requestedLifetime time.Duration, apiToken, requestedSubdomain, upstreamHost string, showQR, copyClip, skipWarning bool, onURL func(string)) (string, error) {
	var auths []ssh.AuthMethod
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if agentConn, err := net.Dial("unix", sock); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
		}
	}
	auths = append(auths, ssh.Password(""))

	cfg := &ssh.ClientConfig{
		User:            "tunnel",
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", server, sshPort)
	fmt.Printf("%s  →  [:%d] Connecting to %s...%s\n", gray, localPort, server, reset)

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	payload := ssh.Marshal(tcpIPForwardReq{BindAddr: "", BindPort: 80})
	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		return "", fmt.Errorf("port-forward request error: %w", err)
	}
	if !ok {
		return "", portForwardRejectedError(client)
	}

	fwdChans := client.HandleChannelOpen("forwarded-tcpip")
	go func() {
		for nc := range fwdChans {
			var d forwardedTCPIPData
			if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
				nc.Reject(ssh.Prohibited, "bad payload")
				continue
			}
			ch, _, err := nc.Accept()
			if err != nil {
				continue
			}
			go proxyToLocal(ch, localPort)
		}
	}()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("session error: %w", err)
	}
	defer sess.Close()

	w, h := 120, 40
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if tw, th, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			w, h = tw, th
		}
	}
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty("xterm-256color", h, w, modes); err != nil {
		return "", fmt.Errorf("pty error: %w", err)
	}

	_, err = sess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe: %w", err)
	}

	if requestedLifetime != config.DefaultTunnelLifetime {
		if err := sess.Setenv(expiry.EnvName, expiry.Format(requestedLifetime)); err != nil {
			return "", fmt.Errorf("%w: update mekongtunnel server to v1.4.4 or newer (%v)", errExpireUnsupported, err)
		}
	}
	if apiToken != "" {
		// Best-effort: ignore errors (old servers without token support will silently skip).
		_ = sess.Setenv("MEKONG_API_TOKEN", apiToken)
	}
	if requestedSubdomain != "" {
		_ = sess.Setenv("MEKONG_SUBDOMAIN", requestedSubdomain)
	}
	if upstreamHost != "" {
		_ = sess.Setenv("MEKONG_UPSTREAM_HOST", upstreamHost)
	}
	if skipWarning {
		_ = sess.Setenv("MEKONG_SKIP_WARNING", "1")
	}
	_ = sess.Setenv("MEKONG_LOCAL_PORT", strconv.Itoa(localPort))

	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("shell: %w", err)
	}

	urlCh := make(chan string, 1)
	streamDone := make(chan struct{})
	var status streamStatus
	go streamOutput(stdout, urlCh, &status, streamDone, logPrefixForPort(localPort))

	var tunnelURL string
	go func() {
		u, ok := <-urlCh
		if !ok {
			return
		}
		tunnelURL = u
		if onURL != nil {
			onURL(u)
		}
		if copyClip {
			if err := clipboard.WriteAll(u); err == nil {
				fmt.Printf("%s  ✔  [:%d] Copied to clipboard!%s\n", green, localPort, reset)
			}
		}
		if showQR {
			fmt.Printf("\n%s  [:%d] Scan with your phone:%s\n\n", gray, localPort, reset)
			qrterminal.GenerateHalfBlock(u, qrterminal.L, os.Stdout)
			fmt.Println()
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()

	waitErr := <-waitDone
	<-streamDone
	if status.blockedMsg != "" {
		return tunnelURL, fmt.Errorf("%w: %s", errBlocked, status.blockedMsg)
	}
	if status.expiredMsg != "" {
		return tunnelURL, fmt.Errorf("%w: %s", errExpired, status.expiredMsg)
	}
	if waitErr != nil && tunnelURL == "" {
		return "", waitErr
	}
	return tunnelURL, nil
}

func portForwardRejectedError(client *ssh.Client) error {
	msg, err := readPortForwardRejectMessage(client)
	if err == nil && msg != "" {
		if strings.Contains(msg, "temporarily blocked") {
			return fmt.Errorf("%w: %s", errBlocked, msg)
		}
		return fmt.Errorf("server rejected port-forward request: %s", msg)
	}
	return fmt.Errorf("server rejected port-forward request")
}

func readPortForwardRejectMessage(client *ssh.Client) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := sess.Shell(); err != nil {
		return "", err
	}

	output, readErr := io.ReadAll(stdout)
	waitErr := sess.Wait()
	if readErr != nil {
		return "", readErr
	}

	msg := extractServerErrorMessage(string(output))
	if msg != "" {
		return msg, nil
	}
	if waitErr != nil {
		return "", waitErr
	}
	return "", nil
}

func extractServerErrorMessage(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		clean := strings.TrimSpace(ansiRe.ReplaceAllString(scanner.Text(), ""))
		if idx := strings.Index(clean, "ERROR:"); idx >= 0 {
			msg := strings.TrimSpace(clean[idx+len("ERROR:"):])
			if msg != "" {
				return msg
			}
		}
	}
	return ""
}

type streamStatus struct {
	blockedMsg string
	expiredMsg string
}

// streamOutput prints every line from the server PTY, extracts the tunnel URL,
// and records status messages reported by the server.
func streamOutput(r io.Reader, urlCh chan<- string, status *streamStatus, done chan<- struct{}, prefix string) {
	defer close(done)
	scanner := bufio.NewScanner(r)
	urlFound := false
	suppressServerBanner := true
	for scanner.Scan() {
		line := scanner.Text()
		clean := strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
		if suppressServerBanner {
			if clean == "" || isServerBannerLine(clean) {
				continue
			}
			suppressServerBanner = false
		}
		if prefix != "" {
			fmt.Println(prefix + line)
		} else {
			fmt.Println(line)
		}
		if !urlFound {
			if strings.Contains(clean, "URL") {
				if m := urlRe.FindString(clean); m != "" {
					urlFound = true
					urlCh <- m
				}
			}
		}
		if status.blockedMsg == "" && strings.Contains(clean, "temporarily blocked") {
			status.blockedMsg = clean
		}
		if status.expiredMsg == "" && strings.Contains(clean, "Tunnel expired") {
			status.expiredMsg = clean
		}
	}
	close(urlCh)
}

func isServerBannerLine(clean string) bool {
	switch {
	case strings.HasPrefix(clean, "███╗"),
		strings.HasPrefix(clean, "████╗"),
		strings.HasPrefix(clean, "██╔████╔"),
		strings.HasPrefix(clean, "██║╚██╔╝"),
		strings.HasPrefix(clean, "██║ ╚═╝"),
		strings.HasPrefix(clean, "╚═╝     ╚═╝"),
		strings.Contains(clean, "by Ing Muyleang"),
		strings.HasPrefix(clean, "────────────────"):
		return true
	default:
		return false
	}
}

// proxyToLocal copies data between an SSH channel and localhost:port.
func proxyToLocal(ch ssh.Channel, port int) {
	defer ch.Close()
	local, err := dialLocalTarget(port)
	if err != nil {
		fmt.Printf("%s  ✖  [:%d] %v%s\n", red, port, err, reset)
		return
	}
	defer local.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(local, ch); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(ch, local); done <- struct{}{} }() //nolint:errcheck
	<-done
}

func dialLocalTarget(port int) (net.Conn, error) {
	targets := []string{
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		net.JoinHostPort("::1", strconv.Itoa(port)),
	}

	var lastErr error
	for _, target := range targets {
		conn, err := localDial("tcp", target, localDialTimeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("nothing is listening on localhost:%d; start your app first (%v)", port, lastErr)
}

func ensureLocalPortReady(port int) error {
	conn, err := dialLocalTarget(port)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ---- mekong logs / status / stop ----

func runLogsCommand(args []string) error {
	follow, portFilter, nameFilter, err := parseLogsArgs(args)
	if err != nil {
		return err
	}
	// Resolve subdomain name → port via active tunnel states.
	if nameFilter != "" {
		states, _ := readActiveTunnelStates()
		for _, t := range states {
			if tunnelShortID(t.URL) == nameFilter {
				portFilter = t.LocalPort
				nameFilter = ""
				break
			}
		}
		if nameFilter != "" {
			// Not found — suggest close names.
			states2, _ := readActiveTunnelStates()
			var names []string
			for _, t := range states2 {
				names = append(names, tunnelShortID(t.URL))
			}
			msg := fmt.Sprintf("no active tunnel with subdomain %q", nameFilter)
			if len(names) > 0 {
				msg += fmt.Sprintf("\n\n  Active tunnels: %s", strings.Join(names, ", "))
				msg += "\n  Run: mekong ps"
			} else {
				msg += "\n\n  No tunnels are running. Start one with: mekong 3000 -d"
			}
			return fmt.Errorf("%s", msg)
		}
	}
	return runLogs(follow, portFilter)
}

func parseLogsArgs(args []string) (follow bool, portFilter int, nameFilter string, err error) {
	for _, arg := range args {
		switch arg {
		case "-f", "--follow":
			follow = true
		default:
			if strings.HasPrefix(arg, "-") {
				err = fmt.Errorf("usage: mekong logs [-f] [<port>|<subdomain>]")
				return
			}
			if portFilter != 0 || nameFilter != "" {
				err = fmt.Errorf("usage: mekong logs [-f] [<port>|<subdomain>]")
				return
			}
			if p, e := strconv.Atoi(arg); e == nil && p >= 1 && p <= 65535 {
				portFilter = p
			} else {
				nameFilter = arg
			}
		}
	}
	return
}

func runLogs(follow bool, portFilter int) error {
	path := logFilePath()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No log file yet. Start a background tunnel first.%s\n\n", gray, reset)
			return nil
		}
		return fmt.Errorf("stat log file: %w", err)
	}

	if info.Size() == 0 && !follow {
		if portFilter > 0 {
			fmt.Printf("\n%s  No log entries yet for port %d.%s\n\n", gray, portFilter, reset)
		} else {
			fmt.Printf("\n%s  No log entries yet.%s\n\n", gray, reset)
		}
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	matchedAny, err := printLogStream(f, portFilter)
	if err != nil {
		return err
	}
	if !follow {
		if !matchedAny {
			if portFilter > 0 {
				fmt.Printf("\n%s  No log entries for port %d.%s\n", gray, portFilter, reset)
				fmt.Printf("%s  The tunnel must be running in background mode (%s-d%s) to write logs.\n", gray, cyan, gray)
				fmt.Printf("%s  To see all logs:  %smekong logs%s\n\n", gray, cyan, reset)
			} else {
				fmt.Printf("\n%s  No log entries yet.%s\n\n", gray, reset)
			}
		}
		return nil
	}

	if portFilter > 0 {
		fmt.Fprintf(os.Stderr, "%s  Following %s for port %d (Ctrl+C to stop)%s\n", gray, path, portFilter, reset)
	} else {
		fmt.Fprintf(os.Stderr, "%s  Following %s (Ctrl+C to stop)%s\n", gray, path, reset)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	var pending strings.Builder
	for {
		_, err := printLogUpdates(f, portFilter, &pending)
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("read logs: %w", err)
		}

		select {
		case <-sigs:
			fmt.Fprintln(os.Stderr)
			return nil
		case <-time.After(500 * time.Millisecond):
		}

		currentOffset, seekErr := f.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return fmt.Errorf("seek log file: %w", seekErr)
		}

		info, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return fmt.Errorf("stat log file: %w", statErr)
		}
		if info.Size() < currentOffset {
			reopened, openErr := os.Open(path)
			if openErr != nil {
				return fmt.Errorf("reopen log file: %w", openErr)
			}
			_ = f.Close()
			f = reopened
			pending.Reset()
		}
	}
}

func printLogStream(r io.Reader, portFilter int) (bool, error) {
	var pending strings.Builder
	matched, err := printLogUpdates(r, portFilter, &pending)
	if err != nil && !errors.Is(err, io.EOF) {
		return matched, fmt.Errorf("read logs: %w", err)
	}
	if pending.Len() > 0 {
		line := pending.String()
		if logLineMatchesPort(line, portFilter) {
			if _, writeErr := io.WriteString(os.Stdout, line); writeErr != nil {
				return matched, fmt.Errorf("write logs: %w", writeErr)
			}
			matched = true
		}
	}
	return matched, nil
}

func printLogUpdates(r io.Reader, portFilter int, pending *strings.Builder) (bool, error) {
	buf := make([]byte, 32*1024)
	n, err := r.Read(buf)
	if n == 0 {
		return false, err
	}

	pending.Write(buf[:n])
	data := pending.String()
	pending.Reset()

	matched := false
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}

		line := data[start : i+1]
		if logLineMatchesPort(line, portFilter) {
			if _, writeErr := io.WriteString(os.Stdout, line); writeErr != nil {
				return matched, fmt.Errorf("write logs: %w", writeErr)
			}
			matched = true
		}
		start = i + 1
	}

	if start < len(data) {
		pending.WriteString(data[start:])
	}
	return matched, err
}

func logLineMatchesPort(line string, portFilter int) bool {
	if portFilter == 0 {
		return true
	}
	clean := ansiRe.ReplaceAllString(line, "")
	return strings.Contains(clean, fmt.Sprintf("[:%d]", portFilter))
}

func logPrefixForPort(localPort int) string {
	if os.Getenv(daemonEnvName) == "1" {
		return fmt.Sprintf("[:%d] ", localPort)
	}
	return ""
}

func formatOutputForPorts(ports []int, line string) string {
	if os.Getenv(daemonEnvName) == "1" && len(ports) == 1 {
		return logPrefixForPort(ports[0]) + line
	}
	return line
}

// runStatus prints active tunnels for the current user.
// If portFilter > 0, only the tunnel for that local port is shown.
func runStatus(portFilter int) {
	states, err := readActiveTunnelStates()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  error reading state: %v\n", err)
		}
		return
	}

	if len(states) == 0 {
		fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		return
	}

	alive := states[:0]
	for _, state := range states {
		if state.PID > 0 && isPIDAlive(state.PID) {
			alive = append(alive, state)
			continue
		}
		removeTunnelStateFile(state.LocalPort)
	}
	states = alive
	if len(states) == 0 {
		fmt.Printf("\n%s  No active tunnels (mekong is not running — stale state file).%s\n\n", gray, reset)
		removeState()
		return
	}

	// Apply port filter.
	if portFilter > 0 {
		filtered := states[:0]
		for _, t := range states {
			if t.LocalPort == portFilter {
				filtered = append(filtered, t)
			}
		}
		states = filtered
	}

	if len(states) == 0 {
		if portFilter > 0 {
			fmt.Printf("\n%s  No active tunnel for port %d.%s\n\n", gray, portFilter, reset)
		} else {
			fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		}
		return
	}

	fmt.Printf("\n")
	fmt.Printf(gray + "  ─────────────────────────────────────────────────────" + reset + "\n")
	if portFilter > 0 {
		fmt.Printf(yellow+"  Tunnel for :%d"+reset+"\n", portFilter)
	} else {
		fmt.Printf(yellow + "  Active tunnels" + reset + "\n")
	}
	fmt.Printf(gray + "  ─────────────────────────────────────────────────────" + reset + "\n")

	for _, t := range states {
		uptime := time.Since(t.StartedAt).Round(time.Second)
		fmt.Printf(gray+"  URL        "+cyan+"%s"+reset+"\n", t.URL)
		fmt.Printf(gray+"  Local      "+purple+"localhost:%d"+reset+"\n", t.LocalPort)
		if t.PID > 0 {
			fmt.Printf(gray+"  PID        "+purple+"%d"+reset+"\n", t.PID)
		}
		fmt.Printf(gray+"  Uptime     "+purple+"%s"+reset+"\n", uptime)
		if !t.ExpiresAt.IsZero() {
			fmt.Printf(gray+"  Expires    "+purple+"%s"+reset+"\n", t.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"))
		}
		fmt.Printf(gray + "  ─────────────────────────────────────────────────────" + reset + "\n")
	}
	fmt.Printf("\n")
}

// formatAgo formats a duration as a human-readable "X ago" string, matching docker ps style.
func formatAgo(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "About an hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "A day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

// formatUptime formats a duration as "Up Xh" / "Up Xm" like docker ps STATUS.
func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("Up %ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("Up %dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("Up %dh", int(d.Hours()))
	default:
		return fmt.Sprintf("Up %dd", int(d.Hours()/24))
	}
}

// tunnelShortID extracts the subdomain part from a tunnel URL for the ID column.
func tunnelShortID(rawURL string) string {
	clean := ansiRe.ReplaceAllString(rawURL, "")
	clean = strings.TrimPrefix(clean, "https://")
	clean = strings.TrimPrefix(clean, "http://")
	if idx := strings.Index(clean, "."); idx > 0 {
		return clean[:idx]
	}
	return clean
}

// truncateURL shortens a URL to maxLen characters with an ellipsis.
func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-1] + "…"
}

// formatExpire formats a tunnel's expiry time as a compact remaining-time string.
func formatExpire(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "no limit"
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return "expired"
	}
	switch {
	case remaining < time.Hour:
		return fmt.Sprintf("%dm left", int(remaining.Minutes()))
	case remaining < 24*time.Hour:
		return fmt.Sprintf("%dh left", int(remaining.Hours()))
	default:
		days := int(remaining.Hours() / 24)
		if days == 1 {
			return "1d left"
		}
		return fmt.Sprintf("%dd left", days)
	}
}

// runPS prints active tunnels in a Docker-style table (mekong ps).
func runPS() {
	states, err := readActiveTunnelStates()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  error reading state: %v\n", err)
		}
		return
	}

	alive := states[:0]
	for _, state := range states {
		if state.PID > 0 && isPIDAlive(state.PID) {
			alive = append(alive, state)
			continue
		}
		removeTunnelStateFile(state.LocalPort)
	}
	states = alive

	if len(states) == 0 {
		fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		return
	}

	const (
		colID     = 22
		colURL    = 46
		colPort   = 7
		colStatus = 10
		colCreate = 16
	)

	hdr := fmt.Sprintf("%-*s   %-*s   %-*s   %-*s   %-*s   %s",
		colID, "TUNNEL ID",
		colURL, "URL",
		colPort, "PORT",
		colStatus, "STATUS",
		colCreate, "CREATED",
		"EXPIRE",
	)
	fmt.Printf("\n%s%s%s\n", gray, hdr, reset)

	for _, t := range states {
		id := tunnelShortID(t.URL)
		rawURL := ansiRe.ReplaceAllString(t.URL, "")
		u := truncateURL(rawURL, colURL)
		port := fmt.Sprintf(":%d", t.LocalPort)
		status := formatUptime(time.Since(t.StartedAt))
		created := formatAgo(time.Since(t.StartedAt))
		expire := formatExpire(t.ExpiresAt)

		row := fmt.Sprintf("%-*s   %-*s   %-*s   %-*s   %-*s   %s",
			colID, id,
			colURL, u,
			colPort, port,
			colStatus, status,
			colCreate, created,
			expire,
		)
		fmt.Printf("%s%s%s\n", cyan, row, reset)
	}
	fmt.Printf("\n")
}

// ---- shell completion ----

func runCompletionCommand(args []string) {
	shell := "zsh"
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}

	switch shell {
	case "zsh":
		fmt.Print(zshCompletionScript)
	case "bash":
		fmt.Print(bashCompletionScript)
	default:
		fmt.Fprintf(os.Stderr, "  usage: mekong completion [zsh|bash]\n")
		fmt.Fprintf(os.Stderr, "  example: mekong completion zsh >> ~/.zshrc && source ~/.zshrc\n")
		os.Exit(1)
	}
}

const zshCompletionScript = `
# mekong zsh completion — generated by 'mekong completion zsh'
# Add to ~/.zshrc:  mekong completion zsh >> ~/.zshrc && source ~/.zshrc

# Initialize zsh completion system if not already done
autoload -Uz compinit && compinit

_mekong() {
  local context state line
  typeset -A opt_args

  _arguments -C \
    '(-v --version)'{-v,--version}'[Show version]' \
    '1: :->command' \
    '*: :->args'

  case $state in
    command)
      local -a cmds
      cmds=(
        'ps:List active tunnels (table view)'
        'status:List active tunnels (detailed view)'
        'logs:Show or follow daemon logs'
        'stop:Stop background tunnel(s)'
        'rm:Clear daemon logs'
        'update:Update mekong binary'
        'version:Show current version'
        'login:Authenticate to MekongTunnel'
        'logout:Remove saved credentials'
        'whoami:Show current account info'
        'subdomain:Manage reserved subdomains'
        'domain:Manage custom domains'
        'detect:Detect local stack and port'
        'init:Write .mekong.json'
        'doctor:Check connectivity and auth'
        'help:Show help for a topic'
      )
      _describe 'command' cmds
      ;;
    args)
      case $words[2] in
        logs|rm)
          local -a tunnels
          tunnels=(${(f)"$(mekong __tunnels 2>/dev/null)"})
          _describe 'tunnel name' tunnels
          ;;
        stop)
          local -a tunnels
          tunnels=(${(f)"$(mekong __tunnels 2>/dev/null)"})
          _describe 'tunnel name' tunnels
          ;;
        subdomain|sd)
          case $words[3] in
            delete|remove|rm)
              local -a subs
              subs=(${(f)"$(mekong __subdomains 2>/dev/null)"})
              _describe 'subdomain' subs
              ;;
            *)
              local -a subcmds
              subcmds=('list:List subdomains' 'add:Reserve a subdomain' 'delete:Delete a subdomain')
              _describe 'subcommand' subcmds
              ;;
          esac
          ;;
        domain|dm)
          local -a subcmds
          subcmds=(
            'list:List custom domains'
            'add:Add a custom domain'
            'connect:Add+verify+target in one step'
            'verify:Run verification check'
            'wait:Poll until ready'
            'target:Point domain to subdomain'
            'delete:Remove a custom domain'
          )
          _describe 'subcommand' subcmds
          ;;
        help)
          local -a topics
          topics=('auth' 'subdomain' 'domain' 'config' 'php' 'health')
          _describe 'topic' topics
          ;;
      esac
      ;;
  esac
}

compdef _mekong mekong
`

const bashCompletionScript = `
# mekong bash completion — generated by 'mekong completion bash'
# Add to ~/.bashrc or ~/.bash_profile:
#   mekong completion bash >> ~/.bashrc && source ~/.bashrc

_mekong_complete() {
  local cur prev words
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  if [[ ${COMP_CWORD} -eq 1 ]]; then
    local cmds="ps status logs stop rm update version login logout whoami subdomain domain detect init doctor help"
    COMPREPLY=($(compgen -W "$cmds" -- "$cur"))
    return
  fi

  case "$prev" in
    logs|rm|stop)
      local tunnels
      tunnels=$(mekong __tunnels 2>/dev/null)
      COMPREPLY=($(compgen -W "$tunnels" -- "$cur"))
      ;;
    subdomain|sd)
      COMPREPLY=($(compgen -W "list add delete" -- "$cur"))
      ;;
    delete|remove)
      local subs
      subs=$(mekong __subdomains 2>/dev/null)
      COMPREPLY=($(compgen -W "$subs" -- "$cur"))
      ;;
    domain|dm)
      COMPREPLY=($(compgen -W "list add connect verify wait target delete" -- "$cur"))
      ;;
    help)
      COMPREPLY=($(compgen -W "auth subdomain domain config php health" -- "$cur"))
      ;;
  esac
}

complete -F _mekong_complete mekong
`

// runRMCommand clears mekong daemon logs with reserved-subdomain protection.
//
//	mekong rm              clear logs for random tunnels; reserved tunnels are protected
//	mekong rm -f <name>    clear logs specifically for the named reserved tunnel
//	mekong rm -f           clear ALL logs (no protection)
func runRMCommand(args []string) error {
	force := false
	nameFilter := ""
	for _, a := range args {
		switch {
		case a == "-f" || a == "--force" || a == "-rf" || a == "-fr":
			force = true
		case strings.HasPrefix(a, "-") && strings.Contains(a, "f"):
			// handle -rf, -fr, --force etc.
			force = true
		case !strings.HasPrefix(a, "-"):
			nameFilter = a
		}
	}

	// ── Case 1: clear a specific named tunnel's logs ──────────────────────────
	if nameFilter != "" {
		states, _ := readActiveTunnelStates()
		portFilter := 0
		for _, t := range states {
			if tunnelShortID(t.URL) == nameFilter {
				portFilter = t.LocalPort
				break
			}
		}
		if portFilter == 0 {
			return fmt.Errorf("no active tunnel with subdomain %q — run: mekong ps", nameFilter)
		}
		if err := pruneLogFile(portFilter, false); err != nil {
			return fmt.Errorf("clear logs for %q: %w", nameFilter, err)
		}
		fmt.Printf("\n%s  ✔  Logs cleared for%s %s%s%s\n\n", green, reset, cyan, nameFilter, reset)
		return nil
	}

	// ── Case 2: force-clear everything ────────────────────────────────────────
	if force {
		if err := os.WriteFile(logFilePath(), nil, 0644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear log: %w", err)
		}
		fmt.Printf("\n%s  ✔  All logs cleared%s\n\n", green, reset)
		return nil
	}

	// ── Case 3: safe clear — protect reserved tunnels ─────────────────────────
	states, _ := readActiveTunnelStates()
	var reservedNames []string
	var randomPorts []int
	for _, t := range states {
		sub := tunnelShortID(t.URL)
		if isRandomSubdomain(sub) {
			randomPorts = append(randomPorts, t.LocalPort)
		} else {
			reservedNames = append(reservedNames, sub)
		}
	}

	if len(reservedNames) > 0 {
		fmt.Printf("\n%s  Protected (reserved):%s %s%s%s\n", yellow, reset, cyan, strings.Join(reservedNames, ", "), reset)
		fmt.Printf("%s  To clear a reserved tunnel's logs:%s %smekong rm -f <name>%s\n", gray, reset, cyan, reset)
		if len(randomPorts) == 0 {
			fmt.Printf("%s  Nothing else to clear.%s\n\n", gray, reset)
			return nil
		}
		fmt.Printf("%s  Clearing logs for random tunnels only...%s\n", gray, reset)
		for _, port := range randomPorts {
			_ = pruneLogFile(port, false)
		}
		fmt.Printf("%s  ✔  Done%s\n\n", green, reset)
		return nil
	}

	// No reserved tunnels — clear everything.
	if err := os.WriteFile(logFilePath(), nil, 0644); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear log: %w", err)
	}
	fmt.Printf("\n%s  ✔  Logs cleared%s\n\n", green, reset)
	return nil
}

func runStopCommand(args []string) error {
	portFilter, stopAll, err := parseStopArgs(args)
	if err != nil {
		return err
	}
	return runStop(portFilter, stopAll)
}

func parseStopArgs(args []string) (int, bool, error) {
	portFilter := 0
	stopAll := false
	for _, arg := range args {
		switch arg {
		case "--all":
			stopAll = true
		default:
			if strings.HasPrefix(arg, "-") {
				return 0, false, fmt.Errorf("usage: mekong stop [port] [--all]")
			}
			if portFilter != 0 {
				return 0, false, fmt.Errorf("usage: mekong stop [port] [--all]")
			}
			p, err := strconv.Atoi(arg)
			if err != nil || p < 1 || p > 65535 {
				return 0, false, fmt.Errorf("invalid port %q", arg)
			}
			portFilter = p
		}
	}
	if stopAll && portFilter != 0 {
		return 0, false, fmt.Errorf("usage: mekong stop [port] [--all]")
	}
	return portFilter, stopAll, nil
}

// runStop stops either a specific tunnel daemon, all tunnel daemons, or the
// single active daemon when only one tunnel is running.
func runStop(portFilter int, stopAll bool) error {
	states, err := readActiveTunnelStates()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No background tunnel to stop.%s\n\n", gray, reset)
			return nil
		}
		return fmt.Errorf("reading tunnel state: %w", err)
	}

	if len(states) == 0 {
		fmt.Printf("\n%s  No background tunnel to stop.%s\n\n", gray, reset)
		return nil
	}

	alive := states[:0]
	for _, state := range states {
		if state.PID > 0 && isPIDAlive(state.PID) {
			alive = append(alive, state)
			continue
		}
		removeTunnelStateFile(state.LocalPort)
	}
	states = alive
	if len(states) == 0 {
		if stopAll {
			_ = pruneLogFile(0, true)
		} else if portFilter > 0 {
			_ = pruneLogFile(portFilter, false)
		}
		fmt.Printf("\n%s  mekong is not running (stale state file cleaned up).%s\n\n", gray, reset)
		removeState()
		return nil
	}

	if stopAll {
		pids := uniquePIDs(states)
		stopped := 0
		for _, pid := range pids {
			p, err := os.FindProcess(pid)
			if err != nil {
				continue
			}
			if err := p.Signal(syscall.SIGTERM); err == nil {
				stopped++
			}
			waitForPIDExit(pid, 3*time.Second)
		}
		for _, pid := range pids {
			removePIDStateFiles(pid, states)
		}
		if err := pruneLogFile(0, true); err != nil {
			return fmt.Errorf("clean log file: %w", err)
		}
		fmt.Printf("\n%s  ✔  Stopped %d mekong process(es).%s\n\n", green, stopped, reset)
		return nil
	}

	if portFilter == 0 {
		if len(states) > 1 {
			fmt.Printf("\n%s  Multiple active tunnels. Use mekong stop <port> or mekong stop --all.%s\n\n", yellow, reset)
			return nil
		}
		portFilter = states[0].LocalPort
	}

	var target *tunnelState
	for i := range states {
		if states[i].LocalPort == portFilter {
			target = &states[i]
			break
		}
	}
	if target == nil {
		_ = pruneLogFile(portFilter, false)
		fmt.Printf("\n%s  No active tunnel for port %d.%s\n\n", gray, portFilter, reset)
		return nil
	}

	p, err := os.FindProcess(target.PID)
	if err != nil {
		return fmt.Errorf("finding process: %w", err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending signal: %w", err)
	}

	waitForPIDExit(target.PID, 3*time.Second)
	removePIDStateFiles(target.PID, states)
	if err := pruneLogFile(target.LocalPort, false); err != nil {
		return fmt.Errorf("clean log for port %d: %w", target.LocalPort, err)
	}
	fmt.Printf("\n%s  ✔  Stopped mekong for :%d (PID %d)%s\n\n", green, target.LocalPort, target.PID, reset)
	return nil
}

func uniquePIDs(states []tunnelState) []int {
	seen := make(map[int]struct{}, len(states))
	pids := make([]int, 0, len(states))
	for _, state := range states {
		if state.PID == 0 {
			continue
		}
		if _, ok := seen[state.PID]; ok {
			continue
		}
		seen[state.PID] = struct{}{}
		pids = append(pids, state.PID)
	}
	return pids
}

func waitForPIDExit(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for isPIDAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}

func pruneLogFile(portFilter int, clearAll bool) error {
	path := logFilePath()
	if clearAll {
		if err := os.WriteFile(path, nil, 0644); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	parts := strings.SplitAfter(string(data), "\n")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		if logLineMatchesPort(part, portFilter) {
			continue
		}
		kept = append(kept, part)
	}

	return os.WriteFile(path, []byte(strings.Join(kept, "")), 0644)
}

// ---- self-update ----

func selfUpdate() {
	fmt.Printf("%s  →  Checking for updates...%s\n", gray, reset)

	client := &http.Client{Timeout: updateHTTPTimeout}

	latest, err := latestReleaseTag(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Failed to check latest release: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	if latest == "" {
		fmt.Fprintf(os.Stderr, "%s  ✖  No release found.%s\n", red, reset)
		os.Exit(1)
	}

	if version != "dev" && version == latest {
		fmt.Printf("%s  ✔  Already up to date (%s).%s\n", green, version, reset)
		return
	}

	assetName, ok := releaseAssetName()
	if !ok {
		fmt.Fprintf(os.Stderr, "%s  ✖  Unsupported platform: %s/%s%s\n", red, runtime.GOOS, runtime.GOARCH, reset)
		os.Exit(1)
	}

	downloadURL := fmt.Sprintf("https://github.com/MuyleangIng/MekongTunnel/releases/download/%s/%s", latest, assetName)
	expectedChecksum, err := fetchReleaseChecksum(client, latest, assetName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Checksum fetch failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	fmt.Printf("%s  →  Downloading %s %s...%s\n", gray, assetName, latest, reset)

	currentBinary, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Cannot locate current binary: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	tmpPath, err := downloadReleaseAsset(client, downloadURL, assetName, expectedChecksum)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Download failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	defer os.Remove(tmpPath)

	if err := os.Rename(tmpPath, currentBinary); err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Replace failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	fmt.Printf("%s  ✔  Updated to %s — restart mekong to use the new version.%s\n", green, latest, reset)
}

func latestReleaseTag(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/repos/MuyleangIng/MekongTunnel/releases/latest") //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return strings.TrimSpace(release.TagName), nil
}

func releaseAssetName() (string, bool) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "mekong-darwin-arm64", true
	case "darwin/amd64":
		return "mekong-darwin-amd64", true
	case "linux/amd64":
		return "mekong-linux-amd64", true
	case "linux/arm64":
		return "mekong-linux-arm64", true
	case "windows/amd64":
		return "mekong-windows-amd64.exe", true
	default:
		return "", false
	}
}

func fetchReleaseChecksum(client *http.Client, tag, assetName string) (string, error) {
	checksumURL := fmt.Sprintf("https://github.com/MuyleangIng/MekongTunnel/releases/download/%s/SHA256SUMS-%s.txt", tag, tag)
	resp, err := client.Get(checksumURL) //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download returned HTTP %d", resp.StatusCode)
	}

	return parseReleaseChecksum(resp.Body, assetName)
}

func parseReleaseChecksum(r io.Reader, assetName string) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == assetName {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("asset %s not found in checksum file", assetName)
}

func downloadReleaseAsset(client *http.Client, downloadURL, assetName, expectedChecksum string) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= updateMaxAttempts; attempt++ {
		tmpPath, err := downloadReleaseAssetOnce(client, downloadURL, expectedChecksum)
		if err == nil {
			return tmpPath, nil
		}

		lastErr = err
		if attempt == updateMaxAttempts || !shouldRetryUpdateDownload(err) {
			break
		}
		fmt.Fprintf(os.Stderr, "%s  ↺  Download retry %d/%d for %s after: %v%s\n", yellow, attempt+1, updateMaxAttempts, assetName, err, reset)
		time.Sleep(time.Duration(attempt) * time.Second)
	}

	return "", lastErr
}

func downloadReleaseAssetOnce(client *http.Client, downloadURL, expectedChecksum string) (string, error) {
	resp, err := client.Get(downloadURL) //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "mekong-update-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}

	gotChecksum := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(gotChecksum, expectedChecksum) {
		os.Remove(tmpPath)
		return "", fmt.Errorf("checksum mismatch: got %s, want %s", gotChecksum, expectedChecksum)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil { //nolint:gosec
		os.Remove(tmpPath)
		return "", err
	}

	return tmpPath, nil
}

func shouldRetryUpdateDownload(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "checksum mismatch")
}
