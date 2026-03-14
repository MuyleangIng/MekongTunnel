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
	ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	urlRe  = regexp.MustCompile(`https?://[^\s\r\n]+`)
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
		"-e": true,
		"-p": true,
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

// ---- main ----

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "logs":
			if err := runLogsCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
				os.Exit(1)
			}
			return
		case "status":
			// Optional port filter: mekong status 3000
			portFilter := 0
			if len(os.Args) > 2 {
				if p, err := strconv.Atoi(os.Args[2]); err == nil {
					portFilter = p
				}
			}
			runStatus(portFilter)
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
		case "version", "--version", "-v":
			fmt.Printf("mekong %s\n", version)
			return
		}
	}

	var (
		serverFlag    = flag.String("server", "mekongtunnel.dev", "MekongTunnel server hostname")
		sshPortFlag   = flag.Int("ssh-port", 22, "SSH server port")
		localPortFlag = flag.Int("port", 0, "Local port to expose (alternative to positional arg)")
		expireFlag    = flag.String("expire", "", "Tunnel lifetime (examples: 30m, 48h, 2d, 1w, or bare hours like 48)")
		detachFlag    = flag.Bool("d", false, "Run tunnel in background (daemon mode)")
		noQR          = flag.Bool("no-qr", false, "Disable QR code display")
		noClip        = flag.Bool("no-clipboard", false, "Disable auto clipboard copy")
		noReconnect   = flag.Bool("no-reconnect", false, "Disable auto-reconnect on disconnect")
	)
	flag.IntVar(localPortFlag, "p", 0, "Local port to expose (shorthand for --port)")
	flag.StringVar(expireFlag, "e", "", "Shorthand for --expire")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Usage: mekong [flags] <local-port>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Examples:")
		fmt.Fprintln(os.Stderr, "    mekong 3000                            expose localhost:3000")
		fmt.Fprintln(os.Stderr, "    mekong -d 3000                         run in background")
		fmt.Fprintln(os.Stderr, "    mekong logs                            show daemon logs")
		fmt.Fprintln(os.Stderr, "    mekong logs -f                         follow daemon logs")
		fmt.Fprintln(os.Stderr, "    mekong 3000 --expire 1w                keep the tunnel for up to 1 week")
		fmt.Fprintln(os.Stderr, "    mekong status                          show your active tunnels")
		fmt.Fprintln(os.Stderr, "    mekong status 3000                     show tunnel for port 3000")
		fmt.Fprintln(os.Stderr, "    mekong stop 3000                       stop the background tunnel for port 3000")
		fmt.Fprintln(os.Stderr, "    mekong stop --all                      stop all background tunnels")
		fmt.Fprintln(os.Stderr, "    mekong update                          self-update binary")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
	}
	// Go's flag package stops at the first non-flag argument, so
	// `mekong 3000 --subdomain myapp` would leave "--subdomain" as a
	// positional arg. Reorder so flags always come before port numbers.
	os.Args = append(os.Args[:1], reorderArgs(os.Args[1:])...)
	flag.Parse()

	requestedLifetime := config.DefaultTunnelLifetime
	if strings.TrimSpace(*expireFlag) != "" {
		d, err := expiry.Parse(*expireFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", err)
			os.Exit(1)
		}
		if d > config.MaxTunnelLifetime {
			fmt.Fprintf(os.Stderr, "  error: requested expiry %s exceeds max %s\n", expiry.Format(d), expiry.Format(config.MaxTunnelLifetime))
			os.Exit(1)
		}
		requestedLifetime = d
	}

	// Build port list: -p/--port flag takes priority; fall back to positional args.
	var ports []int
	if *localPortFlag > 0 {
		if *localPortFlag < 1 || *localPortFlag > 65535 {
			fmt.Fprintf(os.Stderr, "  error: invalid port %d\n", *localPortFlag)
			os.Exit(1)
		}
		ports = []int{*localPortFlag}
		// positional args not allowed when -p is used
		if flag.NArg() > 0 {
			fmt.Fprintf(os.Stderr, "  error: cannot mix -p/--port flag with positional port arguments\n")
			os.Exit(1)
		}
	} else {
		if flag.NArg() < 1 {
			flag.Usage()
			os.Exit(1)
		}
		ports = make([]int, 0, flag.NArg())
		for _, arg := range flag.Args() {
			p, err := strconv.Atoi(arg)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "  error: invalid port %q\n", arg)
				os.Exit(1)
			}
			ports = append(ports, p)
		}
	}

	// --- Daemon mode ---
	// Re-exec self without -d, redirect output to log file, detach from terminal.
	if *detachFlag {
		if err := spawnDaemon(ports, *serverFlag, *sshPortFlag, requestedLifetime, *noReconnect); err != nil {
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

				_, err := connect(*serverFlag, *sshPortFlag, localPort, requestedLifetime, !*noQR, !*noClip, func(u string) {
					ts := tunnelState{
						PID:       os.Getpid(),
						URL:       u,
						LocalPort: localPort,
						StartedAt: time.Now(),
						ExpiresAt: time.Now().Add(requestedLifetime),
					}
					writeTunnelState(ts)
					addTunnelState(ts)
				})
				// Tunnel disconnected — remove its entry so status stays accurate.
				removeTunnelFromState(localPort, &state, &stateMu)
				if err != nil {
					fmt.Printf("%s  ✖  [:%d] %v%s\n", red, localPort, err, reset)
					if errors.Is(err, errBlocked) {
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — wait for the block to expire.%s\n\n", red, localPort, reset)
						return
					}
					if errors.Is(err, errExpired) {
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — tunnel lifetime reached.%s\n\n", red, localPort, reset)
						return
					}
					if errors.Is(err, errExpireUnsupported) {
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — update the mekongtunnel server to v1.4.4 or newer.%s\n\n", red, localPort, reset)
						return
					}
				}
				if *noReconnect {
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
func spawnDaemon(ports []int, server string, sshPort int, requestedLifetime time.Duration, noReconnect bool) error {
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
	portStr := make([]string, len(ports))
	for i, p := range ports {
		portStr[i] = strconv.Itoa(p)
	}
	lines := []string{
		cyan + "  ███╗   ███╗███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗ " + reset,
		cyan + "  ████╗ ████║██╔════╝██║ ██╔╝██╔═══██╗████╗  ██║██╔════╝ " + reset,
		cyan + "  ██╔████╔██║█████╗  █████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗" + reset,
		cyan + "  ██║╚██╔╝██║██╔══╝  ██╔═██╗ ██║   ██║██║╚██╗██║██║   ██║" + reset,
		cyan + "  ██║ ╚═╝ ██║███████╗██║  ██╗╚██████╔╝██║ ╚████║╚██████╔╝" + reset,
		cyan + "  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ " + reset,
		gray + "  by " + yellow + "Ing Muyleang" + gray + " · Founder of " + yellow + "KhmerStack" + reset,
		gray + "  ─────────────────────────────────────────────────────" + reset,
		fmt.Sprintf(gray+"  Server     "+purple+"%s"+reset, server),
		fmt.Sprintf(gray+"  Local      "+purple+"localhost:%s"+reset, strings.Join(portStr, ", ")),
		fmt.Sprintf(gray+"  Expire     "+purple+"%s"+reset, expiry.Format(requestedLifetime)),
		gray + "  ─────────────────────────────────────────────────────" + reset,
	}

	fmt.Printf("\n")
	for _, line := range lines {
		fmt.Println(formatOutputForPorts(ports, line))
	}
	fmt.Printf("\n")
}

// connect establishes one SSH tunnel session. Returns the tunnel URL and any error.
// onURL is called as soon as the tunnel URL is received from the server (while still connected).
func connect(server string, sshPort, localPort int, requestedLifetime time.Duration, showQR, copyClip bool, onURL func(string)) (string, error) {
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
	for scanner.Scan() {
		line := scanner.Text()
		if prefix != "" {
			fmt.Println(prefix + line)
		} else {
			fmt.Println(line)
		}
		clean := strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
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

// proxyToLocal copies data between an SSH channel and localhost:port.
func proxyToLocal(ch ssh.Channel, port int) {
	defer ch.Close()
	local, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return
	}
	defer local.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(local, ch); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(ch, local); done <- struct{}{} }() //nolint:errcheck
	<-done
}

// ---- mekong logs / status / stop ----

func runLogsCommand(args []string) error {
	follow, portFilter, err := parseLogsArgs(args)
	if err != nil {
		return err
	}
	return runLogs(follow, portFilter)
}

func parseLogsArgs(args []string) (bool, int, error) {
	follow := false
	portFilter := 0
	for _, arg := range args {
		switch arg {
		case "-f", "--follow":
			follow = true
		default:
			if strings.HasPrefix(arg, "-") {
				return false, 0, fmt.Errorf("usage: mekong logs [-f|--follow] [port]")
			}
			if portFilter != 0 {
				return false, 0, fmt.Errorf("usage: mekong logs [-f|--follow] [port]")
			}
			p, err := strconv.Atoi(arg)
			if err != nil || p < 1 || p > 65535 {
				return false, 0, fmt.Errorf("invalid port %q", arg)
			}
			portFilter = p
		}
	}
	return follow, portFilter, nil
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
				fmt.Printf("\n%s  No log entries yet for port %d.%s\n\n", gray, portFilter, reset)
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
