// mekong — CLI client for MekongTunnel.
// Exposes one or more local ports to the internet via MekongTunnel:
//
//	mekong 3000
//	mekong 3000 8080
//	mekong 8080 --subdomain myapp
//	mekong -d 3000          (background/daemon mode)
//	mekong status           (show your active tunnels)
//	mekong status 3000      (filter by port)
//	mekong stop             (stop background tunnel)
//
// Features: auto-reconnect, QR code, clipboard copy, custom subdomain,
// multi-port, daemon mode, status/stop commands.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package main

import (
	"bufio"
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
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// errBlocked is returned by connect() when the server reports the IP is blocked.
var errBlocked = errors.New("IP is blocked")

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
	Subdomain string    `json:"subdomain"`
	URL       string    `json:"url"`
	LocalPort int       `json:"local_port"`
	Server    string    `json:"server"`
	StartedAt time.Time `json:"started_at"`
}

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

func stateFilePath() string  { return filepath.Join(mekongDir(), "state.json") }
func logFilePath() string    { return filepath.Join(mekongDir(), "mekong.log") }

func writeState(s stateFile) {
	_ = os.MkdirAll(mekongDir(), 0755)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(stateFilePath(), b, 0600)
}

func removeState() { _ = os.Remove(stateFilePath()) }

func readState() (stateFile, error) {
	b, err := os.ReadFile(stateFilePath())
	if err != nil {
		return stateFile{}, err
	}
	var s stateFile
	return s, json.Unmarshal(b, &s)
}

// isPIDAlive is defined in platform_unix.go / platform_windows.go

// ---- subdomain validation ----

func isValidSubdomain(s string) bool {
	if len(s) < 3 || len(s) > 50 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// reorderArgs moves flags (and their values) before positional arguments so
// that flag.Parse() works regardless of where flags appear on the command line.
// e.g. ["3000", "--subdomain", "myapp"] → ["--subdomain", "myapp", "3000"]
func reorderArgs(args []string) []string {
	// Flags that consume the next token as their value.
	valueFlags := map[string]bool{
		"--server":   true, "-server":   true,
		"--ssh-port": true, "-ssh-port": true,
		"--port":     true, "-port":     true,
		"-p":         true,
		"--subdomain": true, "-subdomain": true,
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
			runStop()
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
		subdomainFlag = flag.String("subdomain", "", "Request a custom subdomain (e.g. myapp)")
		detachFlag    = flag.Bool("d", false, "Run tunnel in background (daemon mode)")
		noQR          = flag.Bool("no-qr", false, "Disable QR code display")
		noClip        = flag.Bool("no-clipboard", false, "Disable auto clipboard copy")
		noReconnect   = flag.Bool("no-reconnect", false, "Disable auto-reconnect on disconnect")
	)
	flag.IntVar(localPortFlag, "p", 0, "Local port to expose (shorthand for --port)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Usage: mekong [flags] <local-port> [local-port...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Examples:")
		fmt.Fprintln(os.Stderr, "    mekong 3000                            expose localhost:3000")
		fmt.Fprintln(os.Stderr, "    mekong 3000 8080                       expose two ports")
		fmt.Fprintln(os.Stderr, "    mekong 3000 --subdomain myapp          custom subdomain")
		fmt.Fprintln(os.Stderr, "    mekong -d 3000                         run in background")
		fmt.Fprintln(os.Stderr, "    mekong status                          show your active tunnels")
		fmt.Fprintln(os.Stderr, "    mekong status 3000                     show tunnel for port 3000")
		fmt.Fprintln(os.Stderr, "    mekong stop                            stop background tunnel")
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

	if *subdomainFlag != "" && !isValidSubdomain(*subdomainFlag) {
		fmt.Fprintf(os.Stderr, "  error: invalid subdomain %q — use lowercase letters, digits, hyphens (3–50 chars)\n", *subdomainFlag)
		os.Exit(1)
	}
	if *subdomainFlag != "" && len(ports) > 1 {
		fmt.Fprintf(os.Stderr, "  error: --subdomain can only be used with a single port\n")
		os.Exit(1)
	}

	// --- Daemon mode ---
	// Re-exec self without -d, redirect output to log file, detach from terminal.
	if *detachFlag {
		if err := spawnDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "%s  ✖  Failed to start daemon: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		return
	}

	// Graceful Ctrl+C / SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Printf("\n%s  ✖  Disconnected. Goodbye!%s\n\n", yellow, reset)
		removeState()
		os.Exit(0)
	}()

	printBanner(*serverFlag, ports)

	state := stateFile{PID: os.Getpid()}
	var stateMu sync.Mutex

	addTunnelState := func(ts tunnelState) {
		stateMu.Lock()
		defer stateMu.Unlock()
		state.Tunnels = append(state.Tunnels, ts)
		writeState(state)
	}

	var wg sync.WaitGroup
	for _, localPort := range ports {
		localPort := localPort
		subdomain := *subdomainFlag
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

				tunnelURL, err := connect(*serverFlag, *sshPortFlag, localPort, subdomain, !*noQR, !*noClip)
				if tunnelURL != "" {
					parts := strings.SplitN(tunnelURL, ".", 2)
					sub := strings.TrimPrefix(parts[0], "https://")
					addTunnelState(tunnelState{
						Subdomain: sub,
						URL:       tunnelURL,
						LocalPort: localPort,
						Server:    *serverFlag,
						StartedAt: time.Now(),
					})
				}
				if err != nil {
					fmt.Printf("%s  ✖  [:%d] %v%s\n", red, localPort, err, reset)
					if errors.Is(err, errBlocked) {
						fmt.Printf("%s  ✖  [:%d] Reconnect aborted — wait for the block to expire.%s\n\n", red, localPort, reset)
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
func spawnDaemon() error {
	_ = os.MkdirAll(mekongDir(), 0755)

	logFile, err := os.OpenFile(logFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}

	// Build args: same as current invocation minus the -d flag.
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a == "-d" || a == "--d" {
			continue
		}
		args = append(args, a)
	}
	// Force no-qr and no-clipboard in daemon mode (terminal is detached).
	args = append(args, "--no-qr", "--no-clipboard")

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate binary: %w", err)
	}

	cmd := exec.Command(self, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detachProcess(cmd) // platform-specific: detach from terminal
	if err := cmd.Start(); err != nil {
		return err
	}

	fmt.Printf("\n")
	fmt.Printf(green+"  ✔  mekong running in background"+reset+"\n")
	fmt.Printf(gray+"     PID     "+purple+"%d"+reset+"\n", cmd.Process.Pid)
	fmt.Printf(gray+"     Logs    "+purple+"%s"+reset+"\n", logFilePath())
	fmt.Printf(gray+"     Status  "+purple+"mekong status"+reset+"\n")
	fmt.Printf(gray+"     Stop    "+purple+"mekong stop"+reset+"\n\n")

	return nil
}

// printBanner prints the startup header.
func printBanner(server string, ports []int) {
	portStr := make([]string, len(ports))
	for i, p := range ports {
		portStr[i] = strconv.Itoa(p)
	}
	fmt.Printf("\n")
	fmt.Printf(cyan+"  ███╗   ███╗███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗ \r\n"+
		"  ████╗ ████║██╔════╝██║ ██╔╝██╔═══██╗████╗  ██║██╔════╝ \r\n"+
		"  ██╔████╔██║█████╗  █████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗\r\n"+
		"  ██║╚██╔╝██║██╔══╝  ██╔═██╗ ██║   ██║██║╚██╗██║██║   ██║\r\n"+
		"  ██║ ╚═╝ ██║███████╗██║  ██╗╚██████╔╝██║ ╚████║╚██████╔╝\r\n"+
		"  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ "+reset+"\n")
	fmt.Printf(gray+"  by "+yellow+"Ing Muyleang"+gray+" · Founder of "+yellow+"KhmerStack"+reset+"\n")
	fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n")
	fmt.Printf(gray+"  Server     "+purple+"%s"+reset+"\n", server)
	fmt.Printf(gray+"  Local      "+purple+"localhost:%s"+reset+"\n", strings.Join(portStr, ", "))
	fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n\n")
}

// connect establishes one SSH tunnel session. Returns the tunnel URL and any error.
func connect(server string, sshPort, localPort int, subdomain string, showQR, copyClip bool) (string, error) {
	var auths []ssh.AuthMethod
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if agentConn, err := net.Dial("unix", sock); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
		}
	}
	auths = append(auths, ssh.Password(""))

	user := "tunnel"
	if subdomain != "" {
		user = subdomain
	}

	cfg := &ssh.ClientConfig{
		User:            user,
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
		return "", fmt.Errorf("server rejected port-forward request")
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

	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("shell: %w", err)
	}

	urlCh := make(chan string, 1)
	blockedCh := make(chan string, 1)
	go streamOutput(stdout, urlCh, blockedCh)

	var tunnelURL string
	go func() {
		u, ok := <-urlCh
		if !ok {
			return
		}
		tunnelURL = u
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

	select {
	case msg := <-blockedCh:
		return tunnelURL, fmt.Errorf("%w: %s", errBlocked, msg)
	case <-waitDone:
	}
	return tunnelURL, nil
}

// streamOutput prints every line from the server PTY, extracts the tunnel URL,
// and signals blockedCh if the server reports a blocked IP.
func streamOutput(r io.Reader, urlCh chan<- string, blockedCh chan<- string) {
	scanner := bufio.NewScanner(r)
	urlFound := false
	blockedFound := false
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		clean := strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
		if !urlFound {
			if strings.Contains(clean, "URL") {
				if m := urlRe.FindString(clean); m != "" {
					urlFound = true
					urlCh <- m
				}
			}
		}
		if !blockedFound && strings.Contains(clean, "temporarily blocked") {
			blockedFound = true
			blockedCh <- clean
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
	go func() { io.Copy(local, ch); done <- struct{}{} }()  //nolint:errcheck
	go func() { io.Copy(ch, local); done <- struct{}{} }()  //nolint:errcheck
	<-done
}

// ---- mekong status ----

// runStatus prints active tunnels for the current user.
// If portFilter > 0, only the tunnel for that local port is shown.
func runStatus(portFilter int) {
	state, err := readState()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  error reading state: %v\n", err)
		}
		return
	}

	if !isPIDAlive(state.PID) {
		fmt.Printf("\n%s  No active tunnels (mekong is not running — stale state file).%s\n\n", gray, reset)
		// Clean up stale file automatically.
		removeState()
		return
	}

	// Apply port filter.
	tunnels := state.Tunnels
	if portFilter > 0 {
		filtered := tunnels[:0]
		for _, t := range tunnels {
			if t.LocalPort == portFilter {
				filtered = append(filtered, t)
			}
		}
		tunnels = filtered
	}

	if len(tunnels) == 0 {
		if portFilter > 0 {
			fmt.Printf("\n%s  No active tunnel for port %d.%s\n\n", gray, portFilter, reset)
		} else {
			fmt.Printf("\n%s  No active tunnels.%s\n\n", gray, reset)
		}
		return
	}

	fmt.Printf("\n")
	fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n")
	if portFilter > 0 {
		fmt.Printf(yellow+"  Tunnel for :%d  "+gray+"(PID %d)"+reset+"\n", portFilter, state.PID)
	} else {
		fmt.Printf(yellow+"  Active tunnels  "+gray+"(PID %d)"+reset+"\n", state.PID)
	}
	fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n")

	for _, t := range tunnels {
		uptime := time.Since(t.StartedAt).Round(time.Second)
		fmt.Printf(gray+"  Subdomain  "+purple+"%s"+reset+"\n", t.Subdomain)
		fmt.Printf(gray+"  URL        "+cyan+"%s"+reset+"\n", t.URL)
		fmt.Printf(gray+"  Local      "+purple+"localhost:%d"+reset+"\n", t.LocalPort)
		fmt.Printf(gray+"  Uptime     "+purple+"%s"+reset+"\n", uptime)
		fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n")
	}
	fmt.Printf("\n")
}

// ---- mekong stop ----

// runStop reads the PID from the state file and sends SIGTERM.
func runStop() {
	state, err := readState()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\n%s  No background tunnel to stop.%s\n\n", gray, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  error reading state: %v\n", err)
		}
		return
	}

	if !isPIDAlive(state.PID) {
		fmt.Printf("\n%s  mekong is not running (stale state file cleaned up).%s\n\n", gray, reset)
		removeState()
		return
	}

	p, err := os.FindProcess(state.PID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error finding process: %v\n", err)
		return
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "  error sending signal: %v\n", err)
		return
	}

	removeState()
	fmt.Printf("\n%s  ✔  Stopped mekong (PID %d)%s\n\n", green, state.PID, reset)
}

// ---- self-update ----

func selfUpdate() {
	fmt.Printf("%s  →  Checking for updates...%s\n", gray, reset)

	resp, err := http.Get("https://api.github.com/repos/MuyleangIng/MekongTunnel/releases/latest") //nolint:noctx
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Failed to reach GitHub: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Failed to parse release info: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	latest := release.TagName
	if latest == "" {
		fmt.Fprintf(os.Stderr, "%s  ✖  No release found.%s\n", red, reset)
		os.Exit(1)
	}

	if version != "dev" && version == latest {
		fmt.Printf("%s  ✔  Already up to date (%s).%s\n", green, version, reset)
		return
	}

	var assetName string
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		assetName = "mekong-darwin-arm64"
	case "darwin/amd64":
		assetName = "mekong-darwin-amd64"
	case "linux/amd64":
		assetName = "mekong-linux-amd64"
	case "linux/arm64":
		assetName = "mekong-linux-arm64"
	case "windows/amd64":
		assetName = "mekong-windows-amd64.exe"
	default:
		fmt.Fprintf(os.Stderr, "%s  ✖  Unsupported platform: %s/%s%s\n", red, runtime.GOOS, runtime.GOARCH, reset)
		os.Exit(1)
	}

	downloadURL := fmt.Sprintf("https://github.com/MuyleangIng/MekongTunnel/releases/download/%s/%s", latest, assetName)
	fmt.Printf("%s  →  Downloading %s %s...%s\n", gray, assetName, latest, reset)

	dlResp, err := http.Get(downloadURL) //nolint:noctx
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Download failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%s  ✖  Download failed: HTTP %d%s\n", red, dlResp.StatusCode, reset)
		os.Exit(1)
	}

	currentBinary, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Cannot locate current binary: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	tmpFile, err := os.CreateTemp("", "mekong-update-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Cannot create temp file: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, dlResp.Body); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "%s  ✖  Write failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil { //nolint:gosec
		fmt.Fprintf(os.Stderr, "%s  ✖  chmod failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	if err := os.Rename(tmpPath, currentBinary); err != nil {
		fmt.Fprintf(os.Stderr, "%s  ✖  Replace failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	fmt.Printf("%s  ✔  Updated to %s — restart mekong to use the new version.%s\n", green, latest, reset)
}
