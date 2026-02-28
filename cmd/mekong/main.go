// mekong — CLI client for MekongTunnel.
// Exposes a local port to the internet via MekongTunnel with one command:
//
//	mekong 3000
//	mekong 8080 --server myserver.com
//
// Features: auto-reconnect, QR code in terminal, clipboard copy.
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
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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
// The main loop treats this as a permanent failure and stops retrying.
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

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "update":
			selfUpdate()
			return
		case "version", "--version", "-v":
			fmt.Printf("mekong %s\n", version)
			return
		}
	}

	var (
		serverFlag  = flag.String("server", "mekongtunnel.dev", "MekongTunnel server hostname")
		portFlag    = flag.Int("port", 22, "SSH server port")
		noQR        = flag.Bool("no-qr", false, "Disable QR code display")
		noClip      = flag.Bool("no-clipboard", false, "Disable auto clipboard copy")
		noReconnect = flag.Bool("no-reconnect", false, "Disable auto-reconnect on disconnect")
	)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Usage: mekong [flags] <local-port>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Examples:")
		fmt.Fprintln(os.Stderr, "    mekong 3000                         expose localhost:3000")
		fmt.Fprintln(os.Stderr, "    mekong 8080                         expose localhost:8080")
		fmt.Fprintln(os.Stderr, "    mekong 5173 --server myserver.com   use a custom server")
		fmt.Fprintln(os.Stderr, "    mekong 3000 --no-qr                 no QR code")
		fmt.Fprintln(os.Stderr, "    mekong 3000 --no-reconnect          exit on disconnect")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	localPort, err := strconv.Atoi(flag.Arg(0))
	if err != nil || localPort < 1 || localPort > 65535 {
		fmt.Fprintf(os.Stderr, "  error: invalid port %q\n", flag.Arg(0))
		os.Exit(1)
	}

	// Graceful Ctrl+C / SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Printf("\n%s  ✖  Disconnected. Goodbye!%s\n\n", yellow, reset)
		os.Exit(0)
	}()

	printBanner(*serverFlag, localPort)

	backoff := 2 * time.Second
	attempt := 0
	for {
		attempt++
		if attempt > 1 {
			fmt.Printf("%s  ↺  Reconnecting in %s...%s\n", yellow, backoff, reset)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
		} else {
			backoff = 2 * time.Second
		}

		if err := connect(*serverFlag, *portFlag, localPort, !*noQR, !*noClip); err != nil {
			fmt.Printf("%s  ✖  %v%s\n", red, err, reset)
			if errors.Is(err, errBlocked) {
				fmt.Printf("%s  ✖  Reconnect aborted — wait for the block to expire, then try again.%s\n\n", red, reset)
				os.Exit(1)
			}
		}

		if *noReconnect {
			break
		}
	}
}

// printBanner prints the startup header.
func printBanner(server string, localPort int) {
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
	fmt.Printf(gray+"  Local      "+purple+"localhost:%d"+reset+"\n", localPort)
	fmt.Printf(gray+"  ─────────────────────────────────────────────────────"+reset+"\n\n")
}

// connect establishes one SSH tunnel session. Returns when the session ends.
func connect(server string, sshPort, localPort int, showQR, copyClip bool) error {
	// Build auth — try SSH agent first, server accepts no-auth so it's fine either way
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
	fmt.Printf("%s  →  Connecting to %s...%s\n", gray, server, reset)

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// Ask server to listen on port 80 and forward connections to us
	payload := ssh.Marshal(tcpIPForwardReq{BindAddr: "", BindPort: 80})
	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		return fmt.Errorf("port-forward request error: %w", err)
	}
	if !ok {
		return fmt.Errorf("server rejected port-forward request")
	}

	// Handle incoming forwarded-tcpip channels (HTTP requests proxied from server)
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

	// Open a PTY session — server writes the banner + URL here
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session error: %w", err)
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
		return fmt.Errorf("pty error: %w", err)
	}

	// Keep stdin open so the server's channel.Read() blocks instead of getting EOF.
	// Without this the server immediately closes the connection.
	_, err = sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := sess.Shell(); err != nil {
		return fmt.Errorf("shell: %w", err)
	}

	// Stream server output to terminal; extract the public URL on first match
	// and signal if the server reports a blocked IP.
	urlCh := make(chan string, 1)
	blockedCh := make(chan string, 1)
	go streamOutput(stdout, urlCh, blockedCh)

	// Once URL is found: copy to clipboard + print QR code
	go func() {
		tunnelURL, ok := <-urlCh
		if !ok {
			return
		}
		if copyClip {
			if err := clipboard.WriteAll(tunnelURL); err == nil {
				fmt.Printf("%s  ✔  Copied to clipboard!%s\n", green, reset)
			}
		}
		if showQR {
			fmt.Printf("\n%s  Scan with your phone:%s\n\n", gray, reset)
			qrterminal.GenerateHalfBlock(tunnelURL, qrterminal.L, os.Stdout)
			fmt.Println()
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()

	select {
	case msg := <-blockedCh:
		return fmt.Errorf("%w: %s", errBlocked, msg)
	case <-waitDone:
	}
	return nil
}

// streamOutput prints every line from the server PTY, sends the first tunnel
// URL it finds on urlCh, and signals blockedCh if the server reports a blocked IP.
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

// selfUpdate checks GitHub for the latest release and replaces the running binary.
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

	// Determine asset name for this platform
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

	// Write to a temp file next to the current binary so os.Rename is atomic
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
	defer os.Remove(tmpPath) // clean up on failure

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

// proxyToLocal accepts a forwarded-tcpip SSH channel and proxies it to localhost:port.
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
