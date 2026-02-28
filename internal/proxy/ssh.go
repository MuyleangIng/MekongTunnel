// SSH connection handling for MekongTunnel.
// This file accepts incoming SSH connections, negotiates port forwarding,
// assigns a memorable subdomain, and streams live HTTP request logs
// back to the SSH terminal.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

// tcpipForwardRequest is the SSH wire format for a "tcpip-forward" global request.
// The client sends this to ask the server to start listening on bindAddr:bindPort.
type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

// forwardedTCPPayload is the SSH wire format for opening a "forwarded-tcpip" channel.
// The server sends this when a new TCP connection arrives on the tunnel listener.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// HandleSSHConnection is the main entry point for every new TCP connection on the SSH port.
// It performs the full tunnel lifecycle:
//
//  1. SSH handshake (30s deadline)
//  2. Rate-limit / block check and connection-slot reservation
//  3. Unique subdomain assignment
//  4. Internal TCP listener creation
//  5. Wait for the client's "tcpip-forward" global request
//  6. Tunnel registration and URL display to the SSH terminal
//  7. Accept connections on the internal listener, forward each via SSH
//  8. Inactivity and max-lifetime monitoring
//  9. Graceful cleanup via deferred calls
func (s *Server) HandleSSHConnection(conn net.Conn) {
	clientIP := "unknown"
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			clientIP = tcpAddr.IP.String()
		}
		// TCP_NODELAY avoids spurious errors from the SSH library on some platforms.
		tcpConn.SetNoDelay(true)
	}

	// Perform SSH handshake with a hard deadline so slow clients cannot stall the server.
	conn.SetDeadline(time.Now().Add(config.SSHHandshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after successful handshake
	defer sshConn.Close()

	// Enforce rate limits AFTER the handshake so we can send a human-readable error.
	if err := s.CheckAndReserveConnection(clientIP); err != nil {
		log.Printf("Connection rejected from %s: %v", clientIP, err)
		go ssh.DiscardRequests(reqs)
		s.sendErrorAndClose(sshConn, chans, err.Error())
		return
	}
	// Connection slot reserved — must be released when this function returns.
	defer s.DecrementIPConnection(clientIP)

	// Track connection so the abuse tracker can force-close it on IP block.
	s.RegisterSSHConn(clientIP, sshConn)
	defer s.UnregisterSSHConn(clientIP, sshConn)

	s.IncrementConnections()

	log.Printf("New SSH connection from %s", sshConn.RemoteAddr())

	sub, err := s.GenerateUniqueSubdomain()
	if err != nil {
		log.Printf("Failed to assign subdomain: %v", err)
		return
	}
	log.Printf("Assigned subdomain: %s", sub)

	// Create an internal TCP listener. The HTTP proxy will dial this address
	// and the SSH handler will forward connections from it back to the client.
	tunnelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("Failed to create tunnel listener: %v", err)
		return
	}
	defer tunnelListener.Close()

	var bindAddr string
	var bindPort uint32
	tunnelRegistered := make(chan struct{})
	var tun *tunnel.Tunnel

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle global SSH requests (port forwarding negotiation).
	// Runs in a goroutine because Accept() on chans can block.
	go func() {
		for {
			select {
			case req, ok := <-reqs:
				if !ok {
					return
				}
				switch req.Type {
				case "tcpip-forward":
					// Client requests port forwarding; parse bind address/port.
					var fwdReq tcpipForwardRequest
					if err := ssh.Unmarshal(req.Payload, &fwdReq); err != nil {
						req.Reply(false, nil)
						continue
					}
					bindAddr = fwdReq.BindAddr
					bindPort = fwdReq.BindPort
					tun = s.RegisterTunnel(sub, tunnelListener, bindAddr, bindPort, clientIP)
					tun.SetSSHConn(sshConn)
					close(tunnelRegistered) // signal main goroutine that tunnel is ready
					req.Reply(true, nil)
				case "cancel-tcpip-forward":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for the tunnel to be registered or time out.
	select {
	case <-tunnelRegistered:
	case <-time.After(30 * time.Second):
		log.Printf("Timeout waiting for tcpip-forward request from %s", sshConn.RemoteAddr())
		return
	}

	// Remove tunnel from registry when this function returns (SSH disconnect).
	defer s.RemoveTunnel(sub)

	// Build the public URL and compose the terminal welcome message.
	url := fmt.Sprintf("https://%s.%s", sub, s.domain)
	expiresAt := tun.CreatedAt.Add(config.MaxTunnelLifetime).Format("Jan 02, 2006 at 15:04 MST")
	expiresLine := fmt.Sprintf("%s (or %s idle)", expiresAt, formatDuration(config.InactivityTimeout))

	const (
		reset     = "\033[0m"
		gray      = "\033[38;5;245m"
		boldGreen = "\033[1;32m"
		purple    = "\033[38;5;141m"
		cyan      = "\033[1;36m"
		yellow    = "\033[1;33m"
	)

	urlMessage := "\r\n" +
		cyan + "  ███╗   ███╗███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗ \r\n" +
		"  ████╗ ████║██╔════╝██║ ██╔╝██╔═══██╗████╗  ██║██╔════╝ \r\n" +
		"  ██╔████╔██║█████╗  █████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗\r\n" +
		"  ██║╚██╔╝██║██╔══╝  ██╔═██╗ ██║   ██║██║╚██╗██║██║   ██║\r\n" +
		"  ██║ ╚═╝ ██║███████╗██║  ██╗╚██████╔╝██║ ╚████║╚██████╔╝\r\n" +
		"  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ " + reset + "\r\n" +
		"\r\n" +
		gray + "  by " + yellow + "Ing Muyleang" + gray + " · Founder of " + yellow + "KhmerStack" + reset + "\r\n" +
		gray + "  ─────────────────────────────────────────────────────" + reset + "\r\n" +
		boldGreen + "  ✔  Tunnel is live!" + reset + "\r\n" +
		gray + "     URL      " + purple + url + reset + "\r\n" +
		gray + "     Expires  " + expiresLine + reset + "\r\n\r\n"

	// Background goroutine: close SSH connection if tunnel is idle or past max lifetime.
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if tun.IsExpired() {
					log.Printf("Tunnel %s expired due to inactivity", sub)
					sshConn.Close()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// The client must have passed -t (allocate TTY) for the session channel to appear.
	// Without -t the URL message cannot be displayed.
	sessionReceived := make(chan ssh.NewChannel, 1)
	go func() {
		for {
			select {
			case newChannel, ok := <-chans:
				if !ok {
					return
				}
				if newChannel.ChannelType() == "session" {
					sessionReceived <- newChannel
					return
				}
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			case <-ctx.Done():
				return
			}
		}
	}()

	var sessionChannel ssh.NewChannel
	select {
	case sessionChannel = <-sessionReceived:
	case <-time.After(5 * time.Second):
		log.Printf("Connection from %s rejected: no session channel (use ssh -t)", sshConn.RemoteAddr())
		return
	}

	channel, requests, err := sessionChannel.Accept()
	if err != nil {
		log.Printf("Failed to accept session channel: %v", err)
		return
	}

	// Print the URL and expiry to the SSH terminal.
	fmt.Fprint(channel, urlMessage)

	// Attach an async request logger so HTTP hits are streamed to the SSH terminal.
	logger := tunnel.NewRequestLogger(channel, config.LogBufferSize)
	tun.SetLogger(logger)
	defer logger.Close()

	// Accept incoming connections on the internal listener and proxy each to SSH.
	go func() {
		for {
			tcpConn, err := tunnelListener.Accept()
			if err != nil {
				return
			}
			tun.Touch() // reset inactivity timer on every new connection
			go s.forwardToSSH(sshConn, tcpConn, tun)
		}
	}()

	// Handle SSH session requests (pty-req, shell, signal).
	go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for req := range reqs {
			switch req.Type {
			case "pty-req", "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "signal":
				// Ctrl+C arrives as a "signal" request — close the connection.
				if req.WantReply {
					req.Reply(true, nil)
				}
				sshConn.Close()
				return
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}(channel, requests)

	// Read from channel to detect disconnect or Ctrl+C (0x03 byte).
	buf := make([]byte, 1)
	for {
		_, err := channel.Read(buf)
		if err != nil {
			break
		}
		if buf[0] == 0x03 { // Ctrl+C
			sshConn.Close()
			break
		}
	}

	log.Printf("SSH connection closed for subdomain: %s", sub)
}

// sendErrorAndClose sends a human-readable error message to the SSH client
// via its session channel and then closes the connection.
// Used when a connection is rejected after the handshake (e.g. IP is blocked).
func (s *Server) sendErrorAndClose(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, errMsg string) {
	select {
	case newChannel, ok := <-chans:
		if !ok {
			return
		}
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				if req.Type == "pty-req" || req.Type == "shell" {
					if req.WantReply {
						req.Reply(true, nil)
					}
				} else if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}()
		fmt.Fprintf(channel, "\r\n  ERROR: %s\r\n\r\n", errMsg)
		channel.Close()
	case <-time.After(3 * time.Second):
		return
	}
}

// forwardToSSH opens a "forwarded-tcpip" SSH channel and copies data bidirectionally
// between tcpConn (the HTTP proxy's connection to the internal listener) and the SSH channel
// (which the SSH client forwards to the user's local application).
func (s *Server) forwardToSSH(sshConn *ssh.ServerConn, tcpConn net.Conn, tun *tunnel.Tunnel) {
	defer tcpConn.Close()

	var originAddr string
	var originPort uint32
	if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		originAddr = tcpAddr.IP.String()
		originPort = uint32(tcpAddr.Port)
	} else {
		originAddr = "0.0.0.0"
		originPort = 0
	}

	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&forwardedTCPPayload{
		Addr:       tun.BindAddr,
		Port:       tun.BindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	}))
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	// Bidirectional copy: when one direction finishes, signal the SSH channel
	// that no more data will be sent, which lets the other direction drain cleanly.
	done := make(chan struct{})
	go func() {
		io.Copy(channel, tcpConn)
		channel.CloseWrite()
	}()
	go func() {
		defer close(done)
		io.Copy(tcpConn, channel)
	}()
	<-done
}

// formatDuration formats a duration as a compact human-readable string.
// Examples: 2*time.Hour → "2h", 45*time.Minute → "45m".
func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
