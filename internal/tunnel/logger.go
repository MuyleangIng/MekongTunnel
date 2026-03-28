// Async request logger that streams formatted HTTP request lines
// to an SSH terminal (io.Writer) without blocking the proxy goroutine.
//
// Log lines are queued in a buffered channel (default 128 entries).
// A single drain goroutine reads from the channel and writes to the writer.
// If the channel is full the log line is silently dropped — the tunnel
// is never blocked by slow SSH output.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package tunnel

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
)

const maxPathDisplay = 50

// RequestLogger writes formatted request logs to an io.Writer (typically an SSH channel).
// It uses a buffered channel and a single drain goroutine to avoid blocking callers.
type RequestLogger struct {
	w         io.Writer
	ch        chan string
	done      chan struct{}
	closeOnce sync.Once

	mu          sync.Mutex
	history     []string
	historySize int
	nextIndex   int
	subscribers map[chan string]struct{}
}

// NewRequestLogger creates a RequestLogger that writes to w with the given buffer size.
// A background goroutine is started immediately to drain the channel.
func NewRequestLogger(w io.Writer, bufSize int) *RequestLogger {
	l := &RequestLogger{
		w:           w,
		ch:          make(chan string, bufSize),
		done:        make(chan struct{}),
		history:     make([]string, 0, maxInt(config.LogHistorySize, maxInt(1, bufSize))),
		historySize: maxInt(config.LogHistorySize, maxInt(1, bufSize)),
		subscribers: make(map[chan string]struct{}),
	}
	go l.drain()
	return l
}

// drain reads log lines from the channel and writes them to the underlying writer.
// Runs until the channel is closed by Close().
func (l *RequestLogger) drain() {
	defer close(l.done)
	for line := range l.ch {
		l.w.Write([]byte(line))
	}
}

// LogRequest queues a formatted HTTP request log line.
// The line includes method, path (truncated to 50 chars), HTTP status, and latency.
// Drops silently if the buffer is full.
func (l *RequestLogger) LogRequest(method, path string, status int, latency time.Duration) {
	line := formatRequestLog(method, path, status, latency)
	l.record(line)
	select {
	case l.ch <- line:
	default:
	}
}

// LogWebSocketOpen queues a log line indicating a WebSocket connection was opened.
// Drops silently if the buffer is full.
func (l *RequestLogger) LogWebSocketOpen(path string) {
	line := formatWSOpen(path)
	l.record(line)
	select {
	case l.ch <- line:
	default:
	}
}

// LogWebSocketClose queues a log line indicating a WebSocket connection was closed,
// including the session duration and total bytes transferred.
// Drops silently if the buffer is full.
func (l *RequestLogger) LogWebSocketClose(path string, duration time.Duration, bytes int64) {
	line := formatWSClose(path, duration, bytes)
	l.record(line)
	select {
	case l.ch <- line:
	default:
	}
}

// Snapshot returns the currently retained log lines in oldest-first order.
func (l *RequestLogger) Snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.history) == 0 {
		return nil
	}
	if len(l.history) < l.historySize || l.nextIndex == 0 {
		out := make([]string, len(l.history))
		copy(out, l.history)
		return out
	}

	out := make([]string, 0, len(l.history))
	out = append(out, l.history[l.nextIndex:]...)
	out = append(out, l.history[:l.nextIndex]...)
	return out
}

// Subscribe returns a non-blocking live feed channel and an unsubscribe function.
func (l *RequestLogger) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 32)

	l.mu.Lock()
	l.subscribers[ch] = struct{}{}
	l.mu.Unlock()

	unsubscribe := func() {
		l.mu.Lock()
		if _, ok := l.subscribers[ch]; ok {
			delete(l.subscribers, ch)
			close(ch)
		}
		l.mu.Unlock()
	}

	return ch, unsubscribe
}

// Close stops the logger by closing the channel and waiting for the drain goroutine
// to finish writing any queued messages. Safe to call multiple times (idempotent).
func (l *RequestLogger) Close() {
	l.closeOnce.Do(func() {
		close(l.ch)
	})
	<-l.done

	l.mu.Lock()
	for ch := range l.subscribers {
		close(ch)
		delete(l.subscribers, ch)
	}
	l.mu.Unlock()
}

func (l *RequestLogger) record(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.history) < l.historySize {
		l.history = append(l.history, line)
	} else {
		l.history[l.nextIndex] = line
		l.nextIndex = (l.nextIndex + 1) % l.historySize
	}

	for ch := range l.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// truncatePath shortens path to maxPathDisplay characters with "..." suffix if needed.
func truncatePath(path string) string {
	if len(path) > maxPathDisplay {
		return path[:maxPathDisplay-3] + "..."
	}
	return path
}

// formatRequestLog returns a formatted log line for an HTTP request.
// Example: "  GET  /api/users                                      200  45ms"
func formatRequestLog(method, path string, status int, latency time.Duration) string {
	return fmt.Sprintf("  %-4s %-53s %d  %s\r\n", method, truncatePath(path), status, formatLatency(latency))
}

// formatWSOpen returns a log line for a WebSocket connection opening.
func formatWSOpen(path string) string {
	return fmt.Sprintf("  %-4s %-53s -    OPEN\r\n", "WS", truncatePath(path))
}

// formatWSClose returns a log line for a WebSocket connection closing.
func formatWSClose(path string, duration time.Duration, bytes int64) string {
	return fmt.Sprintf("  %-4s %-53s -    CLOSED (%s, %s)\r\n", "WS", truncatePath(path), formatDurationHuman(duration), formatBytes(bytes))
}

// formatLatency converts a duration to a compact string: "45ms" or "123us".
func formatLatency(d time.Duration) string {
	if d < time.Millisecond {
		us := d.Microseconds()
		if us == 0 {
			return "<1us"
		}
		return fmt.Sprintf("%dus", us)
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// formatDurationHuman converts a duration to a human-readable string like "2h30m" or "45s".
func formatDurationHuman(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// formatBytes converts a byte count to a human-readable string like "1.5MB" or "256B".
func formatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	}
}
