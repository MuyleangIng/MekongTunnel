package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	BaseURL     string
	Mode        string
	Users       int
	Tunnels     int
	Concurrency int
	Password    string
	Timeout     time.Duration
	Cleanup     bool
	LocalPort   int
	RemoteIP    string
}

type apiResponse struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

type registerData struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

type phaseResult struct {
	Name       string
	StartedAt  time.Time
	FinishedAt time.Time
	Total      int
	Success    int64
	Failure    int64
	ReqBytes   int64
	RespBytes  int64
	Durations  []time.Duration
	mu         sync.Mutex
}

type loadTarget struct {
	UserID string
	ID     string
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.BaseURL, "base-url", getenv("TEST_BASE_URL", "http://127.0.0.1:8080"), "API base URL")
	flag.StringVar(&cfg.Mode, "mode", "full", "register, tunnels, or full")
	flag.IntVar(&cfg.Users, "users", 1000, "number of users to create")
	flag.IntVar(&cfg.Tunnels, "tunnels", 5000, "number of tunnel reports to create")
	flag.IntVar(&cfg.Concurrency, "concurrency", 100, "number of concurrent workers")
	flag.StringVar(&cfg.Password, "password", "ChangeMe123!", "password for generated users")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.Cleanup, "cleanup", true, "mark generated tunnels as stopped after the run")
	flag.IntVar(&cfg.LocalPort, "local-port", 3000, "local port to report for synthetic tunnels")
	flag.StringVar(&cfg.RemoteIP, "remote-ip", "127.0.0.1", "remote IP to report for synthetic tunnels")
	flag.Parse()

	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}

	client := &http.Client{Timeout: cfg.Timeout}
	runID := time.Now().UTC().Format("20060102-150405")

	fmt.Printf("Mekong API Bench\n")
	fmt.Printf("Base URL:     %s\n", cfg.BaseURL)
	fmt.Printf("Mode:         %s\n", cfg.Mode)
	fmt.Printf("Users:        %d\n", cfg.Users)
	fmt.Printf("Tunnels:      %d\n", cfg.Tunnels)
	fmt.Printf("Concurrency:  %d\n", cfg.Concurrency)
	fmt.Printf("Cleanup:      %t\n", cfg.Cleanup)
	fmt.Printf("Run ID:       %s\n\n", runID)

	var (
		userIDs   []string
		tunnelIDs []string
		results   []phaseResult
	)

	if cfg.Mode == "register" || cfg.Mode == "full" {
		registerResult, ids, err := runRegisterPhase(client, cfg, runID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "register phase failed: %v\n", err)
			os.Exit(1)
		}
		results = append(results, registerResult)
		userIDs = ids
	}

	if cfg.Mode == "tunnels" || cfg.Mode == "full" {
		tunnelResult, ids, err := runTunnelPhase(client, cfg, runID, userIDs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tunnel phase failed: %v\n", err)
			os.Exit(1)
		}
		results = append(results, tunnelResult)
		tunnelIDs = ids
	}

	if cfg.Cleanup && len(tunnelIDs) > 0 {
		cleanupResult, err := runCleanupPhase(client, cfg, tunnelIDs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cleanup phase failed: %v\n", err)
			os.Exit(1)
		}
		results = append(results, cleanupResult)
	}

	var totalReqBytes int64
	var totalRespBytes int64
	var totalSuccess int64
	var totalFailure int64
	var totalDuration time.Duration
	for _, result := range results {
		printPhase(result)
		totalReqBytes += result.ReqBytes
		totalRespBytes += result.RespBytes
		totalSuccess += result.Success
		totalFailure += result.Failure
		totalDuration += result.FinishedAt.Sub(result.StartedAt)
	}

	fmt.Printf("Overall\n")
	fmt.Printf("  Success:    %d\n", totalSuccess)
	fmt.Printf("  Failed:     %d\n", totalFailure)
	fmt.Printf("  Req bytes:  %d\n", totalReqBytes)
	fmt.Printf("  Resp bytes: %d\n", totalRespBytes)
	fmt.Printf("  Duration:   %s\n\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("Note: this tool measures the API control plane only.\n")
	fmt.Printf("It does not benchmark real SSH tunnel transport, HTTPS proxy bandwidth, or internet egress.\n")
}

func runRegisterPhase(client *http.Client, cfg config, runID string) (phaseResult, []string, error) {
	result := phaseResult{Name: "register", Total: cfg.Users, StartedAt: time.Now()}
	userIDs := make([]string, 0, cfg.Users)
	var mu sync.Mutex

	err := runWorkers(cfg.Users, cfg.Concurrency, func(i int) error {
		email := fmt.Sprintf("loaduser-%s-%04d@local.test", runID, i)
		body := map[string]any{
			"name":     fmt.Sprintf("Load User %04d", i),
			"email":    email,
			"password": cfg.Password,
		}
		respBody, reqBytes, respBytes, dur, err := doJSON(client, http.MethodPost, cfg.BaseURL+"/api/auth/register", body)
		recordResult(&result, reqBytes, respBytes, dur, err == nil)
		if err != nil {
			return err
		}

		var envelope apiResponse
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return err
		}
		if !envelope.OK {
			return fmt.Errorf("register failed: %s", envelope.Error)
		}

		var data registerData
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			return err
		}
		mu.Lock()
		userIDs = append(userIDs, data.User.ID)
		mu.Unlock()
		return nil
	})
	result.FinishedAt = time.Now()
	return result, userIDs, err
}

func runTunnelPhase(client *http.Client, cfg config, runID string, userIDs []string) (phaseResult, []string, error) {
	result := phaseResult{Name: "tunnels", Total: cfg.Tunnels, StartedAt: time.Now()}
	tunnelIDs := make([]string, 0, cfg.Tunnels)
	var mu sync.Mutex

	err := runWorkers(cfg.Tunnels, cfg.Concurrency, func(i int) error {
		tunnelID := fmt.Sprintf("load-%s-%05d", runID, i)
		subdomain := fmt.Sprintf("load-%s-%05d", strings.ToLower(runID), i)
		var userID any
		if len(userIDs) > 0 {
			userID = userIDs[i%len(userIDs)]
		}
		body := map[string]any{
			"id":         tunnelID,
			"user_id":    userID,
			"subdomain":  subdomain,
			"local_port": cfg.LocalPort,
			"remote_ip":  cfg.RemoteIP,
			"status":     "active",
			"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		}

		_, reqBytes, respBytes, dur, err := doJSON(client, http.MethodPost, cfg.BaseURL+"/api/tunnels", body)
		recordResult(&result, reqBytes, respBytes, dur, err == nil)
		if err != nil {
			return err
		}
		mu.Lock()
		tunnelIDs = append(tunnelIDs, tunnelID)
		mu.Unlock()
		return nil
	})
	result.FinishedAt = time.Now()
	return result, tunnelIDs, err
}

func runCleanupPhase(client *http.Client, cfg config, tunnelIDs []string) (phaseResult, error) {
	result := phaseResult{Name: "cleanup", Total: len(tunnelIDs), StartedAt: time.Now()}
	err := runWorkers(len(tunnelIDs), cfg.Concurrency, func(i int) error {
		body := map[string]any{"status": "stopped"}
		_, reqBytes, respBytes, dur, err := doJSON(client, http.MethodPatch, cfg.BaseURL+"/api/tunnels/"+tunnelIDs[i], body)
		recordResult(&result, reqBytes, respBytes, dur, err == nil)
		return err
	})
	result.FinishedAt = time.Now()
	return result, err
}

func runWorkers(total, concurrency int, fn func(int) error) error {
	if total == 0 {
		return nil
	}
	type jobResult struct {
		err error
	}

	jobs := make(chan int)
	results := make(chan jobResult, total)
	var wg sync.WaitGroup

	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results <- jobResult{err: fn(i)}
			}
		}()
	}

	go func() {
		for i := 0; i < total; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
	}
	return firstErr
}

func doJSON(client *http.Client, method, url string, body any) ([]byte, int64, int64, time.Duration, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, int64(len(payload)), 0, time.Since(start), err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, int64(len(payload)), 0, time.Since(start), err
	}
	if resp.StatusCode >= 300 {
		return respBody, int64(len(payload)), int64(len(respBody)), time.Since(start), fmt.Errorf("%s %s returned %d: %s", method, url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, int64(len(payload)), int64(len(respBody)), time.Since(start), nil
}

func recordResult(result *phaseResult, reqBytes, respBytes int64, dur time.Duration, ok bool) {
	if ok {
		atomic.AddInt64(&result.Success, 1)
	} else {
		atomic.AddInt64(&result.Failure, 1)
	}
	atomic.AddInt64(&result.ReqBytes, reqBytes)
	atomic.AddInt64(&result.RespBytes, respBytes)
	result.mu.Lock()
	result.Durations = append(result.Durations, dur)
	result.mu.Unlock()
}

func printPhase(result phaseResult) {
	fmt.Printf("%s phase\n", strings.Title(result.Name))
	fmt.Printf("  Success:    %d / %d\n", result.Success, result.Total)
	fmt.Printf("  Failed:     %d\n", result.Failure)
	fmt.Printf("  Duration:   %s\n", result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond))
	if seconds := result.FinishedAt.Sub(result.StartedAt).Seconds(); seconds > 0 {
		fmt.Printf("  Throughput: %.2f req/s\n", float64(result.Total)/seconds)
	}
	if len(result.Durations) > 0 {
		p50, p95, max := latencySummary(result.Durations)
		fmt.Printf("  Latency:    p50=%s p95=%s max=%s\n", p50.Round(time.Millisecond), p95.Round(time.Millisecond), max.Round(time.Millisecond))
	}
	fmt.Printf("  Req bytes:  %d\n", result.ReqBytes)
	fmt.Printf("  Resp bytes: %d\n\n", result.RespBytes)
}

func latencySummary(samples []time.Duration) (time.Duration, time.Duration, time.Duration) {
	clone := append([]time.Duration(nil), samples...)
	sort.Slice(clone, func(i, j int) bool { return clone[i] < clone[j] })
	return percentile(clone, 50), percentile(clone, 95), clone[len(clone)-1]
}

func percentile(samples []time.Duration, p int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	if p <= 0 {
		return samples[0]
	}
	if p >= 100 {
		return samples[len(samples)-1]
	}
	index := (len(samples) - 1) * p / 100
	return samples[index]
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
