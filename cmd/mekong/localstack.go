package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type projectConfig struct {
	Port         int    `json:"port,omitempty"`
	UpstreamHost string `json:"upstream_host,omitempty"`
	Start        string `json:"start,omitempty"`
	Stack        string `json:"stack,omitempty"`
}

type detectedProject struct {
	Stack        string   `json:"stack"`
	Source       string   `json:"source"`
	Port         int      `json:"port"`
	Start        string   `json:"start,omitempty"`
	UpstreamHost string   `json:"upstream_host,omitempty"`
	Running      bool     `json:"running"`
	Notes        []string `json:"notes,omitempty"`
}

type packageManifest struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

var portArgRe = regexp.MustCompile(`(?:--port|-p)[=\s]+(\d+)`)

func projectConfigPath(dir string) string {
	return filepath.Join(dir, ".mekong.json")
}

func loadProjectConfig() (*projectConfig, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return loadProjectConfigFromDir(dir)
}

func loadProjectConfigFromDir(dir string) (*projectConfig, error) {
	path := projectConfigPath(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg projectConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

func writeProjectConfig(path string, cfg *projectConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}

func normalizeUpstreamHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")
	if host == "" {
		return "", nil
	}
	if strings.Contains(host, "/") || strings.Contains(host, " ") {
		return "", fmt.Errorf("invalid upstream host %q", raw)
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("upstream host should not include a port: %q", raw)
	}
	return host, nil
}

func extractPortFromScripts(scripts map[string]string) int {
	for _, key := range []string{"dev", "start"} {
		script := strings.TrimSpace(scripts[key])
		if script == "" {
			continue
		}
		if m := portArgRe.FindStringSubmatch(script); len(m) == 2 {
			var port int
			_, _ = fmt.Sscanf(m[1], "%d", &port)
			if port >= 1 && port <= 65535 {
				return port
			}
		}
	}
	return 0
}

func detectNodeProject(dir string) (*detectedProject, error) {
	path := filepath.Join(dir, "package.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var pkg packageManifest
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	deps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		deps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		deps[k] = v
	}

	type frameworkSpec struct {
		keys  []string
		stack string
		port  int
	}
	specs := []frameworkSpec{
		{keys: []string{"next"}, stack: "nextjs", port: 3000},
		{keys: []string{"nuxt", "nuxt3"}, stack: "nuxt", port: 3000},
		{keys: []string{"vite"}, stack: "vite", port: 5173},
		{keys: []string{"react-scripts"}, stack: "react", port: 3000},
		{keys: []string{"@angular/core"}, stack: "angular", port: 4200},
		{keys: []string{"@sveltejs/kit", "svelte"}, stack: "svelte", port: 5173},
		{keys: []string{"astro"}, stack: "astro", port: 4321},
		{keys: []string{"gatsby"}, stack: "gatsby", port: 8000},
		{keys: []string{"remix", "@remix-run/react"}, stack: "remix", port: 3000},
		{keys: []string{"express", "fastify", "koa", "hono"}, stack: "node", port: 3000},
	}

	var stack string
	port := extractPortFromScripts(pkg.Scripts)
	start := strings.TrimSpace(pkg.Scripts["dev"])
	if start == "" {
		start = strings.TrimSpace(pkg.Scripts["start"])
	}
	for _, spec := range specs {
		for _, key := range spec.keys {
			if _, ok := deps[key]; ok {
				stack = spec.stack
				if port == 0 {
					port = spec.port
				}
				break
			}
		}
		if stack != "" {
			break
		}
	}

	if stack == "" && start == "" {
		return nil, nil
	}
	if stack == "" {
		stack = "node"
	}
	if port == 0 {
		port = 3000
	}

	return &detectedProject{
		Stack:   stack,
		Source:  "package.json",
		Port:    port,
		Start:   start,
		Running: isPortListening(port),
	}, nil
}

func detectPythonProject(dir string) (*detectedProject, error) {
	if _, err := os.Stat(filepath.Join(dir, "manage.py")); err == nil {
		return &detectedProject{
			Stack:   "django",
			Source:  "manage.py",
			Port:    8000,
			Start:   "python manage.py runserver 8000",
			Running: isPortListening(8000),
		}, nil
	}

	packages := map[string]struct{}{}
	for _, file := range []string{"requirements.txt", "pyproject.toml"} {
		content, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name := strings.FieldsFunc(line, func(r rune) bool {
				switch r {
				case '=', '>', '<', '!', '[', ' ', '"', '\'':
					return true
				default:
					return false
				}
			})
			if len(name) == 0 {
				continue
			}
			packages[strings.ToLower(name[0])] = struct{}{}
		}
	}

	type frameworkSpec struct {
		name  string
		stack string
		port  int
		start string
	}
	specs := []frameworkSpec{
		{name: "fastapi", stack: "fastapi", port: 8000, start: "uvicorn main:app --reload --port 8000"},
		{name: "flask", stack: "flask", port: 5000, start: "flask run --port 5000"},
		{name: "django", stack: "django", port: 8000, start: "python manage.py runserver 8000"},
		{name: "starlette", stack: "starlette", port: 8000, start: "uvicorn main:app --reload --port 8000"},
		{name: "hypercorn", stack: "hypercorn", port: 8000, start: "hypercorn main:app --bind 127.0.0.1:8000"},
	}
	for _, spec := range specs {
		if _, ok := packages[spec.name]; ok {
			return &detectedProject{
				Stack:   spec.stack,
				Source:  spec.name,
				Port:    spec.port,
				Start:   spec.start,
				Running: isPortListening(spec.port),
			}, nil
		}
	}
	return nil, nil
}

func composerRequireField(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var data struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("parse composer.json: %w", err)
	}
	return data.Require, nil
}

func firstListeningPort(ports ...int) int {
	for _, port := range ports {
		if isPortListening(port) {
			return port
		}
	}
	return 0
}

func detectPHPProject(dir string) (*detectedProject, error) {
	require, err := composerRequireField(dir)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(filepath.Join(dir, "artisan")); err == nil {
		port := 8000
		return &detectedProject{
			Stack:   "laravel",
			Source:  "artisan",
			Port:    port,
			Start:   "php artisan serve --host=127.0.0.1 --port 8000",
			Running: isPortListening(port),
			Notes: []string{
				"Laravel works well with `php artisan serve`.",
				"If you use Laragon, XAMPP, or WAMP vhosts, also set `upstream_host`.",
			},
		}, nil
	}

	if require != nil {
		if _, ok := require["laravel/framework"]; ok {
			port := 8000
			return &detectedProject{
				Stack:   "laravel",
				Source:  "composer.json",
				Port:    port,
				Start:   "php artisan serve --host=127.0.0.1 --port 8000",
				Running: isPortListening(port),
				Notes: []string{
					"Laravel detected from composer.json.",
					"If you use local Apache vhosts, set `upstream_host` to your local hostname such as `myapp.test`.",
				},
			}, nil
		}
	}

	hasPHPMarker := false
	for _, rel := range []string{"composer.json", "public/index.php", "index.php"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			hasPHPMarker = true
			break
		}
	}
	if !hasPHPMarker {
		return nil, nil
	}

	port := firstListeningPort(80, 8080, 8081)
	if port == 0 {
		port = 80
	}

	return &detectedProject{
		Stack:   "php",
		Source:  "php-files",
		Port:    port,
		Running: isPortListening(port),
		Notes: []string{
			"Generic PHP stack detected.",
			"For Laragon, XAMPP, or WAMP with local domains like `myapp.test`, set `upstream_host`.",
			"Common Apache ports are 80, 8080, and 8081.",
		},
	}, nil
}

func detectWordPressProject(dir string) (*detectedProject, error) {
	if _, err := os.Stat(filepath.Join(dir, "wp-config.php")); err != nil {
		if os.IsNotExist(err) {
			if _, err := os.Stat(filepath.Join(dir, "wp-content")); err != nil {
				if os.IsNotExist(err) {
					return nil, nil
				}
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	port := firstListeningPort(80, 8080, 8081)
	if port == 0 {
		port = 80
	}
	return &detectedProject{
		Stack:   "wordpress",
		Source:  "wp-config.php",
		Port:    port,
		Running: isPortListening(port),
		Notes: []string{
			"WordPress usually runs behind Apache or Nginx on 80, 8080, or 8081.",
			"If your local site uses a host like `wordpress.test`, set `upstream_host`.",
		},
	}, nil
}

func detectStaticWebProject(dir string) (*detectedProject, error) {
	for _, rel := range []string{"index.html", "index.htm", "public/index.html", "public/index.htm"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			port := firstListeningPort(80, 8080, 8081)
			if port == 0 {
				port = 80
			}
			return &detectedProject{
				Stack:   "web",
				Source:  rel,
				Port:    port,
				Running: isPortListening(port),
				Notes: []string{
					"Static HTML site detected.",
					"If this runs through XAMPP, WAMP, Laragon, or Apache vhosts, set `upstream_host`.",
				},
			}, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return nil, nil
}

func detectProject(dir string) (*detectedProject, error) {
	for _, detect := range []func(string) (*detectedProject, error){
		detectWordPressProject,
		detectPHPProject,
		detectNodeProject,
		detectPythonProject,
		detectStaticWebProject,
	} {
		project, err := detect(dir)
		if err != nil {
			return nil, err
		}
		if project != nil {
			return project, nil
		}
	}
	return nil, fmt.Errorf("could not detect a supported local stack in %s", dir)
}

func isPortListening(port int) bool {
	conn, err := dialLocalTarget(port)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func printDetectedProject(project *detectedProject, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(project, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
		return nil
	}

	fmt.Printf("\n")
	fmt.Printf(green+"  ✔  Detected "+reset+yellow+"%s"+reset+"\n", project.Stack)
	fmt.Printf(gray+"     Source   "+reset+purple+"%s"+reset+"\n", project.Source)
	fmt.Printf(gray+"     Port     "+reset+purple+"%d"+reset, project.Port)
	if project.Running {
		fmt.Printf(gray + "  (reachable now)" + reset)
	}
	fmt.Printf("\n")
	if project.Start != "" {
		fmt.Printf(gray+"     Start    "+reset+cyan+"%s"+reset+"\n", project.Start)
	}
	if project.UpstreamHost != "" {
		fmt.Printf(gray+"     Host     "+reset+purple+"%s"+reset+"\n", project.UpstreamHost)
	}
	for _, note := range project.Notes {
		fmt.Printf(gray+"     Note     "+reset+gray+"%s"+reset+"\n", note)
	}
	fmt.Printf("\n")
	return nil
}

func runDetectCommand(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Print detection data as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: mekong detect [--json]")
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	project, err := detectProject(dir)
	if err != nil {
		return err
	}
	return printDetectedProject(project, *asJSON)
}

func runInitCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "Overwrite an existing .mekong.json")
	port := fs.Int("port", 0, "Override detected local port")
	start := fs.String("start", "", "Override detected start command")
	upstreamHost := fs.String("upstream-host", "", "Override Host header for local virtual-host stacks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: mekong init [--force] [--port N] [--start CMD] [--upstream-host HOST]")
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	project, detectErr := detectProject(dir)
	cfg := &projectConfig{}
	if project != nil {
		cfg.Port = project.Port
		cfg.Start = project.Start
		cfg.Stack = project.Stack
		cfg.UpstreamHost = project.UpstreamHost
	}

	if *port > 0 {
		cfg.Port = *port
	}
	if strings.TrimSpace(*start) != "" {
		cfg.Start = strings.TrimSpace(*start)
	}
	if strings.TrimSpace(*upstreamHost) != "" {
		host, err := normalizeUpstreamHost(*upstreamHost)
		if err != nil {
			return err
		}
		cfg.UpstreamHost = host
	}

	if cfg.Port <= 0 {
		if detectErr != nil {
			return detectErr
		}
		return fmt.Errorf("no local port detected; use --port to set one explicitly")
	}

	path := projectConfigPath(dir)
	if !*force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	if err := writeProjectConfig(path, cfg); err != nil {
		return err
	}

	fmt.Printf("\n")
	fmt.Printf(green+"  ✔  Wrote "+reset+purple+"%s"+reset+"\n", path)
	if cfg.Stack != "" {
		fmt.Printf(gray+"     Stack   "+reset+yellow+"%s"+reset+"\n", cfg.Stack)
	}
	fmt.Printf(gray+"     Port    "+reset+purple+"%d"+reset+"\n", cfg.Port)
	if cfg.Start != "" {
		fmt.Printf(gray+"     Start   "+reset+cyan+"%s"+reset+"\n", cfg.Start)
	}
	if cfg.UpstreamHost != "" {
		fmt.Printf(gray+"     Host    "+reset+purple+"%s"+reset+"\n", cfg.UpstreamHost)
	}
	fmt.Printf(gray + "     Next    " + reset + cyan + "mekong" + reset + "\n\n")
	return nil
}

func printMainHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Usage: mekong [flags] <local-port>")
	fmt.Fprintln(os.Stderr, "         mekong <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Quick Start:")
	fmt.Fprintln(os.Stderr, "    mekong 3000                            expose localhost:3000 with a random URL")
	fmt.Fprintln(os.Stderr, "    mekong                                 use port from .mekong.json")
	fmt.Fprintln(os.Stderr, "    mekong -d 3000                         run in background")
	fmt.Fprintln(os.Stderr, "    mekong 80 --upstream-host myapp.test   tunnel a local virtual-host app")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Project Setup:")
	fmt.Fprintln(os.Stderr, "    mekong detect                          detect the local stack")
	fmt.Fprintln(os.Stderr, "    mekong detect --json                   machine-readable detection output")
	fmt.Fprintln(os.Stderr, "    mekong init                            write .mekong.json from detection")
	fmt.Fprintln(os.Stderr, "    mekong help php                        Laragon/XAMPP/WAMP/Laravel examples")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Background And Health:")
	fmt.Fprintln(os.Stderr, "    mekong status                          show active tunnels")
	fmt.Fprintln(os.Stderr, "    mekong logs -f                         follow daemon logs")
	fmt.Fprintln(os.Stderr, "    mekong stop --all                      stop background tunnels")
	fmt.Fprintln(os.Stderr, "    mekong test                            check binary, DNS, SSH, API, and login")
	fmt.Fprintln(os.Stderr, "    mekong doctor                          connectivity, auth, and binary checks")
	fmt.Fprintln(os.Stderr, "    mekong doctor app.example.com          check custom-domain DNS and HTTPS")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Auth And Domains:")
	fmt.Fprintln(os.Stderr, "    mekong login                           save a token locally")
	fmt.Fprintln(os.Stderr, "    mekong whoami                          show saved account info")
	fmt.Fprintln(os.Stderr, "    mekong subdomain                       list reserved subdomains")
	fmt.Fprintln(os.Stderr, "    mekong subdomain myapp                 reserve a subdomain")
	fmt.Fprintln(os.Stderr, "    mekong subdomain delete myapp          remove a reserved subdomain")
	fmt.Fprintln(os.Stderr, "    mekong 3000 --subdomain myapp          pick a specific reserved subdomain")
	fmt.Fprintln(os.Stderr, "    mekong domains                         list custom domains")
	fmt.Fprintln(os.Stderr, "    mekong domain connect app.example.com myapp")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Advanced Auth:")
	fmt.Fprintln(os.Stderr, "    MEKONG_TOKEN=<tok> mekong 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong --token <tok> 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  More Help:")
	fmt.Fprintln(os.Stderr, "    mekong help auth")
	fmt.Fprintln(os.Stderr, "    mekong help subdomain")
	fmt.Fprintln(os.Stderr, "    mekong help domain")
	fmt.Fprintln(os.Stderr, "    mekong help config")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Flags:")
	fmt.Fprintln(os.Stderr, "    --server <host>          MekongTunnel server hostname")
	fmt.Fprintln(os.Stderr, "    --ssh-port <port>        SSH server port")
	fmt.Fprintln(os.Stderr, "    --port, -p <port>        Local port to expose")
	fmt.Fprintln(os.Stderr, "    --expire, -e <dur>       Tunnel lifetime")
	fmt.Fprintln(os.Stderr, "    --subdomain <name>       Pick a specific reserved subdomain")
	fmt.Fprintln(os.Stderr, "    --token <tok>            API token override (flag > env > saved login)")
	fmt.Fprintln(os.Stderr, "    --upstream-host <host>   Override Host header sent to the local app")
	fmt.Fprintln(os.Stderr, "    --host-header <host>     Alias for --upstream-host")
	fmt.Fprintln(os.Stderr, "    -d                       Run tunnel in background")
	fmt.Fprintln(os.Stderr, "    --no-qr                  Disable QR code display")
	fmt.Fprintln(os.Stderr, "    --no-clipboard           Disable auto clipboard copy")
	fmt.Fprintln(os.Stderr, "    --no-reconnect           Disable auto-reconnect on disconnect")
	fmt.Fprintln(os.Stderr, "")
}

func printAuthHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Auth")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Token resolution order:")
	fmt.Fprintln(os.Stderr, "    1. --token")
	fmt.Fprintln(os.Stderr, "    2. MEKONG_TOKEN")
	fmt.Fprintln(os.Stderr, "    3. saved login from `mekong login`")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Examples:")
	fmt.Fprintln(os.Stderr, "    mekong login")
	fmt.Fprintln(os.Stderr, "    mekong 3000")
	fmt.Fprintln(os.Stderr, "    mekong 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong subdomain myapp")
	fmt.Fprintln(os.Stderr, "    MEKONG_TOKEN=<tok> mekong 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong --token <tok> 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Note:")
	fmt.Fprintln(os.Stderr, "    A saved login or token does not force a reserved subdomain.")
	fmt.Fprintln(os.Stderr, "    Use `--subdomain myapp` when you want a specific reserved name.")
	fmt.Fprintln(os.Stderr, "")
}

func printSubdomainHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Reserved Subdomains")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Use `subdomain` for names under `*.proxy.angkorsearch.dev`.")
	fmt.Fprintln(os.Stderr, "  Use `domain` for your own custom domains such as `app.example.com`.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Preferred commands:")
	fmt.Fprintln(os.Stderr, "    mekong subdomain")
	fmt.Fprintln(os.Stderr, "    mekong subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong subdomain delete myapp")
	fmt.Fprintln(os.Stderr, "    mekong 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Compatibility aliases:")
	fmt.Fprintln(os.Stderr, "    mekong subdomains")
	fmt.Fprintln(os.Stderr, "    mekong reserve myapp")
	fmt.Fprintln(os.Stderr, "    mekong unreserve myapp")
	fmt.Fprintln(os.Stderr, "")
}

func printDomainHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Custom Domains")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Reserved names use `mekong subdomain ...` and live under `*.proxy.angkorsearch.dev`.")
	fmt.Fprintln(os.Stderr, "  Custom domains use `mekong domain ...` and point your own domain such as `app.example.com`.")
	fmt.Fprintln(os.Stderr, "  Branded domains such as `app.mekongtunnel.dev` are optional.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Examples:")
	fmt.Fprintln(os.Stderr, "    mekong domain")
	fmt.Fprintln(os.Stderr, "    mekong domain list")
	fmt.Fprintln(os.Stderr, "    mekong domains")
	fmt.Fprintln(os.Stderr, "    mekong subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong 3000 --subdomain myapp")
	fmt.Fprintln(os.Stderr, "    mekong domain add app.example.com")
	fmt.Fprintln(os.Stderr, "    mekong domain connect app.example.com myapp")
	fmt.Fprintln(os.Stderr, "    mekong domain verify app.example.com")
	fmt.Fprintln(os.Stderr, "    mekong domain wait app.example.com")
	fmt.Fprintln(os.Stderr, "    mekong domain target app.example.com myapp")
	fmt.Fprintln(os.Stderr, "    mekong domain delete app.example.com")
	fmt.Fprintln(os.Stderr, "    mekong doctor app.example.com")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Domain subcommands:")
	fmt.Fprintln(os.Stderr, "    add      create a custom domain record")
	fmt.Fprintln(os.Stderr, "    connect  add, verify, target, and wait")
	fmt.Fprintln(os.Stderr, "    verify   run one verification check now")
	fmt.Fprintln(os.Stderr, "    wait     poll until DNS and HTTPS are ready")
	fmt.Fprintln(os.Stderr, "    target   point a custom domain to a reserved subdomain")
	fmt.Fprintln(os.Stderr, "    delete   remove a custom domain from MekongTunnel")
	fmt.Fprintln(os.Stderr, "")
}

func printConfigHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Project Config")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  `.mekong.json` is stored in the current project directory.")
	fmt.Fprintln(os.Stderr, "  Supported fields: `port`, `upstream_host`, `start`, `stack`.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Examples:")
	fmt.Fprintln(os.Stderr, "    mekong init")
	fmt.Fprintln(os.Stderr, "    mekong init --port 8080")
	fmt.Fprintln(os.Stderr, "    mekong init --port 80 --upstream-host myapp.test")
	fmt.Fprintln(os.Stderr, "    mekong detect --json")
	fmt.Fprintln(os.Stderr, "")
}

func printPHPHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  PHP, Laravel, Laragon, XAMPP, WAMP")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Laravel built-in server:")
	fmt.Fprintln(os.Stderr, "    php artisan serve --host=127.0.0.1 --port=8000")
	fmt.Fprintln(os.Stderr, "    mekong 8000")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  WordPress or generic Apache site:")
	fmt.Fprintln(os.Stderr, "    mekong 80 --upstream-host wordpress.test")
	fmt.Fprintln(os.Stderr, "    mekong init --port 80 --upstream-host wordpress.test")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Local Apache vhost stacks:")
	fmt.Fprintln(os.Stderr, "    mekong 80 --upstream-host myapp.test")
	fmt.Fprintln(os.Stderr, "    mekong init --port 80 --upstream-host myapp.test")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Notes:")
	fmt.Fprintln(os.Stderr, "    `--upstream-host` makes the local app receive the expected Host header.")
	fmt.Fprintln(os.Stderr, "    This is useful for Laragon, XAMPP, WAMP, and Apache virtual hosts.")
	fmt.Fprintln(os.Stderr, "")
}

func printHealthHelp() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Health Checks")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Examples:")
	fmt.Fprintln(os.Stderr, "    mekong test")
	fmt.Fprintln(os.Stderr, "    mekong doctor")
	fmt.Fprintln(os.Stderr, "    mekong doctor app.example.com")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  `mekong test` and `mekong doctor` are the same when no domain is passed.")
	fmt.Fprintln(os.Stderr, "  `mekong doctor <domain>` checks custom-domain DNS and HTTPS readiness.")
	fmt.Fprintln(os.Stderr, "")
}

func runHelpCommand(args []string) error {
	topic := ""
	if len(args) > 0 {
		topic = strings.ToLower(strings.TrimSpace(args[0]))
	}
	switch topic {
	case "", "main":
		printMainHelp()
	case "auth":
		printAuthHelp()
	case "subdomain", "subdomains", "reserve", "unreserve":
		printSubdomainHelp()
	case "domain", "domains":
		printDomainHelp()
	case "config", "init":
		printConfigHelp()
	case "doctor", "test", "health":
		printHealthHelp()
	case "php", "laravel", "xampp", "wamp", "laragon":
		printPHPHelp()
	default:
		return fmt.Errorf("unknown help topic %q", args[0])
	}
	return nil
}

func resolvePorts(flagPort int, args []string, cfg *projectConfig) ([]int, error) {
	if flagPort > 0 {
		if flagPort < 1 || flagPort > 65535 {
			return nil, fmt.Errorf("invalid port %d", flagPort)
		}
		if len(args) > 0 {
			return nil, fmt.Errorf("cannot mix -p/--port flag with positional port arguments")
		}
		return []int{flagPort}, nil
	}

	if len(args) == 0 {
		if cfg != nil && cfg.Port > 0 {
			return []int{cfg.Port}, nil
		}
		return nil, nil
	}

	ports := make([]int, 0, len(args))
	for _, arg := range args {
		port, err := strconv.Atoi(arg)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", arg)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func augmentLocalPortError(port int, err error, cfg *projectConfig) error {
	if cfg == nil || strings.TrimSpace(cfg.Start) == "" {
		return err
	}
	return fmt.Errorf("%w\n  start your app with: %s", err, cfg.Start)
}
