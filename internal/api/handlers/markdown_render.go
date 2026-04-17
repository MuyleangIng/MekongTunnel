// markdown_render.go — server-side Markdown renderer for the deploy file server.
// Renders .md files to styled HTML with cross-file link navigation.
// Zero external dependencies — pure Go stdlib.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package handlers

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ── Regex cache ───────────────────────────────────────────────────────────────

var (
	reCache   sync.Map
)

func compiledRe(pattern string) *regexp.Regexp {
	if v, ok := reCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	reCache.Store(pattern, re)
	return re
}

func reReplaceAll(s, pattern string, fn func([]string) string) string {
	re := compiledRe(pattern)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		sub := re.FindStringSubmatch(match)
		return fn(sub)
	})
}

// ── Markdown → HTML renderer ─────────────────────────────────────────────────

func mdEscape(s string) string { return html.EscapeString(s) }

func mdInline(text string) string {
	// Inline code (process first to protect inner content)
	text = reReplaceAll(text, "`([^`]+)`", func(m []string) string {
		return "<code>" + mdEscape(m[1]) + "</code>"
	})
	// Bold + italic ***
	text = reReplaceAll(text, `\*\*\*([^*]+)\*\*\*`, func(m []string) string {
		return "<strong><em>" + m[1] + "</em></strong>"
	})
	// Bold **
	text = reReplaceAll(text, `\*\*([^*]+)\*\*`, func(m []string) string {
		return "<strong>" + m[1] + "</strong>"
	})
	text = reReplaceAll(text, `__([^_]+)__`, func(m []string) string {
		return "<strong>" + m[1] + "</strong>"
	})
	// Italic *
	text = reReplaceAll(text, `\*([^*\n]+)\*`, func(m []string) string {
		return "<em>" + m[1] + "</em>"
	})
	text = reReplaceAll(text, `_([^_\n]+)_`, func(m []string) string {
		return "<em>" + m[1] + "</em>"
	})
	// Strikethrough ~~
	text = reReplaceAll(text, `~~([^~]+)~~`, func(m []string) string {
		return "<del>" + m[1] + "</del>"
	})
	// Images ![alt](url)
	text = reReplaceAll(text, `!\[([^\]]*)\]\(([^)]+)\)`, func(m []string) string {
		return fmt.Sprintf(`<img src="%s" alt="%s" style="max-width:100%%">`, mdEscape(m[2]), mdEscape(m[1]))
	})
	// Links [text](url) — keep .md extension so the handler resolves it
	text = reReplaceAll(text, `\[([^\]]+)\]\(([^)]+)\)`, func(m []string) string {
		return fmt.Sprintf(`<a href="%s">%s</a>`, mdEscape(m[2]), m[1])
	})
	return text
}

// renderMarkdown converts a Markdown string to an HTML body fragment.
func renderMarkdown(src string) string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	lines := strings.Split(src, "\n")
	var out strings.Builder
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Fenced code block ```lang
		if strings.HasPrefix(line, "```") {
			lang := strings.TrimSpace(line[3:])
			langAttr := ""
			if lang != "" {
				langAttr = fmt.Sprintf(` class="language-%s"`, mdEscape(lang))
			}
			i++
			var codeLines []string
			for i < len(lines) && !strings.HasPrefix(lines[i], "```") {
				codeLines = append(codeLines, mdEscape(lines[i]))
				i++
			}
			i++ // consume closing ```
			out.WriteString(fmt.Sprintf("<pre><code%s>%s</code></pre>\n",
				langAttr, strings.Join(codeLines, "\n")))
			continue
		}

		// Heading #…#
		if strings.HasPrefix(line, "#") {
			level := 0
			for level < len(line) && line[level] == '#' {
				level++
			}
			if level <= 6 && len(line) > level && line[level] == ' ' {
				content := strings.TrimSpace(line[level+1:])
				id := compiledRe(`[^\w\s-]`).ReplaceAllString(strings.ToLower(content), "")
				id = compiledRe(`\s+`).ReplaceAllString(id, "-")
				out.WriteString(fmt.Sprintf("<h%d id=\"%s\">%s</h%d>\n",
					level, id, mdInline(content), level))
				i++
				continue
			}
		}

		// Horizontal rule
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 3 &&
			(strings.Trim(trimmed, "-") == "" ||
				strings.Trim(trimmed, "*") == "" ||
				strings.Trim(trimmed, "_") == "") {
			out.WriteString("<hr>\n")
			i++
			continue
		}

		// Blockquote >
		if strings.HasPrefix(line, ">") {
			var bqLines []string
			for i < len(lines) && strings.HasPrefix(lines[i], ">") {
				bqLines = append(bqLines,
					strings.TrimPrefix(strings.TrimPrefix(lines[i], ">"), " "))
				i++
			}
			out.WriteString("<blockquote>" +
				mdInline(strings.Join(bqLines, "\n")) +
				"</blockquote>\n")
			continue
		}

		// Table (line has | and next line is separator)
		if strings.Contains(line, "|") && i+1 < len(lines) && isTableSep(lines[i+1]) {
			headers := parseTableRow(line)
			aligns := parseTableAligns(lines[i+1])
			i += 2
			out.WriteString("<table>\n<thead><tr>")
			for j, h := range headers {
				align := tableAlign(aligns, j)
				out.WriteString(fmt.Sprintf(`<th style="text-align:%s">%s</th>`,
					align, mdInline(h)))
			}
			out.WriteString("</tr></thead>\n<tbody>\n")
			for i < len(lines) && strings.Contains(lines[i], "|") {
				cells := parseTableRow(lines[i])
				out.WriteString("<tr>")
				for j, c := range cells {
					align := tableAlign(aligns, j)
					out.WriteString(fmt.Sprintf(`<td style="text-align:%s">%s</td>`,
						align, mdInline(c)))
				}
				out.WriteString("</tr>\n")
				i++
			}
			out.WriteString("</tbody>\n</table>\n")
			continue
		}

		// Unordered list - * +
		if isULItem(line) {
			out.WriteString("<ul>\n")
			for i < len(lines) && isULItem(lines[i]) {
				item := compiledRe(`^[\s]*[-*+]\s+`).ReplaceAllString(lines[i], "")
				out.WriteString("<li>" + mdInline(item) + "</li>\n")
				i++
			}
			out.WriteString("</ul>\n")
			continue
		}

		// Ordered list 1. 2. …
		if isOLItem(line) {
			out.WriteString("<ol>\n")
			for i < len(lines) && isOLItem(lines[i]) {
				item := compiledRe(`^\d+\.\s+`).ReplaceAllString(lines[i], "")
				out.WriteString("<li>" + mdInline(item) + "</li>\n")
				i++
			}
			out.WriteString("</ol>\n")
			continue
		}

		// Blank line
		if strings.TrimSpace(line) == "" {
			i++
			continue
		}

		// Paragraph — collect consecutive non-special lines
		var paraLines []string
		for i < len(lines) &&
			strings.TrimSpace(lines[i]) != "" &&
			!strings.HasPrefix(lines[i], "#") &&
			!strings.HasPrefix(lines[i], "```") &&
			!strings.HasPrefix(lines[i], ">") &&
			!isULItem(lines[i]) &&
			!isOLItem(lines[i]) {
			paraLines = append(paraLines, lines[i])
			i++
		}
		if len(paraLines) > 0 {
			out.WriteString("<p>" + mdInline(strings.Join(paraLines, "<br>")) + "</p>\n")
		}
	}
	return out.String()
}

// ── Table helpers ─────────────────────────────────────────────────────────────

func isTableSep(line string) bool {
	t := strings.TrimSpace(line)
	if !strings.Contains(t, "|") {
		return false
	}
	stripped := strings.ReplaceAll(strings.ReplaceAll(t, "|", ""), "-", "")
	stripped = strings.ReplaceAll(stripped, ":", "")
	return strings.TrimSpace(stripped) == ""
}

func parseTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func parseTableAligns(line string) []string {
	cells := parseTableRow(line)
	aligns := make([]string, len(cells))
	for i, c := range cells {
		if strings.HasPrefix(c, ":") && strings.HasSuffix(c, ":") {
			aligns[i] = "center"
		} else if strings.HasSuffix(c, ":") {
			aligns[i] = "right"
		} else {
			aligns[i] = "left"
		}
	}
	return aligns
}

func tableAlign(aligns []string, i int) string {
	if i < len(aligns) {
		return aligns[i]
	}
	return "left"
}

// ── List helpers ──────────────────────────────────────────────────────────────

func isULItem(line string) bool {
	t := strings.TrimLeft(line, " \t")
	return strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") || strings.HasPrefix(t, "+ ")
}

func isOLItem(line string) bool {
	re := compiledRe(`^\d+\.\s+`)
	return re.MatchString(line)
}

// ── HTML page wrapper ─────────────────────────────────────────────────────────

func renderMarkdownPage(title, body, nav string) string {
	safeTitle := mdEscape(title)
	sidebar := ""
	mainClass := "no-nav"
	if nav != "" {
		sidebar = `<nav id="sidenav">` + nav + `</nav>`
		mainClass = "with-nav"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
:root{color-scheme:dark}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:16px;line-height:1.7;background:#0d1117;color:#e6edf3;display:flex;min-height:100vh}
#sidenav{width:240px;flex-shrink:0;background:#161b22;border-right:1px solid #30363d;padding:24px 0;position:sticky;top:0;height:100vh;overflow-y:auto}
#sidenav .nav-title{font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#8b949e;padding:0 16px 10px}
#sidenav a{display:block;padding:5px 16px;font-size:13px;color:#8b949e;text-decoration:none;border-left:2px solid transparent;transition:all .12s}
#sidenav a:hover{color:#e6edf3;background:rgba(255,255,255,.04)}
#sidenav a.active{color:#58a6ff;border-left-color:#58a6ff;background:rgba(88,166,255,.08)}
#content{flex:1;padding:40px 48px 80px;max-width:860px}
#content.no-nav{margin:0 auto}
h1,h2,h3,h4,h5,h6{font-weight:600;line-height:1.25;margin:1.5em 0 .5em;color:#f0f6fc}
h1{font-size:2em;border-bottom:1px solid #30363d;padding-bottom:.3em}
h2{font-size:1.5em;border-bottom:1px solid #30363d;padding-bottom:.3em}
h3{font-size:1.25em}
p{margin:.75em 0}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
img{max-width:100%%;border-radius:6px}
code{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:.875em;background:#161b22;color:#e6edf3;padding:.2em .4em;border-radius:6px;border:1px solid #30363d}
pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;overflow-x:auto;margin:1em 0;line-height:1.5}
pre code{background:none;border:none;padding:0;font-size:.875em}
blockquote{border-left:3px solid #3d444d;padding:.5em 1em;color:#848d97;margin:1em 0;background:#161b22;border-radius:0 6px 6px 0}
ul,ol{padding-left:2em;margin:.75em 0}
li{margin:.25em 0}
table{border-collapse:collapse;width:100%%;margin:1em 0;font-size:.9em}
th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}
th{background:#161b22;font-weight:600;color:#f0f6fc}
tr:nth-child(even){background:#161b22}
hr{border:none;border-top:1px solid #30363d;margin:2em 0}
del{color:#848d97}
@media(max-width:700px){body{flex-direction:column}#sidenav{width:100%%;height:auto;position:static;border-right:none;border-bottom:1px solid #30363d}#content{padding:24px 20px 60px}}
</style>
</head>
<body>
%s
<div id="content" class="%s">
%s
</div>
<script>
(function(){
  var links=document.querySelectorAll('#sidenav a');
  var cur=decodeURIComponent(location.pathname);
  links.forEach(function(a){
    var href=decodeURIComponent(a.getAttribute('href')||'');
    if(href===cur||href===cur.replace(/\/$/,'')){a.classList.add('active');}
  });
})();
</script>
</body>
</html>`, safeTitle, sidebar, mainClass, body)
}

// ── Markdown deploy handler ───────────────────────────────────────────────────

// markdownDeployServer returns an http.Handler that renders .md files to HTML
// with a sidebar nav. Other files (images, CSS, etc.) fall through to http.FileServer.
func markdownDeployServer(root string) http.Handler {
	plain := http.FileServer(http.Dir(root))
	rootClean := filepath.Clean(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath := r.URL.Path
		if rawPath == "" {
			rawPath = "/"
		}
		decoded, err := url.PathUnescape(rawPath)
		if err == nil {
			rawPath = decoded
		}

		// Security: prevent path traversal
		clean := filepath.Join(rootClean, filepath.FromSlash(rawPath))
		if !strings.HasPrefix(filepath.Clean(clean), rootClean) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		target := clean
		info, statErr := os.Stat(target)

		// Directory → prefer README.md > index.md > first .md found > index.html
		if statErr == nil && info.IsDir() {
			found := false
			for _, idx := range []string{"README.md", "index.md"} {
				candidate := filepath.Join(target, idx)
				if _, err := os.Stat(candidate); err == nil {
					target = candidate
					info, statErr = os.Stat(target)
					found = true
					break
				}
			}
			if !found {
				// Auto-redirect to first .md file in directory
				entries, _ := os.ReadDir(target)
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
						rel, _ := filepath.Rel(rootClean, filepath.Join(target, e.Name()))
						http.Redirect(w, r, "/"+rel, http.StatusFound)
						return
					}
				}
			}
		}

		// Serve .md as rendered HTML
		if statErr == nil && !info.IsDir() &&
			strings.HasSuffix(strings.ToLower(target), ".md") {
			raw, err := os.ReadFile(target)
			if err != nil {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			body := renderMarkdown(string(raw))
			nav := buildNav(rootClean, rawPath)
			title := strings.TrimSuffix(filepath.Base(target), ".md")
			if title == "README" || title == "index" {
				parent := filepath.Base(filepath.Dir(target))
				if parent != "." && parent != rootClean {
					title = parent
				} else {
					title = "Docs"
				}
			}
			page := renderMarkdownPage(title, body, nav)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, page)
			return
		}

		// All other files: images, CSS, fonts, etc.
		plain.ServeHTTP(w, r)
	})
}

// buildNav scans root for .md files and returns an HTML sidebar nav.
// Returns empty string if only one file found (no sidebar needed).
func buildNav(root, currentPath string) string {
	var entries []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		entries = append(entries, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(entries)

	if len(entries) <= 1 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(`<div class="nav-title">Pages</div>`)
	for _, rel := range entries {
		href := "/" + rel
		label := strings.TrimSuffix(rel, ".md")
		parts := strings.Split(label, "/")
		indent := len(parts) - 1
		display := parts[len(parts)-1]
		if (display == "README" || display == "index") && len(parts) > 1 {
			display = parts[len(parts)-2] + "/"
		} else if display == "README" || display == "index" {
			display = "Home"
		}
		prefix := strings.Repeat("&nbsp;&nbsp;", indent)
		sb.WriteString(fmt.Sprintf(`<a href="%s">%s%s</a>`,
			mdEscape(href), prefix, mdEscape(display)))
	}
	return sb.String()
}
