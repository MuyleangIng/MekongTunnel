/**
 * Built-in Live Server for HTML and Markdown files.
 * - Serves static files from a root directory.
 * - Renders .md files to styled HTML on the fly.
 * - Injects a WebSocket client into every .html/.md response.
 * - Broadcasts a "reload" message to all connected browsers on demand.
 * Zero external dependencies — uses only Node.js built-ins.
 */

import * as crypto from 'crypto'
import * as fs     from 'fs'
import * as http   from 'http'
import * as net    from 'net'
import * as path   from 'path'

// ---------------------------------------------------------------------------
// MIME types
// ---------------------------------------------------------------------------
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.htm':  'text/html; charset=utf-8',
  '.md':   'text/html; charset=utf-8',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.mjs':  'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.webp': 'image/webp',
  '.mp4':  'video/mp4',
  '.webm': 'video/webm',
}

// ---------------------------------------------------------------------------
// Markdown renderer (zero external deps)
// ---------------------------------------------------------------------------
function escapeHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
}

function getMdSiblings(rootDir: string, filePath: string): Array<{ name: string; href: string; active: boolean }> {
  try {
    const dir  = path.dirname(filePath)
    const base = path.basename(filePath)
    return fs.readdirSync(dir)
      .filter(e => /\.md$/i.test(e) && fs.statSync(path.join(dir, e)).isFile())
      .sort((a, b) => {
        const rank = (n: string) => /^(readme|index)\./i.test(n) ? 0 : 1
        return rank(a) - rank(b) || a.localeCompare(b)
      })
      .map(name => ({
        name: name.replace(/\.md$/i, '').replace(/[-_]/g, ' '),
        href: '/' + path.relative(rootDir, path.join(dir, name)).replace(/\\/g, '/'),
        active: name === base,
      }))
  } catch { return [] }
}

function renderMarkdown(src: string, title: string, filePath?: string, rootDir?: string): string {
  const lines = src.replace(/\r\n/g, '\n').split('\n')
  let html = ''
  let i = 0

  function inlineRender(text: string): string {
    // Code spans (do first to avoid inner processing)
    text = text.replace(/`([^`]+)`/g, (_,c) => `<code>${escapeHtml(c)}</code>`)
    // Bold + italic ***text***
    text = text.replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>')
    // Bold **text**
    text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    text = text.replace(/__([^_]+)__/g, '<strong>$1</strong>')
    // Italic *text*
    text = text.replace(/\*([^*]+)\*/g, '<em>$1</em>')
    text = text.replace(/_([^_]+)_/g, '<em>$1</em>')
    // Strikethrough ~~text~~
    text = text.replace(/~~([^~]+)~~/g, '<del>$1</del>')
    // Images ![alt](url)
    text = text.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width:100%">')
    // Links [text](url)
    text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
    // Auto-links
    text = text.replace(/(?<![">])(https?:\/\/[^\s<>"]+)/g, '<a href="$1">$1</a>')
    return text
  }

  while (i < lines.length) {
    const line = lines[i]

    // Fenced code block ```lang
    if (/^```/.test(line)) {
      const lang = line.slice(3).trim()
      const langAttr = lang ? ` class="language-${escapeHtml(lang)}"` : ''
      i++
      const codeLines: string[] = []
      while (i < lines.length && !/^```/.test(lines[i])) {
        codeLines.push(escapeHtml(lines[i]))
        i++
      }
      i++ // consume closing ```
      html += `<pre><code${langAttr}>${codeLines.join('\n')}</code></pre>\n`
      continue
    }

    // Headings
    const hm = line.match(/^(#{1,6})\s+(.+)/)
    if (hm) {
      const level = hm[1].length
      const id = hm[2].toLowerCase().replace(/[^\w\s-]/g,'').replace(/\s+/g,'-')
      html += `<h${level} id="${id}">${inlineRender(hm[2])}</h${level}>\n`
      i++; continue
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(line.trim())) {
      html += '<hr>\n'; i++; continue
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      const bqLines: string[] = []
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        bqLines.push(lines[i].replace(/^>\s?/, ''))
        i++
      }
      html += `<blockquote>${inlineRender(bqLines.join('\n'))}</blockquote>\n`
      continue
    }

    // Table (must have | and a separator row next)
    if (/\|/.test(line) && i + 1 < lines.length && /^\|?\s*[-:]+[-|\s:]*$/.test(lines[i + 1])) {
      const parseRow = (r: string) =>
        r.replace(/^\||\|$/g,'').split('|').map(c => c.trim())
      const headers = parseRow(line)
      const alignRow = parseRow(lines[i + 1])
      const aligns = alignRow.map(c => {
        if (/^:.*:$/.test(c)) return 'center'
        if (/:$/.test(c)) return 'right'
        return 'left'
      })
      i += 2
      let tableHtml = '<table>\n<thead><tr>'
      headers.forEach((h, j) =>
        tableHtml += `<th style="text-align:${aligns[j]||'left'}">${inlineRender(h)}</th>`
      )
      tableHtml += '</tr></thead>\n<tbody>\n'
      while (i < lines.length && /\|/.test(lines[i])) {
        const cells = parseRow(lines[i])
        tableHtml += '<tr>'
        cells.forEach((c, j) =>
          tableHtml += `<td style="text-align:${aligns[j]||'left'}">${inlineRender(c)}</td>`
        )
        tableHtml += '</tr>\n'
        i++
      }
      html += tableHtml + '</tbody>\n</table>\n'
      continue
    }

    // Unordered list
    if (/^(\s*)[-*+]\s+/.test(line)) {
      const listLines: string[] = []
      while (i < lines.length && /^(\s*)[-*+]\s+/.test(lines[i])) {
        listLines.push(lines[i].replace(/^(\s*)[-*+]\s+/, ''))
        i++
      }
      html += '<ul>\n' + listLines.map(l => `<li>${inlineRender(l)}</li>`).join('\n') + '\n</ul>\n'
      continue
    }

    // Ordered list
    if (/^\d+\.\s+/.test(line)) {
      const listLines: string[] = []
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
        listLines.push(lines[i].replace(/^\d+\.\s+/, ''))
        i++
      }
      html += '<ol>\n' + listLines.map(l => `<li>${inlineRender(l)}</li>`).join('\n') + '\n</ol>\n'
      continue
    }

    // Blank line — paragraph break
    if (line.trim() === '') { i++; continue }

    // Paragraph — collect consecutive non-special lines
    const paraLines: string[] = []
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !/^#{1,6}\s/.test(lines[i]) &&
      !/^```/.test(lines[i]) &&
      !/^>\s?/.test(lines[i]) &&
      !/^(\s*)[-*+]\s+/.test(lines[i]) &&
      !/^\d+\.\s+/.test(lines[i]) &&
      !/^(-{3,}|\*{3,}|_{3,})$/.test(lines[i].trim())
    ) {
      paraLines.push(lines[i])
      i++
    }
    if (paraLines.length) {
      html += `<p>${inlineRender(paraLines.join('<br>'))}</p>\n`
    }
  }

  const safeTitle = escapeHtml(title)

  // Build sidebar nav if multiple .md files exist in the same directory
  const siblings = (filePath && rootDir) ? getMdSiblings(rootDir, filePath) : []
  const hasSidebar = siblings.length > 1

  const sidebarHtml = hasSidebar ? `
<nav id="md-nav">
<div class="nav-title">Pages</div>
${siblings.map(s => `<a href="${escapeHtml(s.href)}" class="${s.active ? 'active' : ''}">${escapeHtml(s.name)}</a>`).join('\n')}
</nav>` : ''

  const layoutClass = hasSidebar ? 'has-nav' : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeTitle}</title>
<style>
:root{color-scheme:light dark}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:16px;line-height:1.7;background:#0d1117;color:#e6edf3}
body.has-nav{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
#md-nav{background:#010409;border-right:1px solid #21262d;padding:24px 0;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0}
.nav-title{padding:0 16px 12px;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#484f58}
#md-nav a{display:block;padding:6px 16px;font-size:13px;color:#848d97;text-decoration:none;border-left:2px solid transparent;transition:color .15s,border-color .15s;text-transform:capitalize}
#md-nav a:hover{color:#e6edf3;background:rgba(255,255,255,.03)}
#md-nav a.active{color:#e6edf3;border-left-color:#58a6ff;background:rgba(88,166,255,.07);font-weight:600}
#md-content{padding:40px 48px 80px;max-width:860px;min-width:0}
body:not(.has-nav) #md-content{max-width:860px;margin:0 auto;padding:32px 24px 80px}
h1,h2,h3,h4,h5,h6{font-weight:600;line-height:1.25;margin:1.5em 0 .5em;color:#f0f6fc}
h1{font-size:2em;border-bottom:1px solid #30363d;padding-bottom:.3em}
h2{font-size:1.5em;border-bottom:1px solid #30363d;padding-bottom:.3em}
h3{font-size:1.25em}
p{margin:.75em 0}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
img{max-width:100%;border-radius:6px}
code{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:.875em;background:#161b22;color:#e6edf3;padding:.2em .4em;border-radius:6px;border:1px solid #30363d}
pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;overflow-x:auto;margin:1em 0;line-height:1.5}
pre code{background:none;border:none;padding:0;font-size:.875em;color:#e6edf3}
blockquote{border-left:3px solid #3d444d;padding:.5em 1em;color:#848d97;margin:1em 0;background:#161b22;border-radius:0 6px 6px 0}
ul,ol{padding-left:2em;margin:.75em 0}
li{margin:.25em 0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:.9em}
th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}
th{background:#161b22;font-weight:600;color:#f0f6fc}
tr:nth-child(even){background:#161b22}
hr{border:none;border-top:1px solid #30363d;margin:2em 0}
del{color:#848d97}
.md-title{color:#58a6ff;font-size:.8em;font-family:'SFMono-Regular',monospace;margin-bottom:1.5em;display:block;opacity:.7}
</style>
</head>
<body class="${layoutClass}">
${sidebarHtml}
<div id="md-content">
<span class="md-title">${safeTitle}</span>
${html}
</div>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// WebSocket helpers
// ---------------------------------------------------------------------------
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const WS_PATH = '/__mekong_ws__'

function wsAccept(key: string): string {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64')
}

function wsFrame(msg: string): Buffer {
  const payload = Buffer.from(msg, 'utf8')
  const len = payload.length
  const frame = Buffer.allocUnsafe(len < 126 ? 2 + len : 4 + len)
  frame[0] = 0x81 // FIN + text opcode
  if (len < 126) {
    frame[1] = len
    payload.copy(frame, 2)
  } else {
    frame[1] = 126
    frame[2] = (len >> 8) & 0xff
    frame[3] = len & 0xff
    payload.copy(frame, 4)
  }
  return frame
}

/** Inject before </body> or before </head> or at end */
function injectScript(html: string, _port: number): string {
  const script = [
    `<script>`,
    `(function(){`,
    `  function connect(){`,
    `    var proto=location.protocol==='https:'?'wss:':'ws:';`,
    `    var ws=new WebSocket(proto+'//'+location.host+'${WS_PATH}');`,
    `    ws.onmessage=function(e){if(e.data==='reload')location.reload();};`,
    `    ws.onclose=function(){setTimeout(connect,1500);};`,
    `    ws.onerror=function(){setTimeout(connect,2000);};`,
    `  }`,
    `  connect();`,
    `})();`,
    `</script>`,
  ].join('\n')

  if (html.includes('</body>')) return html.replace('</body>', script + '\n</body>')
  if (html.includes('</html>')) return html.replace('</html>', script + '\n</html>')
  return html + '\n' + script
}

// ---------------------------------------------------------------------------
// Port finder
// ---------------------------------------------------------------------------
export function findAvailablePort(start: number): Promise<number> {
  return new Promise((resolve, reject) => {
    let port = start
    function tryNext() {
      if (port > 65535) { reject(new Error('No available port found')); return }
      const s = net.createServer()
      s.on('error', () => { port++; tryNext() })
      s.listen(port, '127.0.0.1', () => {
        const p = (s.address() as net.AddressInfo).port
        s.close(() => resolve(p))
      })
    }
    tryNext()
  })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
export interface LiveServerHandle {
  port: number
  /** Send "reload" to all connected WebSocket clients */
  broadcast(): void
  /** Stop the HTTP server and close all WS connections */
  stop(): void
}

export async function startLiveServer(
  rootDir: string,
  startPort = 5500
): Promise<LiveServerHandle> {
  const port   = await findAvailablePort(startPort)
  const clients = new Set<net.Socket>()

  // ── HTTP server ──────────────────────────────────────────────────────────
  const server = http.createServer((req, res) => {
    let urlPath = (req.url ?? '/').split('?')[0]

    // Decode %20 etc.
    try { urlPath = decodeURIComponent(urlPath) } catch {}

    const filePath = path.resolve(rootDir, '.' + (urlPath || '/'))

    // Security: must stay within rootDir
    if (!filePath.startsWith(rootDir)) {
      res.writeHead(403); res.end('403 Forbidden'); return
    }

    // Helper: find first .md file in a directory
    const firstMdIn = (dir: string): string | null => {
      try {
        const entries = fs.readdirSync(dir)
        const md = entries.find(e => e.toLowerCase().endsWith('.md') && fs.statSync(path.join(dir, e)).isFile())
        return md ? path.join(dir, md) : null
      } catch { return null }
    }

    // Directory or root → prefer index.html > README.md > index.md > first .md
    let target = filePath
    const isDir = fs.existsSync(target) && fs.statSync(target).isDirectory()
    const isRoot = urlPath === '/' || urlPath === ''

    if (isDir || isRoot) {
      const base = isDir ? target : rootDir
      const indexHtml = path.join(base, 'index.html')
      const readmeMd  = path.join(base, 'README.md')
      const indexMd   = path.join(base, 'index.md')
      if      (fs.existsSync(indexHtml)) target = indexHtml
      else if (fs.existsSync(readmeMd))  target = readmeMd
      else if (fs.existsSync(indexMd))   target = indexMd
      else {
        const first = firstMdIn(base)
        if (first) { target = first }
        else       { target = indexHtml } // will 404 below with clean page
      }
    }

    // /index.html requested but doesn't exist → redirect to first .md if available
    if (urlPath.endsWith('/index.html') && (!fs.existsSync(target) || !fs.statSync(target).isFile())) {
      const dir = path.resolve(rootDir, '.' + urlPath.replace(/\/index\.html$/, '') || '/')
      const first = firstMdIn(dir) ?? firstMdIn(rootDir)
      if (first) {
        const rel = '/' + path.relative(rootDir, first).replace(/\\/g, '/')
        res.writeHead(302, { Location: rel }); res.end(); return
      }
    }

    if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
      const mdHint = firstMdIn(rootDir)
      const suggestion = mdHint
        ? `<p>This looks like a Markdown site. Try <a href="/${path.relative(rootDir, mdHint).replace(/\\/g, '/')}">opening the first page</a>.</p>`
        : `<p>No <code>index.html</code> was found in the served folder.</p>`
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>404 Not Found</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{text-align:center;max-width:480px}h1{font-size:3em;color:#58a6ff;margin-bottom:.25em}p{color:#8b949e}a{color:#58a6ff}</style></head>
<body><div class="box"><h1>404</h1><p><strong>${urlPath}</strong> was not found.</p>${suggestion}</div></body></html>`)
      return
    }

    const ext  = path.extname(target).toLowerCase()
    const mime = MIME[ext] || 'application/octet-stream'

    let content = fs.readFileSync(target)

    if (ext === '.html' || ext === '.htm') {
      const injected = injectScript(content.toString('utf8'), port)
      content = Buffer.from(injected, 'utf8')
    } else if (ext === '.md') {
      const title    = path.basename(target)
      const rendered = renderMarkdown(content.toString('utf8'), title, target, rootDir)
      const injected = injectScript(rendered, port)
      content = Buffer.from(injected, 'utf8')
    }

    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': content.length,
      'Cache-Control': 'no-store',
    })
    res.end(content)
  })

  // ── WebSocket upgrade ────────────────────────────────────────────────────
  server.on('upgrade', (req, socket: net.Socket) => {
    if (req.url !== WS_PATH) { socket.destroy(); return }

    const key = req.headers['sec-websocket-key']
    if (typeof key !== 'string') { socket.destroy(); return }

    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${wsAccept(key)}`,
      '', '',
    ].join('\r\n'))

    clients.add(socket)
    socket.on('close', () => clients.delete(socket))
    socket.on('error', () => { clients.delete(socket); socket.destroy() })
    // Keep-alive ping every 25s
    const ping = setInterval(() => {
      if (socket.destroyed) { clearInterval(ping); return }
      socket.write(Buffer.from([0x89, 0x00])) // WebSocket ping frame
    }, 25_000)
    socket.on('close', () => clearInterval(ping))
  })

  await new Promise<void>((resolve, reject) => {
    server.listen(port, '127.0.0.1', resolve)
    server.on('error', reject)
  })

  return {
    port,
    broadcast() {
      const frame = wsFrame('reload')
      for (const s of clients) {
        try { if (!s.destroyed) s.write(frame) } catch {}
      }
    },
    stop() {
      server.close()
      for (const s of clients) {
        try { s.destroy() } catch {}
      }
      clients.clear()
    },
  }
}
