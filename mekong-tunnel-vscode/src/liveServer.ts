/**
 * Built-in Live Server for HTML files.
 * - Serves static files from a root directory.
 * - Injects a WebSocket client into every .html response.
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
function injectScript(html: string, port: number): string {
  const script = [
    `<script>`,
    `(function(){`,
    `  function connect(){`,
    `    var ws=new WebSocket('ws://localhost:${port}${WS_PATH}');`,
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
    if (urlPath === '/') urlPath = '/index.html'

    // Decode %20 etc.
    try { urlPath = decodeURIComponent(urlPath) } catch {}

    const filePath = path.resolve(rootDir, '.' + urlPath)

    // Security: must stay within rootDir
    if (!filePath.startsWith(rootDir)) {
      res.writeHead(403); res.end('403 Forbidden'); return
    }

    // If directory → look for index.html inside
    let target = filePath
    if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
      target = path.join(target, 'index.html')
    }

    if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' })
      res.end(`404 Not Found: ${urlPath}`)
      return
    }

    const ext  = path.extname(target).toLowerCase()
    const mime = MIME[ext] || 'application/octet-stream'

    let content = fs.readFileSync(target)

    if (ext === '.html' || ext === '.htm') {
      const injected = injectScript(content.toString('utf8'), port)
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
