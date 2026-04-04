import * as vscode from 'vscode'
import * as cp from 'child_process'
import * as fs from 'fs'
import * as https from 'https'
import * as net from 'net'
import * as path from 'path'
import * as os from 'os'
import { startLiveServer, LiveServerHandle } from './liveServer'

// ── Global state ────────────────────────────────────────────────────────────
let tunnelProcess: cp.ChildProcess | null = null
let publicUrl: string | null = null
let tunnelPort: number | null = null
let statusBarItem: vscode.StatusBarItem
let liveStatusBar: vscode.StatusBarItem
let outputChannel: vscode.OutputChannel | null = null
let panelProvider: MekongWebviewProvider | null = null

let liveServer: LiveServerHandle | null = null
let liveWatcher: vscode.FileSystemWatcher | null = null
let livePreviewPanel: vscode.WebviewPanel | null = null
let liveRootDir: string | null = null

// cached mekong binary path: undefined = not checked yet, null = not found
let cachedMekongBin: string | null | undefined = undefined

// cached auth info — refreshed on login / logout / startup
let cachedAuth: { token: string; email: string; plan: string } | null = null

// ── Framework port map ───────────────────────────────────────────────────────
const FRAMEWORK_PORTS: Record<string, number> = {
  'next': 3000, 'nuxt': 3000, 'nuxt3': 3000,
  'vite': 5173, 'react-scripts': 3000,
  '@angular/core': 4200, '@sveltejs/kit': 5173,
  'svelte': 5173, 'astro': 4321, 'gatsby': 8000,
  'remix': 3000, '@remix-run/react': 3000,
  'express': 3000, 'fastify': 3000, 'hono': 3000,
}

// ── Helpers ──────────────────────────────────────────────────────────────────
async function findMekong(): Promise<string | null> {
  const config = vscode.workspace.getConfiguration('mekong')
  const custom = config.get<string>('binaryPath')
  if (custom && custom.trim()) return custom.trim()
  try {
    const cmd = process.platform === 'win32' ? 'where mekong' : 'which mekong'
    const result = cp.execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().trim().split('\n')[0].trim()
    if (result && fs.existsSync(result)) return result
  } catch {}
  const localAppData = process.env['LOCALAPPDATA'] || path.join(os.homedir(), 'AppData', 'Local')
  const candidates = process.platform === 'win32'
    ? [
        path.join(localAppData, 'Programs', 'mekong', 'mekong.exe'),
        path.join(localAppData, 'mekong.exe'),
        path.join(os.homedir(), '.local', 'bin', 'mekong.exe'),
      ]
    : [
        '/usr/local/bin/mekong',
        path.join(os.homedir(), '.local', 'bin', 'mekong'),
        path.join(os.homedir(), 'bin', 'mekong'),
        '/usr/bin/mekong',
        '/opt/homebrew/bin/mekong',
      ]
  for (const p of candidates) if (fs.existsSync(p)) return p
  return null
}

/** Read auth config from ~/.mekong/config.json (written by `mekong login`) */
function readSavedToken(): string | null {
  try {
    const cfgPath = path.join(os.homedir(), '.mekong', 'config.json')
    if (!fs.existsSync(cfgPath)) return null
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'))
    return cfg?.token || null
  } catch {
    return null
  }
}

function readSavedAuth(): { token: string; email: string } | null {
  try {
    const cfgPath = path.join(os.homedir(), '.mekong', 'config.json')
    if (!fs.existsSync(cfgPath)) return null
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'))
    if (!cfg?.token) return null
    return { token: cfg.token, email: cfg.email || '' }
  } catch {
    return null
  }
}

/** Fetch email + plan from API using API token (mkt_xxx) */
async function fetchUserInfo(token: string): Promise<{ email: string; plan: string } | null> {
  return new Promise(resolve => {
    const req = https.request(
      { hostname: 'api.angkorsearch.dev', path: '/api/auth/token-info', method: 'GET',
        headers: { 'Authorization': 'Bearer ' + token } },
      res => {
        let body = ''
        res.on('data', (d: Buffer) => { body += d.toString() })
        res.on('end', () => {
          try {
            const j = JSON.parse(body)
            resolve({ email: j.data?.email || '', plan: j.data?.plan || '' })
          } catch { resolve(null) }
        })
      }
    )
    req.on('error', () => resolve(null))
    req.setTimeout(6000, () => { req.destroy(); resolve(null) })
    req.end()
  })
}

function getInstallScriptUrl(): string {
  return process.platform === 'win32'
    ? 'https://mekongtunnel.dev/install.ps1'
    : 'https://mekongtunnel.dev/install.sh'
}

/** Refresh cachedAuth from disk + API; call after login / logout / startup */
async function refreshAuth(): Promise<void> {
  const saved = readSavedAuth()
  if (!saved) { cachedAuth = null; return }
  const info = await fetchUserInfo(saved.token)
  cachedAuth = { token: saved.token, email: info?.email || saved.email, plan: info?.plan || '' }
}

/** Try connecting to 127.0.0.1:port — resolves true if something is listening */
function isPortListening(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = new net.Socket()
    socket.setTimeout(500)
    socket.on('connect', () => { socket.destroy(); resolve(true) })
    socket.on('error',   () => { socket.destroy(); resolve(false) })
    socket.on('timeout', () => { socket.destroy(); resolve(false) })
    socket.connect(port, '127.0.0.1')
  })
}

/**
 * Smart port scan: reads package.json for the base port, then scans
 * base+0…base+9 plus other known framework ports to find what is actually
 * listening. Returns all found ports so the user can pick the right one.
 */
async function scanListeningPorts(): Promise<{ port: number; framework: string; altPort: boolean }[]> {
  const detected  = detectPort()
  const basePort  = detected?.port  ?? 3000
  const framework = detected?.framework ?? 'unknown'

  // All well-known default ports across frameworks
  const knownDefaults = [3000, 3001, 5173, 5174, 4200, 4321, 8000, 8080, 8888, 4000]
  const toScan = new Set<number>(knownDefaults)

  // Always include base port + next 9 (handles Next.js / Vite auto-increment)
  for (let i = 0; i < 10; i++) toScan.add(basePort + i)

  // Probe all ports in parallel (fast)
  const results = await Promise.all(
    [...toScan].map(async port => ({
      port,
      listening: await isPortListening(port),
    }))
  )

  return results
    .filter(r => r.listening)
    .sort((a, b) => a.port - b.port)
    .map(r => ({
      port:     r.port,
      framework: r.port === basePort ? framework : 'detected',
      altPort:   r.port !== basePort,
    }))
}

/** Return the "start dev server" command hint for a given framework */
function devCommand(framework: string): string {
  const map: Record<string, string> = {
    'next': 'npm run dev',  'nuxt': 'npm run dev', 'nuxt3': 'npm run dev',
    'vite': 'npm run dev',  'react-scripts': 'npm start',
    '@angular/core': 'ng serve', '@sveltejs/kit': 'npm run dev',
    'svelte': 'npm run dev', 'astro': 'npm run dev', 'gatsby': 'gatsby develop',
    'remix': 'npm run dev', '@remix-run/react': 'npm run dev',
    'express': 'node index.js', 'fastify': 'node index.js', 'hono': 'npm run dev',
  }
  return map[framework] ?? 'npm run dev'
}

function detectPort(): { port: number; framework: string } | null {
  const config = vscode.workspace.getConfiguration('mekong')
  const cfgPort = config.get<number>('port')
  if (cfgPort) return { port: cfgPort, framework: 'custom' }
  const folders = vscode.workspace.workspaceFolders
  if (!folders?.length) return null
  const pkgPath = path.join(folders[0].uri.fsPath, 'package.json')
  if (!fs.existsSync(pkgPath)) return null
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }
    for (const [dep, port] of Object.entries(FRAMEWORK_PORTS)) {
      if (allDeps[dep]) return { port: port as number, framework: dep }
    }
  } catch {}
  return null
}

function detectHtmlRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders
  if (!folders?.length) return null
  // Prefer the active editor's directory if it's an HTML file
  const active = vscode.window.activeTextEditor?.document.uri.fsPath
  if (active && active.endsWith('.html')) return path.dirname(active)
  // Otherwise use workspace root if index.html exists there
  const root = folders[0].uri.fsPath
  if (fs.existsSync(path.join(root, 'index.html'))) return root
  return root
}

function isWithinDir(rootDir: string, targetPath: string): boolean {
  const relative = path.relative(rootDir, targetPath)
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))
}

function getLiveOpenPath(rootDir: string, fileUri?: vscode.Uri): string {
  if (!fileUri) return '/'
  if (!isWithinDir(rootDir, fileUri.fsPath)) return '/'

  try {
    const stat = fs.statSync(fileUri.fsPath)
    const relative = path.relative(rootDir, fileUri.fsPath).replace(/\\/g, '/')
    if (!relative || relative === '.') return '/'
    if (stat.isDirectory()) return `/${relative.replace(/\/?$/, '/')}`
    return `/${relative}`
  } catch {
    return '/'
  }
}

function hasLiveTunnel(): boolean {
  return tunnelProcess !== null && publicUrl !== null && liveServer !== null && tunnelPort === liveServer.port
}

function setStatus(state: 'idle' | 'starting' | 'running' | 'error', url?: string) {
  if (state === 'idle') {
    statusBarItem.text = '$(radio-tower) mekong'
    statusBarItem.tooltip = 'Click to start Mekong tunnel'
    statusBarItem.command = 'mekong.startTunnel'
    statusBarItem.backgroundColor = undefined
  } else if (state === 'starting') {
    statusBarItem.text = '$(sync~spin) mekong: connecting...'
    statusBarItem.tooltip = 'Tunnel is starting...'
    statusBarItem.command = undefined
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground')
  } else if (state === 'running' && url) {
    const display = url.length > 38 ? url.slice(0, 38) + '\u2026' : url
    statusBarItem.text = `$(radio-tower) ${display}`
    statusBarItem.tooltip = `Tunnel active: ${url}\nClick to copy URL`
    statusBarItem.command = 'mekong.copyUrl'
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground')
  } else if (state === 'error') {
    statusBarItem.text = '$(error) mekong: error'
    statusBarItem.tooltip = 'Tunnel error. Click to restart.'
    statusBarItem.command = 'mekong.startTunnel'
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground')
  }
  panelProvider?.sendState()
}

function setLiveStatus(running: boolean, port?: number) {
  if (running && port) {
    liveStatusBar.text = `$(broadcast) Live :${port}`
    liveStatusBar.tooltip = `Live Server running on localhost:${port}\nClick to open in browser`
    liveStatusBar.command = 'mekong.openLiveInBrowser'
    liveStatusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground')
  } else {
    liveStatusBar.text = '$(broadcast) Live Server'
    liveStatusBar.tooltip = 'Start Mekong Live Server'
    liveStatusBar.command = 'mekong.startLiveServer'
    liveStatusBar.backgroundColor = undefined
  }
  panelProvider?.sendState()
}

// ── Kill helper (kills process group on Unix so child procs die too) ─────────
function killProc(proc: cp.ChildProcess) {
  try {
    if (process.platform !== 'win32' && proc.pid) {
      process.kill(-proc.pid, 'SIGTERM')
    } else {
      proc.kill('SIGTERM')
    }
  } catch {
    try { proc.kill('SIGTERM') } catch {}
  }
  // SIGKILL fallback after 3 s if still alive
  setTimeout(() => {
    try { proc.kill('SIGKILL') } catch {}
  }, 3000)
}

// ── Webview provider ─────────────────────────────────────────────────────────
class MekongWebviewProvider implements vscode.WebviewViewProvider {
  private _view?: vscode.WebviewView

  constructor(private readonly _extensionUri: vscode.Uri) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView

    // Clear stale reference when view is disposed
    webviewView.onDidDispose(() => { this._view = undefined })

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [
        vscode.Uri.joinPath(this._extensionUri, 'media'),
        vscode.Uri.joinPath(this._extensionUri, 'images'),
      ]
    }
    webviewView.webview.html = this._getHtml(webviewView.webview)

    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) this.sendState()
    })

    webviewView.webview.onDidReceiveMessage(async (msg) => {
      switch (msg.command) {
        case 'start': {
          // Check mekong binary first
          if (!cachedMekongBin) {
            webviewView.webview.postMessage({ type: 'mekongMissing' })
            return
          }
          // Check if dev server is actually running on that port
          const listening = await isPortListening(msg.port)
          if (!listening) {
            const detected = detectPort()
            webviewView.webview.postMessage({
              type:      'portWarning',
              port:      msg.port,
              expire:    msg.expire,
              framework: detected?.framework ?? null,
              cmd:       devCommand(detected?.framework ?? ''),
            })
            return
          }
          await vscode.commands.executeCommand('mekong.startTunnel', msg.port, msg.expire)
          break
        }
        case 'startForce':
          // User confirmed "start anyway" despite port not responding
          await vscode.commands.executeCommand('mekong.startTunnel', msg.port, msg.expire)
          break
        case 'stop':
          await vscode.commands.executeCommand('mekong.stopTunnel')
          break
        case 'detect': {
          // First send the static package.json result immediately
          const detected = detectPort()
          webviewView.webview.postMessage({
            type: 'detected',
            port: detected?.port ?? null,
            framework: detected?.framework ?? null,
            scanning: true,
          })
          // Then do the live port scan and send actual results
          const found = await scanListeningPorts()
          webviewView.webview.postMessage({
            type:      'scanned',
            ports:     found,
            basePort:  detected?.port ?? null,
            framework: detected?.framework ?? null,
          })
          break
        }
        case 'copy':
          if (publicUrl) {
            await vscode.env.clipboard.writeText(publicUrl)
            vscode.window.showInformationMessage('URL copied to clipboard!')
            webviewView.webview.postMessage({ type: 'copied' })
          }
          break
        case 'open':
          if (publicUrl) vscode.env.openExternal(vscode.Uri.parse(publicUrl))
          break
        case 'openOutput':
          outputChannel?.show()
          break
        case 'install': {
          vscode.env.openExternal(vscode.Uri.parse(getInstallScriptUrl()))
          break
        }
        case 'copyText':
          if (msg.text) await vscode.env.clipboard.writeText(msg.text)
          break
        case 'checkMekong':
          // Re-check after user installs — reset cache first
          cachedMekongBin = undefined
          findMekong().then(bin => { cachedMekongBin = bin; panelProvider?.sendState() })
          break
        case 'login': {
          // Spawn `mekong login` in a new terminal and watch config for changes
          if (cachedMekongBin === undefined) cachedMekongBin = await findMekong()
          const loginBin = cachedMekongBin
          if (!loginBin) {
            vscode.window.showErrorMessage('Install mekong CLI first, then log in.')
            break
          }
          const term = vscode.window.createTerminal({ name: 'Mekong Login', hideFromUser: false })
          term.show()
          term.sendText(`"${loginBin}" login`)
          // Watch ~/.mekong/ for config changes after login completes
          const mekongDir = path.join(os.homedir(), '.mekong')
          if (!fs.existsSync(mekongDir)) fs.mkdirSync(mekongDir, { recursive: true })
          let loginDebounce: NodeJS.Timeout | null = null
          const loginWatcher = fs.watch(mekongDir, { persistent: false }, () => {
            if (loginDebounce) clearTimeout(loginDebounce)
            loginDebounce = setTimeout(async () => {
              const saved = readSavedAuth()
              if (saved?.token) {
                loginWatcher.close()
                await refreshAuth()
                panelProvider?.sendState()
              }
            }, 500)
          })
          // Stop watching after 10 minutes
          setTimeout(() => { try { loginWatcher.close() } catch {} }, 10 * 60 * 1000)
          break
        }
        case 'logout': {
          const cfgPath = path.join(os.homedir(), '.mekong', 'config.json')
          try { fs.unlinkSync(cfgPath) } catch {}
          cachedAuth = null
          panelProvider?.sendState()
          break
        }
        case 'refreshAuth': {
          await refreshAuth()
          panelProvider?.sendState()
          break
        }
        // ── Live server commands from panel ──
        case 'startLive':
          await vscode.commands.executeCommand('mekong.startLiveServer', undefined, false)
          break
        case 'startLivePreview':
          await vscode.commands.executeCommand('mekong.startLiveServer', undefined, true)
          break
        case 'stopLive':
          await vscode.commands.executeCommand('mekong.stopLiveServer')
          break
        case 'openLive':
          if (liveServer) {
            vscode.env.openExternal(vscode.Uri.parse(`http://localhost:${liveServer.port}`))
          }
          break
        case 'tunnelLive':
          if (liveServer) {
            await vscode.commands.executeCommand('mekong.startTunnel', liveServer.port)
          }
          break
        case 'stopLiveTunnel':
          if (hasLiveTunnel()) {
            await vscode.commands.executeCommand('mekong.stopTunnel')
          }
          break
        case 'copyLivePublic':
          if (publicUrl && hasLiveTunnel()) {
            await vscode.env.clipboard.writeText(publicUrl)
            webviewView.webview.postMessage({ type: 'livePublicCopied' })
          }
          break
        case 'openLivePublic':
          if (publicUrl && hasLiveTunnel()) {
            vscode.env.openExternal(vscode.Uri.parse(publicUrl))
          }
          break
        case 'shareLivePublic':
          if (publicUrl && hasLiveTunnel()) {
            await vscode.env.clipboard.writeText(publicUrl)
            vscode.window.showInformationMessage('Public URL copied. Share it anywhere.')
            webviewView.webview.postMessage({ type: 'livePublicShared' })
          }
          break
        case 'openPreview':
          await vscode.commands.executeCommand('mekong.openLivePreview')
          break
        case 'copyLive':
          if (liveServer) {
            const url = `http://localhost:${liveServer.port}`
            await vscode.env.clipboard.writeText(url)
            webviewView.webview.postMessage({ type: 'liveCopied' })
          }
          break
      }
    })

    this.sendState()
  }

  sendState() {
    if (!this._view) return
    const isRunning = tunnelProcess !== null
    const isLive    = liveServer !== null
    const liveTunnelActive = hasLiveTunnel()
    const view      = this._view

    // badge = undefined is broken in many VS Code versions — use value:0 to hide
    view.badge = (isRunning || isLive)
      ? { value: 1, tooltip: liveTunnelActive ? 'Live Server tunnel active' : (isRunning ? 'Tunnel active' : 'Live Server active') }
      : { value: 0, tooltip: '' }

    view.webview.postMessage({
      type:            'state',
      running:         isRunning,
      url:             publicUrl,
      tunnelPort:      tunnelPort,
      liveRunning:     isLive,
      livePort:        liveServer?.port ?? null,
      liveTunnelActive,
      mekongInstalled: cachedMekongBin !== null && cachedMekongBin !== undefined,
      platform:        process.platform,   // 'darwin' | 'linux' | 'win32'
      arch:            process.arch,       // 'arm64' | 'x64'
      loggedIn:        !!cachedAuth,
      userEmail:       cachedAuth?.email ?? '',
      userPlan:        cachedAuth?.plan ?? '',
    })
  }

  private _getHtml(webview: vscode.Webview): string {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'media', 'webview.js')
    )
    const logoUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'images', 'MekongNoBG.png')
    )
    const htmlPath = path.join(this._extensionUri.fsPath, 'media', 'webview.html')
    let html = fs.readFileSync(htmlPath, 'utf8')
    html = html.split('__CSP_SOURCE__').join(webview.cspSource)
    html = html.replace('__SCRIPT_URI__', scriptUri.toString())
    html = html.replace('__LOGO_URI__', logoUri.toString())
    return html
  }
}

// ── Live Preview Panel HTML ───────────────────────────────────────────────────
function getLivePreviewHtml(port: number, openPath: string = '/'): string {
  const url = `http://localhost:${port}${openPath}`
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; frame-src http://localhost:*; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#1e1e1e;color:#ccc}

/* ── Toolbar ─────────────────────────────────────────────────────────── */
#toolbar{height:42px;background:#252526;border-bottom:1px solid #3c3c3c;display:flex;align-items:center;gap:7px;padding:0 10px;flex-shrink:0}
.live-badge{display:flex;align-items:center;gap:5px;padding:3px 9px 3px 6px;border-radius:20px;background:rgba(63,185,80,.12);border:1px solid rgba(63,185,80,.3);flex-shrink:0}
.live-dot{width:6px;height:6px;border-radius:50%;background:#3fb950;animation:livepulse 2s infinite}
@keyframes livepulse{0%,100%{box-shadow:0 0 0 0 rgba(63,185,80,.4)}50%{box-shadow:0 0 0 3px rgba(63,185,80,0)}}
.live-label{font-size:10px;font-weight:700;color:#3fb950;letter-spacing:.5px;text-transform:uppercase}
.tb-sep{width:1px;height:20px;background:#3c3c3c;flex-shrink:0}
#url-bar{flex:1;min-width:0;background:#3c3c3c;border:1px solid #4c4c4c;border-radius:5px;padding:4px 10px;color:#bbb;font-size:11px;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tb-btn{background:transparent;border:1px solid #3c3c3c;border-radius:5px;color:#999;font-size:12px;padding:4px 9px;cursor:pointer;flex-shrink:0;line-height:1;transition:all .12s;font-family:inherit;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tb-btn:hover{background:rgba(255,255,255,.07);color:#ddd;border-color:#555}
#device-btn{max-width:190px}
.size-badge{font-size:10px;font-weight:600;color:#777;background:#2a2a2a;border:1px solid #3c3c3c;border-radius:4px;padding:3px 7px;flex-shrink:0;font-family:monospace;min-width:58px;text-align:center}

/* ── Main layout ─────────────────────────────────────────────────────── */
#main{display:flex;height:calc(100vh - 42px);overflow:hidden}

/* ── Preview area ───────────────────────────────────────────────────── */
#preview-area{flex:1;display:flex;justify-content:center;align-items:flex-start;overflow:auto;background:#2a2a2a}
#preview-area.desktop{display:block;overflow:hidden}
#device-scale{transform-origin:top center}
#preview-area.desktop #device-scale{width:100%;height:100%}

/* ── Device frame ───────────────────────────────────────────────────── */
#device-wrap{position:relative}
#preview-area.desktop #device-wrap{width:100%;height:100%}

/* phone/tablet frame base */
#device-wrap.frame-iphone,
#device-wrap.frame-island,
#device-wrap.frame-android,
#device-wrap.frame-ipad{
  background:#1a1a1c;
  box-shadow:0 0 0 2px #2c2c2e,0 0 0 5px #1a1a1c,0 28px 80px rgba(0,0,0,.85);
  margin:20px 0 40px;
}
#device-wrap.frame-iphone { border-radius:44px; padding:54px 10px 28px }
#device-wrap.frame-island  { border-radius:44px; padding:58px 10px 24px }
#device-wrap.frame-android { border-radius:40px; padding:48px 10px 24px }
#device-wrap.frame-ipad    { border-radius:20px; padding:22px 16px 22px }

/* screen inner */
#screen-inner{overflow:hidden;background:#000;position:relative}
#preview-area.desktop #screen-inner{width:100%;height:100%}
#device-wrap.frame-iphone  #screen-inner{border-radius:8px}
#device-wrap.frame-island  #screen-inner{border-radius:8px}
#device-wrap.frame-android #screen-inner{border-radius:8px}
#device-wrap.frame-ipad    #screen-inner{border-radius:6px}

/* iframe */
#frame{display:block;border:none}
#preview-area.desktop #frame{width:100%;height:100%}

/* ── Decorations (all hidden by default) ────────────────────────────── */
.deco{position:absolute;display:none}

/* Status bar */
#status-bar{position:absolute;top:0;left:0;right:0;height:44px;display:flex;align-items:flex-end;justify-content:space-between;padding:0 20px 6px;font-size:12px;font-weight:700;color:#fff;z-index:4;pointer-events:none}
.sb-icons{display:flex;align-items:center;gap:5px}
#device-wrap.frame-desktop #status-bar,
#device-wrap.frame-ipad    #status-bar{display:none}

/* Dynamic Island */
#deco-island{width:126px;height:36px;background:#000;border-radius:20px;top:12px;left:50%;transform:translateX(-50%);z-index:5}
/* Notch (older iPhone) */
#deco-notch{width:154px;height:32px;background:#1a1a1c;border-radius:0 0 22px 22px;top:0;left:50%;transform:translateX(-50%);z-index:5}
/* Punch-hole (Android) */
#deco-hole{width:14px;height:14px;background:#000;border-radius:50%;top:14px;left:50%;transform:translateX(-50%);z-index:5}
/* Home indicator */
#deco-home{width:120px;height:5px;background:rgba(255,255,255,.3);border-radius:3px;bottom:6px;left:50%;transform:translateX(-50%)}
/* Side buttons */
#deco-mute   {width:3px;height:18px;border-radius:2px;background:#2a2a2c;left:2px;top:62px}
#deco-vup    {width:3px;height:28px;border-radius:2px;background:#2a2a2c;left:2px;top:90px}
#deco-vdn    {width:3px;height:28px;border-radius:2px;background:#2a2a2c;left:2px;top:128px}
#deco-power  {width:3px;height:38px;border-radius:2px;background:#2a2a2c;right:2px;top:100px}

/* ── Side tools ─────────────────────────────────────────────────────── */
#side-tools{width:40px;background:#252526;border-left:1px solid #3c3c3c;display:flex;flex-direction:column;align-items:center;padding:8px 0;gap:2px;flex-shrink:0}
.st-btn{width:32px;height:32px;border-radius:6px;background:transparent;border:none;color:#888;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .12s}
.st-btn:hover{background:rgba(255,255,255,.08);color:#ddd}
.st-btn.on{color:#007acc}
.st-sep{width:24px;height:1px;background:#3c3c3c;margin:3px 0}

/* ── Picker overlay ─────────────────────────────────────────────────── */
#picker-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;display:none;align-items:center;justify-content:center}
#picker-overlay.open{display:flex}
#picker-panel{background:#252526;border:1px solid #3c3c3c;border-radius:12px;width:540px;max-width:92vw;height:72vh;max-height:620px;display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(0,0,0,.8);overflow:hidden}
.pk-header{display:flex;align-items:center;padding:14px 16px 10px;border-bottom:1px solid #3c3c3c;flex-shrink:0}
.pk-title{font-size:14px;font-weight:700;color:#eee;flex:1}
.pk-close{width:28px;height:28px;border-radius:6px;background:transparent;border:none;color:#888;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center}
.pk-close:hover{background:rgba(255,255,255,.08);color:#ddd}
.pk-search{padding:9px 14px;border-bottom:1px solid #3c3c3c;flex-shrink:0}
.pk-search input{width:100%;background:#3c3c3c;border:1px solid #555;border-radius:6px;padding:6px 10px;color:#ccc;font-size:12px;outline:none;font-family:inherit}
.pk-search input:focus{border-color:#007acc}
#pk-content{overflow-y:auto;flex:1;padding:8px 0}
.pk-top-card{margin:8px 14px;padding:10px 14px;background:#2d2d2d;border:1px solid #3c3c3c;border-radius:8px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:all .15s}
.pk-top-card:hover{background:#383838;border-color:#555}
.pk-group-label{font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#777;padding:10px 16px 5px}
.pk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(108px,1fr));gap:6px;padding:0 12px 10px}
.pk-card{background:#2d2d2d;border:1px solid #3c3c3c;border-radius:8px;padding:10px 6px 8px;text-align:center;cursor:pointer;transition:all .15s;display:flex;flex-direction:column;align-items:center;gap:3px}
.pk-card:hover{background:#383838;border-color:#555}
.pk-card.sel{border-color:#007acc;background:rgba(0,122,204,.1)}
.pk-name{font-size:10px;font-weight:600;color:#ccc;line-height:1.3}
.pk-size{font-size:9px;color:#777;font-family:monospace;margin-top:1px}
.pk-card.hidden,.pk-group-label.hidden,.pk-grid.hidden{display:none}
</style>
</head>
<body>

<!-- Toolbar -->
<div id="toolbar">
  <div class="live-badge"><div class="live-dot"></div><span class="live-label">Live</span></div>
  <div class="tb-sep"></div>
  <div id="url-bar"></div>
  <button class="tb-btn" id="refresh-btn" title="Reload">&#x21BB;</button>
  <div class="tb-sep"></div>
  <button class="tb-btn" id="device-btn" title="Choose device simulator">&#x1F4F1; Desktop &#x25BE;</button>
  <div class="size-badge" id="size-badge">Full</div>
</div>

<!-- Main -->
<div id="main">
  <div id="preview-area" class="desktop">
    <div id="device-scale">
      <div id="device-wrap" class="frame-desktop">
        <!-- Status bar -->
        <div id="status-bar">
          <span id="clock"></span>
          <span class="sb-icons">
            <svg width="17" height="11" viewBox="0 0 17 11" fill="#fff"><rect x="0" y="4" width="3" height="7" rx="1" opacity=".4"/><rect x="4.5" y="2.5" width="3" height="8.5" rx="1" opacity=".6"/><rect x="9" y="1" width="3" height="10" rx="1" opacity=".8"/><rect x="13.5" y="0" width="3" height="11" rx="1"/></svg>
            <svg width="15" height="11" viewBox="0 0 15 11" fill="none" stroke="#fff" stroke-width="1.5"><path d="M7.5 2.5C10.5 2.5 13 4.5 13 7"/><path d="M7.5 2.5C4.5 2.5 2 4.5 2 7"/><path d="M7.5 5.5C9 5.5 10.5 6.5 10.5 8"/><path d="M7.5 5.5C6 5.5 4.5 6.5 4.5 8"/><circle cx="7.5" cy="10" r="1" fill="#fff" stroke="none"/></svg>
            <svg width="26" height="12" viewBox="0 0 26 12" fill="none"><rect x=".5" y=".5" width="22" height="11" rx="3.5" stroke="#fff" stroke-opacity=".35"/><rect x="1.5" y="1.5" width="18" height="9" rx="2.5" fill="#fff"/><rect x="23" y="4" width="2.5" height="4" rx="1.2" fill="#fff" opacity=".4"/></svg>
          </span>
        </div>
        <!-- Decorations -->
        <div class="deco" id="deco-island"></div>
        <div class="deco" id="deco-notch"></div>
        <div class="deco" id="deco-hole"></div>
        <div class="deco" id="deco-home"></div>
        <div class="deco" id="deco-mute"></div>
        <div class="deco" id="deco-vup"></div>
        <div class="deco" id="deco-vdn"></div>
        <div class="deco" id="deco-power"></div>
        <!-- Screen -->
        <div id="screen-inner">
          <iframe id="frame" sandbox="allow-scripts allow-same-origin allow-forms allow-modals allow-popups"></iframe>
        </div>
      </div>
    </div>
  </div>

  <!-- Side toolbar -->
  <div id="side-tools">
    <button class="st-btn" id="st-rotate" title="Rotate portrait / landscape">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 22v-6h6"/><path d="M22 13A10 10 0 0 1 3.5 18.5"/><path d="M2 11A10 10 0 0 1 20.5 5.5"/></svg>
    </button>
    <div class="st-sep"></div>
    <button class="st-btn" id="st-zoomin"  title="Zoom in">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3M11 8v6M8 11h6"/></svg>
    </button>
    <button class="st-btn" id="st-zoomout" title="Zoom out">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3M8 11h6"/></svg>
    </button>
    <div class="st-sep"></div>
    <button class="st-btn" id="st-open" title="Open in browser">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
    </button>
    <div class="st-sep"></div>
    <button class="st-btn" id="st-reset" title="Reset zoom">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg>
    </button>
  </div>
</div>

<!-- Device Picker -->
<div id="picker-overlay">
  <div id="picker-panel">
    <div class="pk-header">
      <span class="pk-title">&#x1F4F1; Choose a Device Simulator</span>
      <button class="pk-close" id="pk-close">&#x2715;</button>
    </div>
    <div class="pk-search"><input id="pk-input" type="text" placeholder="Search device name or size&#x2026;"></div>
    <div id="pk-content"></div>
  </div>
</div>

<script>
(function(){
var vsApi; try{ vsApi = acquireVsCodeApi(); }catch(e){}
var PREVIEW_URL = ${JSON.stringify(url)};

var DEVICES = [
  {g:'Android Phones', items:[
    {n:'Galaxy S20',        w:360, h:800,  f:'android'},
    {n:'Galaxy S21 Ultra',  w:384, h:854,  f:'android'},
    {n:'Galaxy S22',        w:360, h:780,  f:'android'},
    {n:'Galaxy S22 Ultra',  w:412, h:915,  f:'android'},
    {n:'Galaxy S24',        w:360, h:780,  f:'android'},
    {n:'Galaxy S24 Ultra',  w:412, h:915,  f:'android'},
    {n:'Google Pixel 5',    w:393, h:851,  f:'android'},
    {n:'Google Pixel 6 Pro',w:412, h:915,  f:'android'},
    {n:'OnePlus Nord 2',    w:412, h:915,  f:'android'},
    {n:'Xiaomi 12',         w:393, h:851,  f:'android'},
    {n:'Huawei P30 Pro',    w:360, h:780,  f:'android'},
  ]},
  {g:'iPhone', items:[
    {n:'iPhone SE',          w:375, h:667,  f:'iphone'},
    {n:'iPhone X',           w:375, h:812,  f:'iphone'},
    {n:'iPhone 11',          w:414, h:896,  f:'iphone'},
    {n:'iPhone 12',          w:390, h:844,  f:'iphone'},
    {n:'iPhone 12 Mini',     w:360, h:780,  f:'iphone'},
    {n:'iPhone 12 Pro Max',  w:428, h:926,  f:'iphone'},
    {n:'iPhone 13',          w:390, h:844,  f:'iphone'},
    {n:'iPhone 13 Pro',      w:390, h:844,  f:'iphone'},
    {n:'iPhone 13 Pro Max',  w:428, h:926,  f:'iphone'},
    {n:'iPhone 14',          w:390, h:844,  f:'iphone'},
    {n:'iPhone 14 Plus',     w:428, h:926,  f:'iphone'},
    {n:'iPhone 14 Pro',      w:393, h:852,  f:'island'},
    {n:'iPhone 14 Pro Max',  w:430, h:932,  f:'island'},
    {n:'iPhone 15 Pro',      w:393, h:852,  f:'island'},
    {n:'iPhone 15 Pro Max',  w:430, h:932,  f:'island'},
    {n:'iPhone 16',          w:393, h:852,  f:'island'},
    {n:'iPhone 16 Pro Max',  w:440, h:956,  f:'island'},
    {n:'iPhone 17 Pro',      w:393, h:852,  f:'island'},
    {n:'iPhone 17 Pro Max',  w:440, h:956,  f:'island'},
  ]},
  {g:'iPad', items:[
    {n:'iPad Mini',          w:768,  h:1024, f:'ipad'},
    {n:'iPad Air',           w:820,  h:1180, f:'ipad'},
    {n:'iPad Pro 11"',       w:834,  h:1194, f:'ipad'},
    {n:'iPad Pro 12.9"',     w:1024, h:1366, f:'ipad'},
  ]},
];

var state = {device:null, rotated:false, zoom:1};
var wrap   = document.getElementById('device-wrap');
var scale  = document.getElementById('device-scale');
var iframe = document.getElementById('frame');
var screen = document.getElementById('screen-inner');
var area   = document.getElementById('preview-area');
var sizeBadge = document.getElementById('size-badge');
var deviceBtn = document.getElementById('device-btn');

// Set iframe src after DOM load to avoid CSP pre-navigation issues
iframe.src = PREVIEW_URL;
document.getElementById('url-bar').textContent = PREVIEW_URL;

// Clock
function updateClock(){
  var d=new Date(),h=d.getHours(),m=d.getMinutes();
  document.getElementById('clock').textContent=(h<10?'0'+h:h)+':'+(m<10?'0'+m:m);
}
updateClock(); setInterval(updateClock,30000);

// Build picker
(function(){
  var content = document.getElementById('pk-content');
  // Desktop shortcut
  var top = document.createElement('div');
  top.className='pk-top-card';
  top.innerHTML='<svg width="20" height="14" viewBox="0 0 24 17" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="1" y="1" width="22" height="13" rx="2"/><path d="M8 17h8M12 14v3"/></svg><span style="font-size:12px;font-weight:600;color:#ccc">Desktop — Full width</span>';
  top.onclick=function(){selectDesktop();closePicker();};
  content.appendChild(top);

  DEVICES.forEach(function(group){
    var gl=document.createElement('div');
    gl.className='pk-group-label'; gl.textContent=group.g; content.appendChild(gl);
    var grid=document.createElement('div');
    grid.className='pk-grid'; content.appendChild(grid);
    group.items.forEach(function(d){
      var card=document.createElement('div');
      card.className='pk-card';
      card.dataset.n=(d.n+' '+d.w+'x'+d.h).toLowerCase();
      var phoneIcon = d.f==='ipad'
        ? '<svg width="22" height="28" viewBox="0 0 22 28" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="1" width="20" height="26" rx="3"/><circle cx="11" cy="23.5" r="1.2" fill="currentColor" opacity=".4"/></svg>'
        : '<svg width="14" height="26" viewBox="0 0 14 26" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="1" width="12" height="24" rx="3"/>'+(d.f==='island'?'<rect x="4" y="2.5" width="6" height="2" rx="1" fill="currentColor" opacity=".4"/>':'<circle cx="7" cy="22.5" r="1" fill="currentColor" opacity=".3"/><rect x="4.5" y="2.5" width="5" height="1" rx=".5" fill="currentColor" opacity=".3"/>')+'</svg>';
      card.innerHTML=phoneIcon+'<div class="pk-name">'+d.n+'</div><div class="pk-size">'+d.w+' \u00d7 '+d.h+'</div>';
      card.onclick=function(){selectDevice(d,false);closePicker();};
      grid.appendChild(card);
    });
  });
})();

function selectDesktop(){
  state.device=null; state.rotated=false;
  wrap.className='frame-desktop';
  area.className='desktop';
  screen.style.cssText='';
  iframe.style.cssText='display:block;border:none;width:100%;height:100%';
  scale.style.transform='';
  sizeBadge.textContent='Full';
  deviceBtn.textContent='\u2B1C Desktop \u25BE';
  hideDecos();
}

function selectDevice(d, keepRotated){
  state.device=d;
  if(!keepRotated) state.rotated=false;
  var w=state.rotated?d.h:d.w;
  var h=state.rotated?d.w:d.h;
  wrap.className='frame-'+d.f;
  area.className='device';
  area.style.cssText='display:flex;justify-content:center;align-items:flex-start;overflow:auto;background:#2a2a2a';
  screen.style.cssText='width:'+w+'px;height:'+h+'px;overflow:hidden;background:#000;position:relative';
  iframe.style.cssText='display:block;border:none;width:'+w+'px;height:'+h+'px';
  applyZoom();
  sizeBadge.textContent=w+' \u00d7 '+h;
  deviceBtn.textContent='\uD83D\uDCF1 '+d.n+' \u25BE';
  showDecos(d.f);
  document.querySelectorAll('.pk-card.sel').forEach(function(c){c.classList.remove('sel');});
}

function applyZoom(){
  if(state.zoom===1){ scale.style.transform=''; return; }
  scale.style.transform='scale('+state.zoom+')';
  scale.style.transformOrigin='top center';
}

function showDecos(f){
  hideDecos();
  function show(id){ var el=document.getElementById(id); if(el) el.style.display='block'; }
  if(f==='island'){  show('deco-island'); show('deco-home'); show('deco-vup'); show('deco-vdn'); show('deco-mute'); show('deco-power'); }
  else if(f==='iphone'){ show('deco-notch'); show('deco-home'); show('deco-vup'); show('deco-vdn'); show('deco-mute'); show('deco-power'); }
  else if(f==='android'){ show('deco-hole'); show('deco-home'); show('deco-vup'); show('deco-vdn'); show('deco-power'); }
  else if(f==='ipad'){  show('deco-power'); }
}
function hideDecos(){ document.querySelectorAll('.deco').forEach(function(el){el.style.display='none';}); }

// Rotate
document.getElementById('st-rotate').addEventListener('click',function(){
  if(!state.device) return;
  state.rotated=!state.rotated;
  selectDevice(state.device,true);
  this.classList.toggle('on',state.rotated);
});

// Zoom
document.getElementById('st-zoomin').addEventListener('click',function(){
  state.zoom=Math.min(2,+(state.zoom+0.15).toFixed(2));
  applyZoom();
});
document.getElementById('st-zoomout').addEventListener('click',function(){
  state.zoom=Math.max(0.25,+(state.zoom-0.15).toFixed(2));
  applyZoom();
});
document.getElementById('st-reset').addEventListener('click',function(){
  state.zoom=1; applyZoom();
});

// Open in browser
document.getElementById('st-open').addEventListener('click',function(){
  if(vsApi){ vsApi.postMessage({type:'openBrowser',url:PREVIEW_URL}); }
});

// Refresh
document.getElementById('refresh-btn').addEventListener('click',function(){ iframe.src=iframe.src; });

// Device picker
deviceBtn.addEventListener('click', openPicker);
document.getElementById('pk-close').addEventListener('click', closePicker);
document.getElementById('picker-overlay').addEventListener('click',function(e){ if(e.target===this) closePicker(); });

function openPicker(){
  document.getElementById('picker-overlay').classList.add('open');
  var inp=document.getElementById('pk-input');
  inp.value=''; filterPicker('');
  setTimeout(function(){inp.focus();},80);
}
function closePicker(){ document.getElementById('picker-overlay').classList.remove('open'); }
document.getElementById('pk-input').addEventListener('input',function(){ filterPicker(this.value); });

function filterPicker(q){
  q=q.toLowerCase().trim();
  var labels=document.querySelectorAll('.pk-group-label');
  labels.forEach(function(lbl){
    var grid=lbl.nextElementSibling;
    if(!grid) return;
    var cards=grid.querySelectorAll('.pk-card');
    var anyVisible=false;
    cards.forEach(function(card){
      var match=!q||card.dataset.n.includes(q);
      card.classList.toggle('hidden',!match);
      if(match) anyVisible=true;
    });
    lbl.classList.toggle('hidden',!anyVisible);
    grid.classList.toggle('hidden',!anyVisible);
  });
}

// Live reload message from extension
window.addEventListener('message',function(e){
  if(e.data&&e.data.type==='reload'){ iframe.src=iframe.src; }
});
})();
</script>
</body>
</html>`
}

// ── Activate ─────────────────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('Mekong Tunnel')

  // Cache mekong binary + auth info on startup
  findMekong().then(bin => {
    cachedMekongBin = bin
    panelProvider?.sendState()
  })
  refreshAuth().then(() => panelProvider?.sendState())

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100)
  setStatus('idle')
  statusBarItem.show()
  context.subscriptions.push(statusBarItem)

  liveStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99)
  setLiveStatus(false)
  liveStatusBar.show()
  context.subscriptions.push(liveStatusBar)

  panelProvider = new MekongWebviewProvider(context.extensionUri)
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('mekongTunnel.panel', panelProvider)
  )

  // ── Start Tunnel ───────────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.startTunnel', async (portArg?: number, expireArg?: string) => {
      if (tunnelProcess) {
        vscode.window.showWarningMessage('Mekong tunnel is already active.')
        return
      }

      // Re-check and cache mekong binary
      if (cachedMekongBin === undefined) cachedMekongBin = await findMekong()
      const mekongBin = cachedMekongBin
      if (!mekongBin) {
        cachedMekongBin = null
        panelProvider?.sendState()
        const choice = await vscode.window.showErrorMessage(
          'mekong binary not found. Run the install script on your computer, then try starting the tunnel again.',
          'Open Install Script'
        )
        if (choice === 'Open Install Script') {
          vscode.env.openExternal(vscode.Uri.parse(getInstallScriptUrl()))
        }
        return
      }

      let port = portArg
      if (!port) {
        const detected = detectPort()
        if (detected) {
          port = detected.port
        } else {
          const input = await vscode.window.showInputBox({
            prompt: 'Enter local port to tunnel',
            placeHolder: '3000',
            validateInput: v => (!v || isNaN(parseInt(v))) ? 'Enter a valid port number' : null
          })
          if (!input) return
          port = parseInt(input)
        }
      }

      // Warn if nothing is listening on the port (command palette path)
      const listening = await isPortListening(port)
      if (!listening) {
        const detected = detectPort()
        const cmd = devCommand(detected?.framework ?? '')
        const choice = await vscode.window.showWarningMessage(
          `Nothing is listening on port ${port}. Run \`${cmd}\` first to start your dev server.`,
          'Start Anyway', 'Cancel'
        )
        if (choice !== 'Start Anyway') return
      }

      outputChannel!.clear()
      outputChannel!.show(true)

      const config = vscode.workspace.getConfiguration('mekong')
      const args: string[] = [String(port)]
      const expire = expireArg || config.get<string>('expire')
      if (expire && expire.trim()) args.push('--expire', expire.trim())
      const token = config.get<string>('apiToken') || process.env.MEKONG_TOKEN || readSavedToken()
      if (token && token.trim()) args.push('--token', token.trim())
      if (!config.get<boolean>('showQr')) args.push('--no-qr')

      outputChannel!.appendLine(`[mekong] Starting tunnel → localhost:${port}`)
      outputChannel!.appendLine(`[mekong] ${mekongBin} ${args.join(' ')}\n`)

      publicUrl = null
      tunnelPort = port
      const proc = cp.spawn(mekongBin, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      })
      tunnelProcess = proc
      setStatus('starting')
      panelProvider?.sendState()

      const stripAnsi = (s: string) =>
        s.replace(/\x1b\[[0-9;]*[mGKHF]|\x1b\[[0-9;]*m|\x1b\[\d+;\d+;\d+m/g, '')
         .replace(/\x1b\[\d*[A-Za-z]/g, '')

      const handleData = (data: Buffer) => {
        const text  = data.toString()
        const clean = stripAnsi(text)
        outputChannel!.append(clean)
        if (!publicUrl) {
          const match = text.match(/https?:\/\/[^\s\x1b\]]+/)
          if (match) {
            publicUrl = match[0].replace(/[^\w.:/-]/g, '')
            setStatus('running', publicUrl)
            panelProvider?.sendState()
            vscode.window.showInformationMessage(
              `🌐 Tunnel live: ${publicUrl}`, 'Copy URL', 'Open'
            ).then(action => {
              if (action === 'Copy URL') vscode.env.clipboard.writeText(publicUrl!)
              else if (action === 'Open') vscode.env.openExternal(vscode.Uri.parse(publicUrl!))
            })
          }
        }
      }

      proc.stdout?.on('data', handleData)
      proc.stderr?.on('data', handleData)

      proc.on('exit', (code) => {
        if (tunnelProcess === proc) {
          outputChannel?.appendLine(`\n[mekong] Exited (code ${code})`)
          tunnelProcess = null
          publicUrl = null
          tunnelPort = null
          setStatus(code === 0 ? 'idle' : 'error')
          panelProvider?.sendState()
        }
      })
    })
  )

  // ── Stop Tunnel ─────────────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.stopTunnel', () => {
      if (!tunnelProcess) { vscode.window.showWarningMessage('No active tunnel.'); return }
      const proc = tunnelProcess
      tunnelProcess = null
      publicUrl = null
      tunnelPort = null
      killProc(proc)
      setStatus('idle')
      panelProvider?.sendState()
      vscode.window.showInformationMessage('Mekong tunnel stopped.')
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.copyUrl', async () => {
      if (!publicUrl) { vscode.window.showWarningMessage('No active tunnel URL.'); return }
      await vscode.env.clipboard.writeText(publicUrl)
      vscode.window.showInformationMessage('URL copied!')
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.openUrl', () => {
      if (!publicUrl) { vscode.window.showWarningMessage('No active tunnel URL.'); return }
      vscode.env.openExternal(vscode.Uri.parse(publicUrl))
    })
  )

  // ── Start Live Server ───────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.startLiveServer', async (fileUri?: vscode.Uri, previewMode: boolean = false) => {
      if (liveServer) {
        if (fileUri && liveRootDir && !isWithinDir(liveRootDir, fileUri.fsPath)) {
          vscode.window.showWarningMessage('Live Server is already running for a different folder. Stop it first to switch preview roots.')
          return
        }

        const openPath = liveRootDir ? getLiveOpenPath(liveRootDir, fileUri) : '/'

        // Already running
        if (previewMode) {
          await vscode.commands.executeCommand('mekong.openLivePreview', liveServer.port, openPath)
        } else {
          vscode.env.openExternal(vscode.Uri.parse(`http://localhost:${liveServer.port}${openPath}`))
        }
        return
      }

      // Determine root directory
      let rootDir: string | null = null
      if (fileUri) {
        const stat = fs.statSync(fileUri.fsPath)
        rootDir = stat.isDirectory() ? fileUri.fsPath : path.dirname(fileUri.fsPath)
      } else {
        rootDir = detectHtmlRoot()
      }

      if (!rootDir) {
        vscode.window.showErrorMessage('Open a folder or HTML file first.')
        return
      }

      const config   = vscode.workspace.getConfiguration('mekong')
      const basePort = config.get<number>('liveServerPort') ?? 5500

      outputChannel!.appendLine(`[live] Starting Live Server in: ${rootDir}`)
      outputChannel!.appendLine(`[live] Looking for port starting at ${basePort}...`)
      outputChannel!.show(true)

      try {
        liveServer = await startLiveServer(rootDir, basePort)
        liveRootDir = rootDir
      } catch (err: any) {
        vscode.window.showErrorMessage(`Live Server failed to start: ${err.message}`)
        return
      }

      outputChannel!.appendLine(`[live] ✔ Live Server ready on http://localhost:${liveServer.port}\n`)
      setLiveStatus(true, liveServer.port)

      // Watch all files in rootDir for changes
      liveWatcher = vscode.workspace.createFileSystemWatcher(
        new vscode.RelativePattern(rootDir, '**/*.{html,htm,css,js,ts,json,svg,png,jpg,jpeg,gif}')
      )
      const reload = (uri: vscode.Uri) => {
        outputChannel?.appendLine(`[live] File changed: ${path.relative(rootDir!, uri.fsPath)} → reload`)
        liveServer?.broadcast()
        // Also reload the VS Code preview panel if open
        livePreviewPanel?.webview.postMessage({ type: 'reload' })
      }
      liveWatcher.onDidChange(reload)
      liveWatcher.onDidCreate(reload)
      liveWatcher.onDidDelete(reload)

      // Determine which path to open
      let openPath = '/'
      if (fileUri && fileUri.fsPath.match(/\.html?$/i)) {
        openPath = '/' + path.relative(rootDir, fileUri.fsPath).replace(/\\/g, '/')
      }

      const liveUrl = `http://localhost:${liveServer.port}${openPath}`

      if (previewMode) {
        // Open VS Code preview panel (split to the right)
        await vscode.commands.executeCommand('mekong.openLivePreview', liveServer.port, openPath)
        vscode.window.showInformationMessage(
          `⚡ Live Server + Preview: ${liveUrl}`,
          'Open in Browser', 'Stop'
        ).then(action => {
          if (action === 'Open in Browser') vscode.env.openExternal(vscode.Uri.parse(liveUrl))
          if (action === 'Stop')            vscode.commands.executeCommand('mekong.stopLiveServer')
        })
      } else {
        // Open in external browser
        vscode.env.openExternal(vscode.Uri.parse(liveUrl))
        vscode.window.showInformationMessage(
          `⚡ Live Server: ${liveUrl}`,
          'Preview Panel', 'Stop', 'Tunnel'
        ).then(action => {
          if (action === 'Preview Panel') vscode.commands.executeCommand('mekong.openLivePreview', liveServer?.port)
          if (action === 'Stop')          vscode.commands.executeCommand('mekong.stopLiveServer')
          if (action === 'Tunnel')        vscode.commands.executeCommand('mekong.startTunnel', liveServer?.port)
        })
      }
    })
  )

  // ── Open Live Preview Panel ─────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.openLivePreview', async (port?: number, openPath?: string) => {
      const previewPort = port ?? liveServer?.port
      if (!previewPort) {
        vscode.window.showWarningMessage('Start Live Server first to open the preview panel.')
        return
      }

      // If already open, just reveal it
      if (livePreviewPanel) {
        livePreviewPanel.webview.html = getLivePreviewHtml(previewPort, openPath ?? '/')
        livePreviewPanel.reveal(vscode.ViewColumn.Two, true)
        return
      }

      livePreviewPanel = vscode.window.createWebviewPanel(
        'mekong.livePreview',
        'Live Preview',
        { viewColumn: vscode.ViewColumn.Two, preserveFocus: true },
        {
          enableScripts:          true,
          retainContextWhenHidden: true,
        }
      )
      livePreviewPanel.webview.html = getLivePreviewHtml(previewPort, openPath ?? '/')
      livePreviewPanel.onDidDispose(() => { livePreviewPanel = null })
      livePreviewPanel.webview.onDidReceiveMessage(msg => {
        if (msg.type === 'openBrowser') {
          vscode.env.openExternal(vscode.Uri.parse(msg.url))
        }
      })
    })
  )

  // ── Stop Live Server ────────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.stopLiveServer', () => {
      if (!liveServer) { vscode.window.showWarningMessage('No active Live Server.'); return }
      liveServer.stop()
      liveServer = null
      liveRootDir = null
      liveWatcher?.dispose()
      liveWatcher = null
      livePreviewPanel?.dispose()
      livePreviewPanel = null
      setLiveStatus(false)
      panelProvider?.sendState()
      vscode.window.showInformationMessage('Live Server stopped.')
      outputChannel?.appendLine('[live] Live Server stopped.')
    })
  )

  // ── Open Live Server in browser ─────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.openLiveInBrowser', () => {
      if (!liveServer) { vscode.window.showWarningMessage('Live Server is not running.'); return }
      vscode.env.openExternal(vscode.Uri.parse(`http://localhost:${liveServer.port}`))
    })
  )

  // ── Right-click "Open with Live Server" ─────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.openWithLiveServer', (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri
      if (!target) { vscode.window.showWarningMessage('No file selected.'); return }
      vscode.commands.executeCommand('mekong.startLiveServer', target, false)
    })
  )

  // ── Right-click "Open with Mekong Preview" ───────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.openWithLiveServerPreview', (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri
      if (!target) { vscode.window.showWarningMessage('No file selected.'); return }
      vscode.commands.executeCommand('mekong.startLiveServer', target, true)
    })
  )

  const config = vscode.workspace.getConfiguration('mekong')
  if (config.get<boolean>('autoStart')) {
    vscode.commands.executeCommand('mekong.startTunnel')
  }
}

export function deactivate() {
  if (tunnelProcess) { const p = tunnelProcess; tunnelProcess = null; killProc(p) }
  liveServer?.stop()
  liveWatcher?.dispose()
  livePreviewPanel?.dispose()
}
