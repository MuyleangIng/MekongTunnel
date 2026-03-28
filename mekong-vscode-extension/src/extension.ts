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
let statusBarItem: vscode.StatusBarItem
let liveStatusBar: vscode.StatusBarItem
let outputChannel: vscode.OutputChannel | null = null
let panelProvider: MekongWebviewProvider | null = null

let liveServer: LiveServerHandle | null = null
let liveWatcher: vscode.FileSystemWatcher | null = null

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
      localResourceRoots: [vscode.Uri.joinPath(this._extensionUri, 'media')]
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
          const base = 'https://github.com/MuyleangIng/MekongTunnel/releases/download/v1.5.0'
          let url = `${base}/mekong-darwin-arm64`
          if (process.platform === 'win32') {
            url = `${base}/mekong-windows-amd64.exe`
          } else if (process.platform === 'linux') {
            url = process.arch === 'arm64' ? `${base}/mekong-linux-arm64` : `${base}/mekong-linux-amd64`
          } else {
            url = process.arch === 'arm64' ? `${base}/mekong-darwin-arm64` : `${base}/mekong-darwin-amd64`
          }
          vscode.env.openExternal(vscode.Uri.parse(url))
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
          await vscode.commands.executeCommand('mekong.startLiveServer')
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
    const view      = this._view

    // badge = undefined is broken in many VS Code versions — use value:0 to hide
    view.badge = (isRunning || isLive)
      ? { value: 1, tooltip: isRunning ? 'Tunnel active' : 'Live Server active' }
      : { value: 0, tooltip: '' }

    view.webview.postMessage({
      type:            'state',
      running:         isRunning,
      url:             publicUrl,
      liveRunning:     isLive,
      livePort:        liveServer?.port ?? null,
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
    const htmlPath = path.join(this._extensionUri.fsPath, 'media', 'webview.html')
    let html = fs.readFileSync(htmlPath, 'utf8')
    html = html.replace('__CSP_SOURCE__', webview.cspSource)
    html = html.replace('__SCRIPT_URI__', scriptUri.toString())
    return html
  }
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
          'mekong binary not found. Tunneling requires the mekong CLI. Install it from GitHub.',
          'Install'
        )
        if (choice === 'Install') {
          vscode.env.openExternal(vscode.Uri.parse('https://github.com/MuyleangIng/MekongTunnel/releases/latest'))
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
    vscode.commands.registerCommand('mekong.startLiveServer', async (fileUri?: vscode.Uri) => {
      if (liveServer) {
        // Already running — open browser
        vscode.env.openExternal(vscode.Uri.parse(`http://localhost:${liveServer.port}`))
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
      }
      liveWatcher.onDidChange(reload)
      liveWatcher.onDidCreate(reload)
      liveWatcher.onDidDelete(reload)

      // Determine which file to open in browser
      let openPath = '/'
      if (fileUri && fileUri.fsPath.match(/\.html?$/i)) {
        openPath = '/' + path.relative(rootDir, fileUri.fsPath).replace(/\\/g, '/')
      }

      const liveUrl = `http://localhost:${liveServer.port}${openPath}`
      vscode.env.openExternal(vscode.Uri.parse(liveUrl))

      vscode.window.showInformationMessage(
        `⚡ Live Server: ${liveUrl}`,
        'Stop', 'Tunnel'
      ).then(action => {
        if (action === 'Stop')   vscode.commands.executeCommand('mekong.stopLiveServer')
        if (action === 'Tunnel') vscode.commands.executeCommand('mekong.startTunnel', liveServer?.port)
      })
    })
  )

  // ── Stop Live Server ────────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('mekong.stopLiveServer', () => {
      if (!liveServer) { vscode.window.showWarningMessage('No active Live Server.'); return }
      liveServer.stop()
      liveServer = null
      liveWatcher?.dispose()
      liveWatcher = null
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
      if (!target) {
        vscode.window.showWarningMessage('No file selected.')
        return
      }
      vscode.commands.executeCommand('mekong.startLiveServer', target)
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
}
