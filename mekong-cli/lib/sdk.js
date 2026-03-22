'use strict'
/**
 * mekong-cli/sdk — programmatic API for Node.js projects.
 *
 * Usage:
 *   const mekong = require('mekong-cli/sdk')
 *
 *   // Expose a local port (returns public URL)
 *   const { url, stop } = await mekong.expose(3000)
 *   console.log('Public:', url)
 *   // …later…
 *   stop()
 *
 *   // Auth helpers
 *   const token = mekong.getToken()
 *   await mekong.login()   // opens browser, waits for approval
 *   mekong.logout()        // removes ~/.mekong/config.json
 */

const { spawn }   = require('child_process')
const { findMekong } = require('./find-mekong')
const os   = require('os')
const fs   = require('fs')
const path = require('path')
const http = require('https')

const API_BASE = 'https://api.angkorsearch.dev'
const WEB_BASE = 'https://angkorsearch.dev'

// ── Config helpers ────────────────────────────────────────────────────────────

function mekongDir () {
  return path.join(os.homedir(), '.mekong')
}

function configPath () {
  return path.join(mekongDir(), 'config.json')
}

/**
 * Return the saved API token, or null if not logged in.
 * Also checks MEKONG_TOKEN env var.
 */
function getToken () {
  if (process.env.MEKONG_TOKEN) return process.env.MEKONG_TOKEN
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath(), 'utf8'))
    return cfg.token || null
  } catch {
    return null
  }
}

/** Return saved auth config or null. */
function getAuthConfig () {
  try {
    return JSON.parse(fs.readFileSync(configPath(), 'utf8'))
  } catch {
    return null
  }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function httpsGet (url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let body = ''
      res.on('data', chunk => body += chunk)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }) }
        catch { resolve({ status: res.statusCode, body: {} }) }
      })
    }).on('error', reject)
  })
}

function httpsPost (url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const options = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': 0 },
    }
    const req = http.request(options, res => {
      let body = ''
      res.on('data', chunk => body += chunk)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }) }
        catch { resolve({ status: res.statusCode, body: {} }) }
      })
    })
    req.on('error', reject)
    req.end()
  })
}

function unwrap (body) {
  return body?.data ?? body
}

// ── expose() ─────────────────────────────────────────────────────────────────

/**
 * Expose a local port via the mekong binary.
 * Returns a Promise<{ url: string, stop: () => void }>.
 *
 * @param {number} port  - local port to expose
 * @param {object} [opts]
 * @param {string}  [opts.token]    - API token (falls back to saved login / MEKONG_TOKEN)
 * @param {string}  [opts.expire]   - tunnel lifetime e.g. "2h", "1d"
 * @param {boolean} [opts.daemon]   - run in background (-d)
 * @param {boolean} [opts.noQr]     - suppress QR code
 * @param {string}  [opts.binary]   - custom path to mekong binary
 * @returns {Promise<{ url: string, stop: () => void }>}
 */
function expose (port, opts = {}) {
  return new Promise((resolve, reject) => {
    const binary = opts.binary || findMekong()
    if (!binary) {
      return reject(new Error(
        'mekong binary not found. Install from https://github.com/MuyleangIng/MekongTunnel/releases'
      ))
    }

    const token = opts.token || getToken()

    const args = [String(port)]
    if (opts.expire)         args.push('--expire', opts.expire)
    if (token)               args.push('--token', token)
    if (opts.daemon)         args.push('-d')
    if (opts.noQr !== false) args.push('--no-qr') // default true in SDK mode

    const proc = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] })

    const ansiRe = /\x1b\[[0-9;]*[A-Za-z]/g
    const urlRe  = /https?:\/\/[a-zA-Z0-9][a-zA-Z0-9\-.\/]*[a-zA-Z0-9]/
    let resolved = false

    function handleChunk (chunk) {
      const clean = chunk.toString().replace(ansiRe, '')
      if (!resolved) {
        const m = clean.match(urlRe)
        if (m) {
          resolved = true
          resolve({ url: m[0], stop: () => proc.kill('SIGTERM') })
        }
      }
    }

    proc.stdout.on('data', handleChunk)
    proc.stderr.on('data', handleChunk)

    proc.on('exit', code => {
      if (!resolved) {
        reject(new Error(`mekong exited with code ${code} before tunnel was ready`))
      }
    })

    // Timeout after 30 s if no URL received
    setTimeout(() => {
      if (!resolved) {
        proc.kill('SIGTERM')
        reject(new Error('Timed out waiting for tunnel URL'))
      }
    }, 30_000)
  })
}

// ── login() ──────────────────────────────────────────────────────────────────

/**
 * Open browser → mekongtunnel.dev login page → poll until token received.
 * Saves token to ~/.mekong/config.json.
 * Returns the token string.
 *
 * @returns {Promise<string>} resolved token
 */
async function login () {
  // 1. Create device session
  const { body: raw, status } = await httpsPost(API_BASE + '/api/cli/device')
  if (status !== 200) throw new Error(`Server returned ${status}`)
  const sess = unwrap(raw)
  if (!sess?.session_id) throw new Error('Unexpected server response')

  console.log('\n  Open this URL to log in:')
  console.log('  \x1b[35m' + sess.login_url + '\x1b[0m\n')

  // Try to open browser
  const opener = process.platform === 'win32' ? 'start'
    : process.platform === 'darwin' ? 'open' : 'xdg-open'
  try {
    const { execSync } = require('child_process')
    execSync(`${opener} "${sess.login_url}"`, { stdio: 'ignore' })
  } catch {}

  console.log('  Waiting for authorization', { end: '' })

  // 2. Poll
  const deadline = Date.now() + 5 * 60 * 1000
  const interval = (sess.poll_interval || 3) * 1000

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, interval))
    const { body: pb } = await httpsGet(
      API_BASE + '/api/cli/device?session_id=' + sess.session_id
    )
    const poll = unwrap(pb)
    if (poll?.status === 'approved' && poll.token) {
      // Save to disk
      fs.mkdirSync(mekongDir(), { recursive: true })
      fs.writeFileSync(configPath(), JSON.stringify({ token: poll.token }, null, 2), { mode: 0o600 })
      console.log('\n  \x1b[32m✔  Logged in!\x1b[0m\n')
      return poll.token
    }
    if (poll?.status === 'expired') {
      throw new Error('Session expired — call login() again')
    }
    process.stdout.write('.')
  }
  throw new Error('Login timed out')
}

// ── logout() ─────────────────────────────────────────────────────────────────

/**
 * Remove saved credentials from ~/.mekong/config.json.
 */
function logout () {
  try {
    fs.unlinkSync(configPath())
  } catch {}
}

// ── whoami() ─────────────────────────────────────────────────────────────────

/**
 * Return saved auth config { token, email, user_id } or null.
 */
function whoami () {
  return getAuthConfig()
}

module.exports = { expose, login, logout, whoami, getToken }
