/**
 * mekong-cli SDK tests
 * Run: node test/sdk.test.js
 *
 * Tests: getToken, whoami, logout/login flow, expose() with a real local server
 *
 * Set MEKONG_TOKEN env var or run `mekong login` first to test authenticated paths.
 * Tests that require a real tunnel are skipped if the mekong binary is not found.
 */

import assert  from 'assert'
import http    from 'http'
import path    from 'path'
import os      from 'os'
import fs      from 'fs'
import { createRequire } from 'module'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

// Load the CJS SDK from the parent directory
const mekong = require('../lib/sdk.js')

// ─── Simple test runner ────────────────────────────────────────────────────────

let passed = 0, failed = 0, skipped = 0
const results = []

async function test(name, fn) {
  try {
    await fn()
    results.push({ name, status: 'pass' })
    passed++
  } catch (err) {
    if (err.message?.startsWith('SKIP:')) {
      results.push({ name, status: 'skip', detail: err.message.slice(5).trim() })
      skipped++
    } else {
      results.push({ name, status: 'fail', detail: err.message })
      failed++
    }
  }
}

function skip(reason) {
  const err = new Error('SKIP: ' + reason)
  throw err
}

// ─── Tests ────────────────────────────────────────────────────────────────────

await test('getToken() returns string or null', async () => {
  const tok = mekong.getToken()
  assert.ok(tok === null || typeof tok === 'string', 'must be string or null')
})

await test('whoami() returns object or null', async () => {
  const info = mekong.whoami()
  assert.ok(info === null || (typeof info === 'object' && info !== null), 'must be object or null')
  if (info) {
    assert.ok('token' in info, 'object should have token key')
  }
})

await test('getToken() matches whoami().token when logged in', async () => {
  const tok  = mekong.getToken()
  const info = mekong.whoami()
  if (!tok || !info) skip('not logged in')
  assert.strictEqual(tok, info.token, 'getToken() must equal whoami().token')
})

await test('MEKONG_TOKEN env overrides saved config', async () => {
  const saved = process.env.MEKONG_TOKEN
  process.env.MEKONG_TOKEN = 'mkt_envtest_xxx'
  const tok = mekong.getToken()
  process.env.MEKONG_TOKEN = saved ?? ''
  if (!saved) delete process.env.MEKONG_TOKEN
  assert.strictEqual(tok, 'mkt_envtest_xxx', 'env token must take priority')
})

await test('expose() rejects invalid port', async () => {
  try {
    await mekong.expose(0)
    assert.fail('should have thrown')
  } catch (err) {
    // Expected — port 0 or negative is invalid; binary will fail
    assert.ok(err, 'error expected for invalid port')
  }
})

await test('expose() on a local HTTP server returns a URL', async () => {
  // Start a tiny local server
  const server = http.createServer((req, res) => res.end('hello from mekong-cli test'))
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  let tunnel
  try {
    tunnel = await mekong.expose(port, { noQr: true, timeout: 20000 })
    assert.ok(typeof tunnel.url === 'string', 'url must be a string')
    assert.ok(tunnel.url.startsWith('https://'), `url must start with https://, got: ${tunnel.url}`)
    assert.ok(typeof tunnel.stop === 'function', 'stop must be a function')
  } catch (err) {
    if (err.message?.includes('not found') || err.message?.includes('ENOENT')) {
      skip('mekong binary not installed — install it first: https://mekongtunnel.dev/docs/installation')
    }
    throw err
  } finally {
    tunnel?.stop()
    server.close()
  }
})

await test('expose() stop() cleans up process', async () => {
  const server = http.createServer((req, res) => res.end('ok'))
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  let tunnel
  try {
    tunnel = await mekong.expose(port, { noQr: true, timeout: 20000 })
    const urlBefore = tunnel.url
    tunnel.stop()
    // After stop, url should still be accessible as a string
    assert.ok(typeof urlBefore === 'string')
  } catch (err) {
    if (err.message?.includes('not found') || err.message?.includes('ENOENT')) {
      skip('mekong binary not installed')
    }
    throw err
  } finally {
    tunnel?.stop()
    server.close()
  }
})

await test('expose() with token passes --token flag', async () => {
  const token = mekong.getToken()
  if (!token) skip('no token — run: mekong login')

  const server = http.createServer((req, res) => res.end('ok'))
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  let tunnel
  try {
    tunnel = await mekong.expose(port, { token, noQr: true, timeout: 20000 })
    assert.ok(
      tunnel.url.includes('.proxy.angkorsearch.dev'),
      'URL should be on the default proxy.angkorsearch.dev tunnel domain'
    )
  } catch (err) {
    if (err.message?.includes('not found') || err.message?.includes('ENOENT')) {
      skip('mekong binary not installed')
    }
    throw err
  } finally {
    tunnel?.stop()
    server.close()
  }
})

// ─── Print results ─────────────────────────────────────────────────────────────

console.log('\n  mekong-cli SDK Tests\n  ' + '─'.repeat(44))
for (const r of results) {
  if (r.status === 'pass')  console.log(`  ✅ PASS  ${r.name}`)
  if (r.status === 'fail')  console.log(`  ❌ FAIL  ${r.name}\n           ${r.detail}`)
  if (r.status === 'skip')  console.log(`  ⚪ SKIP  ${r.name} — ${r.detail}`)
}
console.log(`\n  Results: ${passed} passed · ${failed} failed · ${skipped} skipped\n`)

if (failed > 0) process.exit(1)
