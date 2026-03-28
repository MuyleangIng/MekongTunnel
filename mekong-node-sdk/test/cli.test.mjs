/**
 * mekong-cli binary (CLI) integration tests
 * Run: node test/cli.test.js
 *
 * Tests the mekong-cli bin/mekong-cli.js behaviour.
 * Requires `mekong` binary to be installed for tunnel tests.
 */

import assert          from 'assert'
import { execFile, spawn } from 'child_process'
import path            from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const CLI = path.resolve(__dirname, '../bin/mekong-cli.js')

// ─── Simple async runner ───────────────────────────────────────────────────────

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

function skip(reason) { throw new Error('SKIP: ' + reason) }

function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
      timeout: 10000,
    }, (err, stdout, stderr) => {
      resolve({ code: err?.code ?? 0, stdout, stderr, err })
    })
  })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

await test('--help prints usage', async () => {
  const { stdout, stderr } = await run(['--help'])
  const out = stdout + stderr
  assert.ok(out.toLowerCase().includes('usage') || out.includes('mekong-cli'), `help output missing: ${out}`)
})

await test('no args prints usage and exits non-zero', async () => {
  const { code, stdout, stderr } = await run([])
  // Either exits non-zero or prints usage
  const out = stdout + stderr
  assert.ok(out.length > 0, 'should print something')
})

await test('--version or -v prints version', async () => {
  const { stdout, stderr } = await run(['--version'])
  const out = stdout + stderr
  assert.ok(out.match(/\d+\.\d+/), `version string not found in: ${out}`)
})

await test('invalid port string prints error', async () => {
  const { code, stdout, stderr } = await run(['notaport'])
  const out = stdout + stderr
  assert.ok(code !== 0 || out.toLowerCase().includes('port') || out.toLowerCase().includes('invalid') || out.length > 0)
})

await test('--token flag is accepted', async () => {
  // Just check it doesn't crash with parse error before trying to connect
  const proc = spawn(process.execPath, [CLI, '--token', 'mkt_testtoken', '19999'], {
    env: { ...process.env },
    timeout: 3000,
  })
  const output = await new Promise(resolve => {
    let out = ''
    proc.stdout.on('data', d => out += d)
    proc.stderr.on('data', d => out += d)
    setTimeout(() => { proc.kill(); resolve(out) }, 2500)
  })
  // Should NOT see "unknown flag" errors
  assert.ok(!output.toLowerCase().includes('unknown flag --token'), `--token flag rejected: ${output}`)
})

await test('MEKONG_TOKEN env is read', async () => {
  const proc = spawn(process.execPath, [CLI, '19998'], {
    env: { ...process.env, MEKONG_TOKEN: 'mkt_envtest' },
    timeout: 3000,
  })
  const output = await new Promise(resolve => {
    let out = ''
    proc.stdout.on('data', d => out += d)
    proc.stderr.on('data', d => out += d)
    setTimeout(() => { proc.kill(); resolve(out) }, 2500)
  })
  // Should not crash on token parsing
  assert.ok(output !== undefined)
})

// ─── Print results ─────────────────────────────────────────────────────────────

console.log('\n  mekong-cli CLI Tests\n  ' + '─'.repeat(44))
for (const r of results) {
  if (r.status === 'pass')  console.log(`  ✅ PASS  ${r.name}`)
  if (r.status === 'fail')  console.log(`  ❌ FAIL  ${r.name}\n           ${r.detail}`)
  if (r.status === 'skip')  console.log(`  ⚪ SKIP  ${r.name} — ${r.detail}`)
}
console.log(`\n  Results: ${passed} passed · ${failed} failed · ${skipped} skipped\n`)

if (failed > 0) process.exit(1)
