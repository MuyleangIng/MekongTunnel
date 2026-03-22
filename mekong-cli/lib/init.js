'use strict'

const fs = require('fs')
const path = require('path')
const os = require('os')
const readline = require('readline')

const BOLD   = '\x1b[1m'
const DIM    = '\x1b[2m'
const CYAN   = '\x1b[36m'
const GREEN  = '\x1b[32m'
const YELLOW = '\x1b[33m'
const RED    = '\x1b[31m'
const RESET  = '\x1b[0m'
const CHECK  = '\x1b[32m✓\x1b[0m'

// ---------------------------------------------------------------------------
// Framework tables
// ---------------------------------------------------------------------------
const FRAMEWORKS = [
  { deps: ['next'],                       name: 'Next.js',   cmd: 'next dev',            port: 3000 },
  { deps: ['nuxt', 'nuxt3', 'nuxt-edge'], name: 'Nuxt',      cmd: 'nuxt dev',            port: 3000 },
  { deps: ['vite'],                       name: 'Vite',       cmd: 'vite',                port: 5173 },
  { deps: ['react-scripts'],              name: 'CRA',        cmd: 'react-scripts start', port: 3000 },
  { deps: ['@angular/core'],              name: 'Angular',    cmd: 'ng serve',            port: 4200 },
  { deps: ['@sveltejs/kit'],              name: 'SvelteKit',  cmd: 'vite dev',            port: 5173 },
  { deps: ['svelte'],                     name: 'Svelte',     cmd: 'vite',                port: 5173 },
  { deps: ['astro'],                      name: 'Astro',      cmd: 'astro dev',           port: 4321 },
  { deps: ['gatsby'],                     name: 'Gatsby',     cmd: 'gatsby develop',      port: 8000 },
  { deps: ['remix', '@remix-run/react'],  name: 'Remix',      cmd: 'remix dev',           port: 3000 },
  { deps: ['@remix-run/dev'],             name: 'Remix',      cmd: 'remix dev',           port: 3000 },
  { deps: ['express'],                    name: 'Express',    cmd: 'node server.js',      port: 3000 },
  { deps: ['fastify'],                    name: 'Fastify',    cmd: 'node server.js',      port: 3000 },
  { deps: ['hono', '@hono/node-server'],  name: 'Hono',       cmd: 'node server.js',      port: 3000 },
]

const PY_FRAMEWORKS = [
  { pkg: 'fastapi',   name: 'FastAPI',   cmd: 'uvicorn main:app --reload', port: 8000 },
  { pkg: 'flask',     name: 'Flask',     cmd: 'flask run',                  port: 5000 },
  { pkg: 'django',    name: 'Django',    cmd: 'python manage.py runserver', port: 8000 },
  { pkg: 'starlette', name: 'Starlette', cmd: 'uvicorn main:app --reload',  port: 8000 },
  { pkg: 'tornado',   name: 'Tornado',   cmd: 'python main.py',             port: 8888 },
  { pkg: 'sanic',     name: 'Sanic',     cmd: 'sanic main.app',             port: 8000 },
  { pkg: 'litestar',  name: 'Litestar',  cmd: 'uvicorn main:app --reload',  port: 8000 },
]

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------

// Read all stdin lines upfront when stdin is not a TTY (piped/test mode),
// so readline auto-close on EOF does not swallow buffered answers.
function readAllStdinLines() {
  return new Promise((resolve) => {
    const lines = []
    const rl = readline.createInterface({ input: process.stdin, terminal: false })
    rl.on('line', (l) => lines.push(l))
    rl.on('close', () => resolve(lines))
  })
}

// Build an `ask(question)` function. In non-TTY (piped) mode, pre-reads all
// stdin lines into a queue so readline close-on-EOF doesn't eat answers.
// Returns { ask, close } where close() tears down the readline interface if any.
async function makeAsker() {
  if (!process.stdin.isTTY) {
    const lines = await readAllStdinLines()
    let idx = 0
    function ask(question) {
      const answer = idx < lines.length ? lines[idx++] : ''
      process.stdout.write(question + answer + '\n')
      return Promise.resolve(answer)
    }
    return { ask, close: () => {} }
  }

  // Interactive TTY
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  function ask(question) {
    return new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer))
    })
  }
  return { ask, close: () => rl.close() }
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------
function fileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Node.js detection
// ---------------------------------------------------------------------------
function detectNode(cwd) {
  const pkgPath = path.join(cwd, 'package.json')
  let pkg
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  } catch (err) {
    throw new Error(`Failed to parse package.json: ${err.message}`)
  }

  const allDeps = Object.assign({}, pkg.dependencies || {}, pkg.devDependencies || {})

  let detected = null
  for (const fw of FRAMEWORKS) {
    if (fw.deps.some((d) => allDeps[d] !== undefined)) {
      detected = { name: fw.name, cmd: fw.cmd, port: fw.port }
      break
    }
  }

  // Try to extract port from scripts.dev if it has --port N
  const devScript = (pkg.scripts && pkg.scripts.dev) || null
  if (devScript) {
    const portMatch = devScript.match(/--port[=\s]+(\d+)/)
    if (portMatch) {
      const extractedPort = parseInt(portMatch[1], 10)
      if (detected) {
        detected.port = extractedPort
      }
    }
    // If no framework detected but dev script exists, use it as the command
    if (!detected) {
      detected = { name: null, cmd: devScript, port: 3000 }
    }
  }

  return { detected, pkg, pkgPath }
}

// ---------------------------------------------------------------------------
// Python detection
// ---------------------------------------------------------------------------
function detectPython(cwd) {
  // Django via manage.py
  if (fileExists(path.join(cwd, 'manage.py'))) {
    return { name: 'Django', cmd: 'python manage.py runserver', port: 8000 }
  }

  const packages = new Set()

  // requirements.txt
  const reqPath = path.join(cwd, 'requirements.txt')
  if (fileExists(reqPath)) {
    const lines = fs.readFileSync(reqPath, 'utf8').split('\n')
    for (const line of lines) {
      const clean = line.trim().split(/[>=<![\s]/)[0].toLowerCase()
      if (clean) packages.add(clean)
    }
  }

  // pyproject.toml — scan [project] dependencies section
  const pyprojectPath = path.join(cwd, 'pyproject.toml')
  if (fileExists(pyprojectPath)) {
    const content = fs.readFileSync(pyprojectPath, 'utf8')
    const lines = content.split('\n')
    let inDeps = false
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed === '[project]') { inDeps = false }
      if (inDeps) {
        if (trimmed.startsWith('[') && trimmed !== '[project.dependencies]') { inDeps = false; continue }
        const clean = trimmed.replace(/^["']/, '').split(/[>=<![\s"']/)[0].toLowerCase()
        if (clean && !clean.startsWith('#')) packages.add(clean)
      }
      if (trimmed === 'dependencies' || trimmed === '[project.dependencies]' ||
          (trimmed.startsWith('dependencies') && trimmed.includes('='))) {
        inDeps = true
      }
    }
  }

  for (const fw of PY_FRAMEWORKS) {
    if (packages.has(fw.pkg)) {
      return { name: fw.name, cmd: fw.cmd, port: fw.port }
    }
  }

  return null
}

// ---------------------------------------------------------------------------
// Inject Node.js (package.json scripts)
// ---------------------------------------------------------------------------
async function injectNode(pkgPath, pkg, cmd, port, ask) {
  if (pkg.scripts && pkg.scripts['dev:tunnel']) {
    const answer = await ask(`${YELLOW}dev:tunnel already exists. Overwrite? (Y/n):${RESET} `)
    if (answer.trim().toLowerCase() === 'n') {
      process.stdout.write(`Skipped. No changes made.\n`)
      return false
    }
  }

  if (!pkg.scripts) pkg.scripts = {}
  pkg.scripts['dev:tunnel'] = `mekong-cli --with "${cmd}" --port ${port}`
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8')
  return true
}

// ---------------------------------------------------------------------------
// Inject Python (Makefile)
// ---------------------------------------------------------------------------
function injectPython(cwd, cmd, port) {
  const makefilePath = path.join(cwd, 'Makefile')
  const target = `dev-tunnel:\n\tmekong ${cmd} --port ${port}\n`

  if (fileExists(makefilePath)) {
    const existing = fs.readFileSync(makefilePath, 'utf8')
    fs.writeFileSync(makefilePath, existing.trimEnd() + '\n\n' + target, 'utf8')
  } else {
    fs.writeFileSync(makefilePath, target, 'utf8')
  }

  process.stdout.write(`Also run directly: ${CYAN}mekong ${cmd} --port ${port}${RESET}\n`)
}

// ---------------------------------------------------------------------------
// Prompt for manual command + port
// ---------------------------------------------------------------------------
async function promptManual(ask) {
  const cmd     = await ask(`Enter dev server command: `)
  const portStr = await ask(`Enter local port: `)
  const port    = parseInt(portStr.trim(), 10)
  if (isNaN(port)) throw new Error(`Invalid port: ${portStr.trim()}`)
  return { cmd: cmd.trim(), port }
}

// ---------------------------------------------------------------------------
// Configure Node.js ecosystem
// ---------------------------------------------------------------------------
async function configureNode(cwd, ask) {
  let { detected, pkg, pkgPath } = detectNode(cwd)
  let cmd, port, frameworkName

  if (detected) {
    frameworkName = detected.name || 'custom'
    cmd  = detected.cmd
    port = detected.port

    const label = detected.name ? detected.name : 'project'
    process.stdout.write(`\nDetected: ${BOLD}${label}${RESET} on port ${CYAN}${port}${RESET}\n`)
    process.stdout.write(`Command:  ${DIM}${cmd}${RESET}\n\n`)
    process.stdout.write(`Will add to package.json:\n`)
    process.stdout.write(`  ${CYAN}"dev:tunnel": "mekong-cli --with \\"${cmd}\\" --port ${port}"${RESET}\n\n`)

    const answer = await ask(`Confirm? (Y/n): `)
    if (answer.trim().toLowerCase() === 'n') {
      const manual = await promptManual(ask)
      cmd  = manual.cmd
      port = manual.port
      frameworkName = 'custom'

      process.stdout.write(`\nWill add to package.json:\n`)
      process.stdout.write(`  ${CYAN}"dev:tunnel": "mekong-cli --with \\"${cmd}\\" --port ${port}"${RESET}\n\n`)
      const confirm2 = await ask(`Confirm? (Y/n): `)
      if (confirm2.trim().toLowerCase() === 'n') {
        process.stdout.write(`Skipped. No changes made.\n`)
        return
      }
    }
  } else {
    process.stdout.write(`\n${YELLOW}No known Node.js framework detected.${RESET}\n`)
    const manual = await promptManual(ask)
    cmd  = manual.cmd
    port = manual.port
    frameworkName = 'custom'

    process.stdout.write(`\nWill add to package.json:\n`)
    process.stdout.write(`  ${CYAN}"dev:tunnel": "mekong-cli --with \\"${cmd}\\" --port ${port}"${RESET}\n\n`)
    const confirm2 = await ask(`Confirm? (Y/n): `)
    if (confirm2.trim().toLowerCase() === 'n') {
      process.stdout.write(`Skipped. No changes made.\n`)
      return
    }
  }

  const wrote = await injectNode(pkgPath, pkg, cmd, port, ask)
  if (!wrote) return

  const label = detected && detected.name ? detected.name : frameworkName
  process.stdout.write(`\n${CHECK} Done! mekong-cli is set up for ${BOLD}${label}${RESET}\n\n`)
  process.stdout.write(`Run your tunnel:\n`)
  process.stdout.write(`  ${CYAN}npm run dev:tunnel${RESET}\n\n`)
  process.stdout.write(`What it does:\n`)
  process.stdout.write(`  1. Starts: ${DIM}${cmd}${RESET} (port ${port})\n`)
  process.stdout.write(`  2. Waits for port ${port} to open\n`)
  process.stdout.write(`  3. Opens a Mekong tunnel\n`)
  process.stdout.write(`  4. Prints your public URL\n\n`)
  process.stdout.write(`Make sure mekong binary is installed:\n`)
  process.stdout.write(`  ${CYAN}https://github.com/MuyleangIng/MekongTunnel/releases/latest${RESET}\n`)
}

// ---------------------------------------------------------------------------
// Configure Python ecosystem
// ---------------------------------------------------------------------------
async function configurePython(cwd, ask) {
  let detected = detectPython(cwd)
  let cmd, port, frameworkName

  if (detected) {
    frameworkName = detected.name
    cmd  = detected.cmd
    port = detected.port

    process.stdout.write(`\nDetected: ${BOLD}${detected.name}${RESET} on port ${CYAN}${port}${RESET}\n`)
    process.stdout.write(`Command:  ${DIM}${cmd}${RESET}\n\n`)
    process.stdout.write(`Will add to Makefile:\n`)
    process.stdout.write(`  ${CYAN}dev-tunnel:${RESET}\n`)
    process.stdout.write(`  ${CYAN}    mekong ${cmd} --port ${port}${RESET}\n\n`)

    const answer = await ask(`Confirm? (Y/n): `)
    if (answer.trim().toLowerCase() === 'n') {
      const manual = await promptManual(ask)
      cmd  = manual.cmd
      port = manual.port
      frameworkName = 'custom'

      process.stdout.write(`\nWill add to Makefile:\n`)
      process.stdout.write(`  ${CYAN}dev-tunnel:${RESET}\n`)
      process.stdout.write(`  ${CYAN}    mekong ${cmd} --port ${port}${RESET}\n\n`)
      const confirm2 = await ask(`Confirm? (Y/n): `)
      if (confirm2.trim().toLowerCase() === 'n') {
        process.stdout.write(`Skipped. No changes made.\n`)
        return
      }
    }
  } else {
    process.stdout.write(`\n${YELLOW}No known Python framework detected.${RESET}\n`)
    const manual = await promptManual(ask)
    cmd  = manual.cmd
    port = manual.port
    frameworkName = 'custom'

    process.stdout.write(`\nWill add to Makefile:\n`)
    process.stdout.write(`  ${CYAN}dev-tunnel:${RESET}\n`)
    process.stdout.write(`  ${CYAN}    mekong ${cmd} --port ${port}${RESET}\n\n`)
    const confirm2 = await ask(`Confirm? (Y/n): `)
    if (confirm2.trim().toLowerCase() === 'n') {
      process.stdout.write(`Skipped. No changes made.\n`)
      return
    }
  }

  injectPython(cwd, cmd, port)

  process.stdout.write(`\n${CHECK} Done! mekong-tunnel is set up for ${BOLD}${frameworkName}${RESET}\n\n`)
  process.stdout.write(`Run your tunnel:\n`)
  process.stdout.write(`  ${CYAN}make dev-tunnel${RESET}\n`)
  process.stdout.write(`  (or) ${CYAN}mekong ${cmd} --port ${port}${RESET}\n\n`)
  process.stdout.write(`Make sure mekong binary is installed:\n`)
  process.stdout.write(`  ${CYAN}https://github.com/MuyleangIng/MekongTunnel/releases/latest${RESET}\n`)
  process.stdout.write(`  ${CYAN}pip install mekong-tunnel${RESET}\n`)
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------
async function runInit() {
  const cwd = process.cwd()

  const hasPkg     = fileExists(path.join(cwd, 'package.json'))
  const hasPyProj  = fileExists(path.join(cwd, 'pyproject.toml'))
  const hasReqs    = fileExists(path.join(cwd, 'requirements.txt'))
  const hasManage  = fileExists(path.join(cwd, 'manage.py'))
  const hasPipfile = fileExists(path.join(cwd, 'Pipfile'))

  const isNode   = hasPkg
  const isPython = hasPyProj || hasReqs || hasManage || hasPipfile

  if (!isNode && !isPython) {
    process.stderr.write(`${RED}No supported project found in current directory.${RESET}\n`)
    process.exit(1)
  }

  const { ask, close } = await makeAsker()

  try {
    if (isNode && isPython) {
      process.stdout.write(`\nBoth ${BOLD}Node.js${RESET} and ${BOLD}Python${RESET} projects detected.\n`)
      const answer = await ask(`Configure which? (Node.js / Python / Both) [Node.js]: `)
      const choice = answer.trim().toLowerCase()

      if (choice === 'python') {
        await configurePython(cwd, ask)
      } else if (choice === 'both') {
        await configureNode(cwd, ask)
        await configurePython(cwd, ask)
      } else {
        await configureNode(cwd, ask)
      }
    } else if (isNode) {
      await configureNode(cwd, ask)
    } else {
      await configurePython(cwd, ask)
    }
  } finally {
    close()
  }
}

module.exports = { runInit }
