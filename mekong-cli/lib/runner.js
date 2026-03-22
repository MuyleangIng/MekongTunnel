'use strict';

const { spawn } = require('child_process');
const { waitForPort } = require('./wait-for-port');

const BOLD   = '\x1b[1m';
const DIM    = '\x1b[2m';
const CYAN   = '\x1b[36m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const RESET  = '\x1b[0m';

/**
 * Prefix and stream lines from a readable stream.
 * @param {import('stream').Readable} readable
 * @param {string} prefix
 * @param {(line: string) => void} [onLine]
 */
function streamLines(readable, prefix, onLine) {
  let buf = '';
  readable.on('data', (chunk) => {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      process.stdout.write(`${DIM}${prefix}${RESET} ${line}\n`);
      if (onLine) onLine(line);
    }
  });
  readable.on('end', () => {
    if (buf.length > 0) {
      process.stdout.write(`${DIM}${prefix}${RESET} ${buf}\n`);
      if (onLine) onLine(buf);
      buf = '';
    }
  });
}

/**
 * Print a banner with the public tunnel URL.
 * @param {string} url
 */
function printBanner(url) {
  const label = '  Public URL: ';
  const inner = label + url + '  ';
  const width = Math.max(inner.length + 2, 42);
  const top    = '╔' + '═'.repeat(width) + '╗';
  const bottom = '╚' + '═'.repeat(width) + '╝';
  const pad    = width - inner.length;
  const middle = '║' + inner + ' '.repeat(pad) + '║';

  process.stdout.write('\n');
  process.stdout.write(`${GREEN}${BOLD}${top}${RESET}\n`);
  process.stdout.write(`${GREEN}${BOLD}${middle}${RESET}\n`);
  process.stdout.write(`${GREEN}${BOLD}${bottom}${RESET}\n`);
  process.stdout.write('\n');
}

/**
 * Run a dev server command alongside a mekong tunnel.
 *
 * @param {string} serverCmd  - shell command to start the dev server
 * @param {number} port       - local port the server will listen on
 * @param {object} opts
 * @param {string}  opts.mekongBin  - path to mekong binary
 * @param {string}  [opts.expire]   - --expire value passed to mekong
 * @param {string}  [opts.token]    - API token for reserved subdomain
 * @param {boolean} [opts.daemon]   - pass -d to mekong
 * @param {boolean} [opts.noQr]     - pass --no-qr to mekong
 */
async function runWithServer(serverCmd, port, opts) {
  const { mekongBin, expire, token, daemon, noQr } = opts;

  process.stdout.write(
    `${CYAN}${BOLD}mekong-cli${RESET} Starting dev server: ${YELLOW}${serverCmd}${RESET}\n`
  );

  // 1. Spawn the dev server
  const server = spawn(serverCmd, [], {
    shell: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  streamLines(server.stdout, '[server]');
  streamLines(server.stderr, '[server]');

  let tunnelProc = null;

  function cleanup(exitCode) {
    if (tunnelProc && !tunnelProc.killed) {
      tunnelProc.kill('SIGTERM');
    }
    if (server && !server.killed) {
      server.kill('SIGTERM');
    }
    process.exit(exitCode == null ? 0 : exitCode);
  }

  process.on('SIGINT', () => cleanup(0));
  process.on('SIGTERM', () => cleanup(0));

  server.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      process.stderr.write(
        `${RED}[server] exited with code ${code}${RESET}\n`
      );
      cleanup(code);
    }
  });

  // 2. Wait for the port to be ready
  process.stdout.write(
    `${DIM}mekong-cli${RESET} Waiting for port ${CYAN}${port}${RESET} to be ready...\n`
  );

  try {
    await waitForPort(port);
  } catch (err) {
    process.stderr.write(`${RED}mekong-cli: ${err.message}${RESET}\n`);
    cleanup(1);
    return;
  }

  process.stdout.write(
    `${GREEN}mekong-cli${RESET} Port ${CYAN}${port}${RESET} is ready. Starting tunnel...\n`
  );

  // 3. Build mekong args
  const mekongArgs = [String(port)];
  if (expire) mekongArgs.push('--expire', expire);
  if (token)  mekongArgs.push('--token', token);
  if (daemon) mekongArgs.push('-d');
  if (noQr)   mekongArgs.push('--no-qr');

  // 4. Spawn mekong
  tunnelProc = spawn(mekongBin, mekongArgs, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const urlRegex = /https?:\/\/[^\s]+/;
  let bannerShown = false;

  function handleTunnelLine(line) {
    if (!bannerShown) {
      const m = line.match(urlRegex);
      if (m) {
        bannerShown = true;
        printBanner(m[0]);
      }
    }
  }

  streamLines(tunnelProc.stdout, '[tunnel]', handleTunnelLine);
  streamLines(tunnelProc.stderr, '[tunnel]', handleTunnelLine);

  tunnelProc.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      process.stderr.write(
        `${YELLOW}[tunnel] exited with code ${code}${RESET}\n`
      );
    }
  });
}

module.exports = { runWithServer };
