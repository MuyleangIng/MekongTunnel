'use strict';

const net = require('net');

/**
 * Poll a TCP port every 500ms until it accepts a connection.
 * Rejects after 30 seconds.
 *
 * @param {number} port
 * @returns {Promise<void>}
 */
function waitForPort(port) {
  const INTERVAL_MS = 500;
  const TIMEOUT_MS = 30_000;

  return new Promise((resolve, reject) => {
    const started = Date.now();

    function attempt() {
      const elapsed = Date.now() - started;
      if (elapsed >= TIMEOUT_MS) {
        return reject(
          new Error(`Timed out waiting for port ${port} after ${TIMEOUT_MS / 1000}s`)
        );
      }

      const sock = new net.Socket();
      let settled = false;

      function cleanup(err) {
        if (settled) return;
        settled = true;
        sock.destroy();
        if (err) {
          setTimeout(attempt, INTERVAL_MS);
        } else {
          resolve();
        }
      }

      sock.setTimeout(INTERVAL_MS);
      sock.once('connect', () => cleanup(null));
      sock.once('error', (err) => cleanup(err));
      sock.once('timeout', () => cleanup(new Error('timeout')));
      sock.connect(port, '127.0.0.1');
    }

    attempt();
  });
}

/**
 * Single immediate check — resolves true if port is open right now, false otherwise.
 * @param {number} port
 * @returns {Promise<boolean>}
 */
function checkPortOpen(port) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    function finish(open) {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open);
    }
    sock.setTimeout(1000);
    sock.once('connect', () => finish(true));
    sock.once('error',   () => finish(false));
    sock.once('timeout', () => finish(false));
    sock.connect(port, '127.0.0.1');
  });
}

module.exports = { waitForPort, checkPortOpen };
