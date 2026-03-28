'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Locate the mekong binary.
 * Returns an absolute path string or null if not found.
 */
function findMekong() {
  const isWindows = process.platform === 'win32';

  // 1. Try `which mekong` (or `where mekong` on Windows)
  try {
    const cmd = isWindows ? 'where mekong' : 'which mekong';
    const result = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim()
      .split('\n')[0]
      .trim();
    if (result && fs.existsSync(result)) return result;
  } catch (_) {
    // not on PATH
  }

  // 2. Common Unix paths — /usr/local/bin first (macOS default install location)
  if (!isWindows) {
    const unixPaths = [
      '/usr/local/bin/mekong',
      path.join(os.homedir(), '.local', 'bin', 'mekong'),
      path.join(os.homedir(), 'bin', 'mekong'),
      '/usr/bin/mekong',
      '/opt/homebrew/bin/mekong',
    ];
    for (const p of unixPaths) {
      if (fs.existsSync(p)) return p;
    }
  }

  // 3. Windows paths — %LOCALAPPDATA%\Programs\mekong first (default install dir)
  if (isWindows) {
    const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    const winPaths = [
      path.join(local, 'Programs', 'mekong', 'mekong.exe'),
      path.join(local, 'mekong.exe'),
      path.join(os.homedir(), '.local', 'bin', 'mekong.exe'),
      'C:\\Program Files\\mekong\\mekong.exe',
    ];
    for (const p of winPaths) {
      if (fs.existsSync(p)) return p;
    }

    // Also try without .exe
    const winPathsNoExt = [
      path.join(local, 'Programs', 'mekong', 'mekong'),
      path.join(os.homedir(), '.local', 'bin', 'mekong'),
    ];
    for (const p of winPathsNoExt) {
      if (fs.existsSync(p)) return p;
    }
  }

  return null;
}

module.exports = { findMekong };
