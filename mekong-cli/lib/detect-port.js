'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Auto-detect the local dev server port from package.json in cwd.
 * Returns a number or null if not detected.
 */
function detectPort() {
  const pkgPath = path.join(process.cwd(), 'package.json');

  let pkg;
  try {
    const raw = fs.readFileSync(pkgPath, 'utf8');
    pkg = JSON.parse(raw);
  } catch (_) {
    return null;
  }

  // Check scripts for explicit --port N
  const scripts = pkg.scripts || {};
  for (const key of ['dev', 'start']) {
    const script = scripts[key];
    if (typeof script === 'string') {
      const m = script.match(/--port[=\s]+(\d+)/);
      if (m) return parseInt(m[1], 10);
      // also handle -p N
      const m2 = script.match(/-p[=\s]+(\d+)/);
      if (m2) return parseInt(m2[1], 10);
    }
  }

  // Check dependencies / devDependencies for known frameworks
  const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies);

  const frameworkPort = [
    [['next', 'next.js'], 3000],
    [['nuxt', 'nuxt3', 'nuxt-edge'], 3000],
    [['vite'], 5173],
    [['react-scripts'], 3000],
    [['@angular/core'], 4200],
    [['svelte', '@sveltejs/kit', '@sveltejs/vite-plugin-svelte'], 5173],
    [['gatsby'], 8000],
    [['remix', '@remix-run/node', '@remix-run/react', '@remix-run/serve'], 3000],
    [['astro'], 4321],
    [['express', 'fastify', 'koa', '@hapi/hapi', 'hapi'], 3000],
  ];

  for (const [keys, port] of frameworkPort) {
    for (const key of keys) {
      if (key in deps) return port;
    }
  }

  return null;
}

module.exports = { detectPort };
