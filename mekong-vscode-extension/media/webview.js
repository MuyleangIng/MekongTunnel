(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  const send = (command, extra) => vscode.postMessage(Object.assign({ command }, extra || {}));
  const show = (id, on) => { const el = $(id); if (el) el.hidden = !on; };
  const stripUrl = (url) => (url || '').replace(/^https?:\/\//, '');

  const saved = vscode.getState() || {};
  let state = {
    running: false, url: null, tunnelPort: null,
    liveRunning: false, livePort: null, liveTunnelActive: false, liveIsMd: false,
    mekongInstalled: true, loggedIn: false, userEmail: '', userPlan: '',
    skipWarning: false,
  };
  let tab = saved.tab || 'tunnel';
  let signingIn = false;
  let pending = null;          // { port, expire } waiting for "start anyway"
  let installCmd = '';
  let prev = {};               // last rendered values, for activity messages
  let logCount = 0;

  // ── Small helpers ──────────────────────────────────────
  function setLabel(btn, text) {
    const label = btn && btn.querySelector('.btn-label');
    (label || btn).textContent = text;
  }

  // Copy buttons flash a check mark.
  function flashCopied(id) {
    const btn = $(id);
    const use = btn && btn.querySelector('use');
    if (!use) return;
    use.setAttribute('href', '#i-check');
    btn.classList.add('done');
    setTimeout(() => { use.setAttribute('href', '#i-copy'); btn.classList.remove('done'); }, 1400);
  }

  // "epic-bear-1234.proxy.mekongtunnel.dev" → bold name + muted domain
  function setUrl(el, url) {
    const host = stripUrl(url).replace(/\/$/, '');
    const dot = host.indexOf('.');
    el.textContent = '';
    if (dot < 0 || /^localhost|^\d/.test(host)) { el.textContent = host; }
    else {
      const b = document.createElement('b'); b.textContent = host.slice(0, dot);
      const rest = document.createElement('span'); rest.className = 'host'; rest.textContent = host.slice(dot);
      el.append(b, rest);
    }
    el.title = url;
  }

  function initials(email) {
    const name = (email || '').split('@')[0].replace(/[^a-zA-Z0-9]+/g, ' ').trim();
    if (!name) return 'MK';
    const parts = name.split(' ');
    return ((parts[0][0] || '') + (parts.length > 1 ? parts[1][0] : (parts[0][1] || ''))).toUpperCase();
  }

  function addLog(msg, type) {
    const entries = $('log-entries');
    const empty = $('log-empty');
    if (empty) empty.remove();
    const d = new Date();
    const ts = [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
    const row = document.createElement('div');
    row.className = 'alog-row ' + (type || 'info');
    const tsEl = document.createElement('span'); tsEl.className = 'alog-ts'; tsEl.textContent = ts;
    const msgEl = document.createElement('span'); msgEl.className = 'alog-msg'; msgEl.textContent = msg;
    row.append(tsEl, msgEl);
    entries.appendChild(row);
    while (entries.children.length > 40) entries.removeChild(entries.firstChild);
    entries.scrollTop = entries.scrollHeight;
    logCount++;
    $('log-count').textContent = String(logCount);
  }

  function setHint(text, kind) {
    const hint = $('framework-hint');
    hint.textContent = text || '';
    hint.className = 'note' + (kind ? ' ' + kind : '');
  }

  function setTab(next) {
    tab = next;
    vscode.setState(Object.assign({}, vscode.getState(), { tab }));
    $('tab-tunnel').classList.toggle('active', tab === 'tunnel');
    $('tab-live').classList.toggle('active', tab === 'live');
    show('tunnel-screen', tab === 'tunnel');
    show('live-screen', tab === 'live');
  }

  // ── Render ─────────────────────────────────────────────
  function renderAuth() {
    const loginBtn = $('acct-login-btn');
    const plan = state.userPlan;
    show('acct-avatar', state.loggedIn);
    show('acct-logout-btn', state.loggedIn);
    show('acct-login-btn', !state.loggedIn);
    show('acct-plan', state.loggedIn && !!plan);
    $('acct-plan').textContent = plan;
    $('acct-avatar').textContent = initials(state.userEmail);
    $('acct-avatar').title = state.userEmail;
    loginBtn.disabled = signingIn;
    setLabel(loginBtn, signingIn ? 'Waiting…' : 'Log in');
    $('acct-sub').textContent = state.loggedIn
      ? (state.userEmail || 'Signed in')
      : (signingIn ? 'Finish signing in in your browser' : 'Log in to use your reserved subdomain');
  }

  function isLiveTunnel() {
    return !!(state.running && state.livePort && state.tunnelPort === state.livePort);
  }

  function renderTunnel() {
    const running = state.running;
    const url = state.url;
    const startBtn = $('start-btn');
    const forLive = isLiveTunnel();

    if (running && !prev.running) addLog('Connecting tunnel…', 'warn');
    if (!running && prev.running) addLog('Tunnel stopped', 'err');
    if (url && url !== prev.url) addLog('Public URL → ' + stripUrl(url), 'ok');

    show('tunnel-setup', !running);
    show('tunnel-live', running);
    show('tab-tunnel-dot', running && !!url);
    $('skip-warning').checked = !!state.skipWarning;

    startBtn.disabled = !state.mekongInstalled;
    setLabel(startBtn, state.mekongInstalled ? 'Start tunnel' : 'Install the mekong CLI first');

    if (!running) return;
    $('tunnel-port').textContent = state.tunnelPort ? 'localhost:' + state.tunnelPort : '';
    $('tunnel-state').textContent = url ? (forLive ? 'Sharing Live Server' : 'Live') : 'Connecting…';
    $('tunnel-state-icon').innerHTML = url ? '<span class="dot"></span>' : '<span class="spinner"></span>';
    $('tunnel-live').classList.toggle('ok', !!url);
    $('tunnel-urlrow').classList.toggle('pending', !url);
    if (url) setUrl($('url-text'), url);
    else { $('url-text').textContent = 'Waiting for your public URL…'; $('url-text').title = ''; }
    $('copy-btn').disabled = !url;
    $('open-btn').disabled = !url;
    $('tunnel-skip-note').textContent = state.skipWarning ? 'Browser warning skipped' : '';
  }

  function renderLive() {
    const live = !!(state.liveRunning && state.livePort);
    const port = state.livePort;
    const shared = !!(live && state.liveTunnelActive && state.url);
    const sharing = live && isLiveTunnel() && !state.url;
    const otherTunnel = state.running && !isLiveTunnel();

    if (live && !prev.live) addLog('Live Server started on :' + port, 'ok');
    if (!live && prev.live) addLog('Live Server stopped', 'warn');

    show('ls-idle', !live);
    show('ls-running', live);
    show('tab-live-dot', live);
    if (!live) return;

    const localUrl = 'http://localhost:' + port;
    $('ls-label').textContent = 'Live Server · :' + port;
    $('ls-url-text').textContent = stripUrl(localUrl);
    $('ls-url-text').title = localUrl;
    $('ls-live-reload-sub').textContent = state.liveIsMd
      ? 'Markdown re-renders when you save.'
      : 'Pages reload when you save.';

    // Public link: button → "creating…" → URL row
    show('ls-tunnel-btn', !shared);
    // Choose before sharing; once shared, just say what was chosen.
    show('ls-skip-row', !shared);
    $('ls-skip-warning').checked = !!state.skipWarning;
    $('ls-skip-warning').disabled = sharing;
    $('ls-public-skip-note').textContent = shared
      ? (state.skipWarning ? 'Browser warning skipped' : 'Visitors see the Mekong warning page first')
      : '';
    show('ls-public', shared);
    show('ls-public-tag', shared);
    const tunnelBtn = $('ls-tunnel-btn');
    tunnelBtn.disabled = sharing || otherTunnel;
    setLabel(tunnelBtn, sharing ? 'Creating public link…'
      : (otherTunnel ? 'Stop the other tunnel to share' : 'Share publicly'));
    if (shared) {
      setUrl($('ls-public-url-text'), state.url);
    }
  }

  function render() {
    show('mekong-missing', !state.mekongInstalled);
    renderAuth();
    renderTunnel();
    renderLive();
    prev = { running: state.running, url: state.url, live: !!(state.liveRunning && state.livePort) };
  }

  function updateInstallUI(platform, arch) {
    if (platform === 'win32') {
      $('install-platform-badge').textContent = 'Windows';
      installCmd = 'irm https://mekongtunnel.dev/install.ps1 | iex';
    } else {
      const arm = arch === 'arm64';
      $('install-platform-badge').textContent = platform === 'darwin'
        ? (arm ? 'macOS arm64' : 'macOS Intel')
        : (arm ? 'Linux arm64' : 'Linux x64');
      installCmd = 'curl -fsSL https://mekongtunnel.dev/install.sh | sh';
    }
    $('install-cmd-text').textContent = installCmd;
  }

  // ── Actions ────────────────────────────────────────────
  function detectPort() {
    $('port-picker').innerHTML = '';
    setHint('Looking for running servers…');
    send('detect');
  }

  function flagPortError(text) {
    $('port-input').classList.add('error');
    setHint(text, 'err');
    setTimeout(() => { $('port-input').classList.remove('error'); setHint(''); }, 3000);
  }

  function startTunnel() {
    if (!state.mekongInstalled) { show('mekong-missing', true); return; }
    const raw = $('port-input').value.trim();
    const port = parseInt(raw, 10);
    if (!raw) return flagPortError('Enter a port, or press the search icon to detect one');
    if (isNaN(port) || port < 1 || port > 65535) return flagPortError('Port must be 1–65535');
    show('port-warning', false);
    state.running = true; state.url = null; state.tunnelPort = port;
    render();
    send('start', { port, expire: $('expire-select').value, skipWarning: $('skip-warning').checked });
  }

  function showPortChips(ports) {
    const picker = $('port-picker');
    picker.innerHTML = '';
    ports.forEach((p) => {
      const chip = document.createElement('button');
      chip.className = 'port-chip' + (p.altPort ? ' alt' : '');
      chip.textContent = ':' + p.port + (p.framework !== 'detected' ? ' ' + p.framework : '');
      chip.addEventListener('click', () => {
        $('port-input').value = String(p.port);
        setHint('Using :' + p.port, 'ok');
        picker.innerHTML = '';
      });
      picker.appendChild(chip);
    });
  }

  // ── Messages from the extension ────────────────────────
  window.addEventListener('message', (e) => {
    const msg = e.data || {};
    switch (msg.type) {
      case 'state':
        state = {
          running: !!msg.running,
          url: msg.url || null,
          tunnelPort: typeof msg.tunnelPort === 'number' ? msg.tunnelPort : null,
          liveRunning: !!msg.liveRunning,
          livePort: msg.livePort || null,
          liveTunnelActive: !!msg.liveTunnelActive,
          liveIsMd: !!msg.liveIsMd,
          mekongInstalled: msg.mekongInstalled !== false,
          loggedIn: !!msg.loggedIn,
          userEmail: msg.userEmail || '',
          userPlan: msg.userPlan || '',
          skipWarning: !!msg.skipWarning,
        };
        if (state.loggedIn && signingIn) { signingIn = false; addLog('Signed in as ' + state.userEmail, 'ok'); }
        if (msg.platform) updateInstallUI(msg.platform, msg.arch || 'x64');
        show('port-warning', false);
        render();
        break;
      case 'mekongMissing':
        state.mekongInstalled = false; state.running = false;
        render();
        break;
      case 'portWarning':
        pending = { port: msg.port, expire: msg.expire, skipWarning: msg.skipWarning };
        $('warn-port').textContent = ':' + msg.port;
        $('warn-cmd').textContent = msg.cmd || 'npm run dev';
        show('port-warning', true);
        state.running = false; state.url = null;
        render();
        break;
      case 'detected':
        if (msg.scanning) setHint('Looking for running servers…');
        break;
      case 'scanned': {
        const ports = msg.ports || [];
        if (ports.length === 1) {
          $('port-input').value = String(ports[0].port);
          setHint('Found a server on :' + ports[0].port, 'ok');
        } else if (ports.length > 1) {
          setHint('Several servers found — pick one:', 'ok');
          showPortChips(ports);
        } else if (msg.basePort) {
          $('port-input').value = String(msg.basePort);
          setHint((msg.framework && msg.framework !== 'unknown' ? msg.framework + ' project' : 'Project') + ' found, but it isn’t running yet');
        } else {
          setHint('No running server found — type the port');
        }
        break;
      }
      case 'copied': flashCopied('copy-btn'); break;
      case 'liveCopied': flashCopied('ls-copy-btn'); break;
      case 'livePublicCopied':
      case 'livePublicShared': flashCopied('ls-public-copy-btn'); break;
      case 'loginFailed':
        signingIn = false;
        addLog(msg.reason || 'Login failed', 'err');
        renderAuth();
        break;
    }
  });

  // ── Wire up ────────────────────────────────────────────
  const on = (id, fn) => $(id).addEventListener('click', fn);

  on('tab-tunnel', () => setTab('tunnel'));
  on('tab-live', () => setTab('live'));
  on('detect-btn', detectPort);
  on('start-btn', startTunnel);
  on('stop-btn', () => send('stop'));
  on('copy-btn', () => send('copy'));
  on('open-btn', () => send('open'));
  on('url-text', () => state.url && send('open'));
  $('port-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') startTunnel(); });
  // Same setting in both tabs; keep the two switches in sync.
  ['skip-warning', 'ls-skip-warning'].forEach((id) => {
    $(id).addEventListener('change', (e) => {
      state.skipWarning = e.target.checked;
      $('skip-warning').checked = $('ls-skip-warning').checked = state.skipWarning;
      send('setSkipWarning', { value: state.skipWarning });
    });
  });

  on('install-cmd-block', () => {
    if (!installCmd) return;
    send('copyText', { text: installCmd });
    $('install-cmd-block').classList.add('copied');
    setTimeout(() => $('install-cmd-block').classList.remove('copied'), 1500);
  });
  on('install-btn', () => send('install'));
  on('recheck-btn', () => send('checkMekong'));
  on('warn-anyway-btn', () => {
    if (!pending) return;
    show('port-warning', false);
    state.running = true; state.url = null; state.tunnelPort = pending.port;
    render();
    send('startForce', pending);
    pending = null;
  });
  on('warn-cancel-btn', () => { show('port-warning', false); pending = null; });

  on('ls-start-btn', () => send('startLive'));
  on('ls-start-preview-btn', () => send('startLivePreview'));
  on('ls-stop-btn', () => send('stopLive'));
  on('ls-open-btn', () => send('openLive'));
  on('ls-url-text', () => send('openLive'));
  on('ls-copy-btn', () => send('copyLive'));
  on('ls-preview-btn', () => send('openPreview'));
  on('ls-tunnel-btn', () => send('tunnelLive', { skipWarning: state.skipWarning }));
  on('ls-public-copy-btn', () => send('copyLivePublic'));
  on('ls-public-open-btn', () => send('openLivePublic'));
  on('ls-public-url-text', () => send('openLivePublic'));
  on('ls-stop-tunnel-btn', () => send('stopLiveTunnel'));

  on('acct-login-btn', () => {
    signingIn = true;
    renderAuth();
    addLog('Opening your browser to sign in…', 'warn');
    send('login');
  });
  on('acct-logout-btn', () => {
    state.loggedIn = false; state.userEmail = ''; state.userPlan = '';
    renderAuth();
    addLog('Logged out', 'warn');
    send('logout');
  });

  on('log-toggle', () => $('activity-log').classList.toggle('collapsed'));
  on('log-btn', () => send('openOutput'));
  on('link-dashboard', () => send('openLink', { target: 'dashboard' }));
  on('link-docs', () => send('openLink', { target: 'docs' }));

  $('brand-logo').addEventListener('error', function onErr() {
    this.removeEventListener('error', onErr);
    this.src = 'https://docs.mekongtunnel.dev/MekongNoBG.png';
  });

  setTab(tab);
  render();
  detectPort();
})();
