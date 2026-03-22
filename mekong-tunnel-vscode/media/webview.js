(function() {
  const vscode = acquireVsCodeApi();

  function $(id) { return document.getElementById(id); }
  function send(cmd, extra) { vscode.postMessage(Object.assign({ command: cmd }, extra || {})); }

  // ── State ──────────────────────────────────────────────────────────────────
  var state = { running: false, url: null, liveRunning: false, livePort: null, mekongInstalled: true,
                loggedIn: false, userEmail: '', userPlan: '' };
  var _pendingPort = null, _pendingExpire = null;
  var logCollapsed = false;
  var _signingIn = false;

  // ── Port picker (shown when multiple servers found) ────────────────────────
  function clearPortPicker() {
    var el = $('port-picker');
    if (el) el.remove();
  }

  function showPortPicker(ports) {
    clearPortPicker();
    var hint = $('framework-hint');
    var picker = document.createElement('div');
    picker.id = 'port-picker';
    picker.style.cssText = 'display:flex;flex-wrap:wrap;gap:5px;margin-top:6px;';
    ports.forEach(function(p) {
      var chip = document.createElement('button');
      chip.style.cssText = [
        'height:24px;padding:0 9px;border-radius:20px;font-size:10px;font-weight:600;',
        'cursor:pointer;font-family:inherit;border:1px solid;transition:opacity 0.12s;',
        p.altPort
          ? 'background:rgba(240,165,0,0.1);border-color:rgba(240,165,0,0.35);color:#f0a500;'
          : 'background:rgba(63,185,80,0.1);border-color:rgba(63,185,80,0.35);color:#3fb950;'
      ].join('');
      chip.textContent = ':' + p.port + (p.framework !== 'detected' ? ' ' + p.framework : '');
      chip.addEventListener('click', function() {
        $('port-input').value = p.port;
        $('framework-hint').textContent = '\u26A1 Selected :' + p.port;
        $('framework-hint').className   = 'hint ok';
        clearPortPicker();
      });
      picker.appendChild(chip);
    });
    hint.parentNode.insertBefore(picker, hint.nextSibling);
  }

  // ── Activity log ───────────────────────────────────────────────────────────
  function ts() {
    var d = new Date();
    return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2);
  }
  function addLog(msg, type) {
    var entries = $('log-entries');
    var empty   = $('log-empty');
    if (empty) empty.remove();
    var row = document.createElement('div');
    row.className = 'alog-row ' + (type || 'info');
    row.innerHTML = '<span class="alog-ts">'+ts()+'</span><span class="alog-msg">'+msg+'</span>';
    entries.appendChild(row);
    while (entries.children.length > 40) entries.removeChild(entries.firstChild);
    if (!logCollapsed) entries.scrollTop = entries.scrollHeight;
  }

  // ── Auth / Account render ──────────────────────────────────────────────────
  function renderAuth() {
    var card      = $('acct-card');
    var avatar    = $('acct-avatar');
    var nameEl    = $('acct-name');
    var subEl     = $('acct-sub');
    var planEl    = $('acct-plan');
    var loginBtn  = $('acct-login-btn');
    var logoutBtn = $('acct-logout-btn');

    if (_signingIn) {
      card.className       = 'acct-card signing-in';
      avatar.textContent   = '\u23F3';
      nameEl.textContent   = 'Waiting for browser login\u2026';
      nameEl.className     = 'acct-name';
      subEl.textContent    = 'Approve the login in your browser';
      planEl.style.display = 'none';
      loginBtn.style.display  = 'none';
      logoutBtn.style.display = 'none';
    } else if (state.loggedIn && state.userEmail) {
      card.className       = 'acct-card signed-in';
      avatar.textContent   = '\u2705';
      nameEl.textContent   = state.userEmail;
      nameEl.className     = 'acct-name signed-in';
      subEl.textContent    = 'Logged in \u2014 reserved subdomain active';
      if (state.userPlan) {
        planEl.textContent   = state.userPlan;
        planEl.style.display = '';
      } else {
        planEl.style.display = 'none';
      }
      loginBtn.style.display  = 'none';
      logoutBtn.style.display = '';
    } else {
      card.className       = 'acct-card';
      avatar.textContent   = '\uD83D\uDC64';
      nameEl.textContent   = 'Not logged in';
      nameEl.className     = 'acct-name';
      subEl.textContent    = 'Login for a reserved subdomain';
      planEl.style.display = 'none';
      loginBtn.style.display  = '';
      logoutBtn.style.display = 'none';
    }
  }

  // ── Platform-specific install UI ──────────────────────────────────────────
  var _installCmd = '';

  function updateInstallUI(platform, arch) {
    var VER  = 'v1.5.0';
    var BASE = 'https://github.com/MuyleangIng/MekongTunnel/releases/download/' + VER + '/';

    if (platform === 'win32') {
      $('install-platform-badge').textContent = 'Windows';
      $('install-unix').style.display    = 'none';
      $('install-windows').style.display = 'block';
      _installCmd = '';
    } else {
      var isDarwin = platform === 'darwin';
      var isArm    = arch === 'arm64';
      var binary   = isDarwin
        ? (isArm ? 'mekong-darwin-arm64' : 'mekong-darwin-amd64')
        : (isArm ? 'mekong-linux-arm64'  : 'mekong-linux-amd64');

      $('install-platform-badge').textContent = isDarwin
        ? (isArm ? 'macOS arm64' : 'macOS Intel')
        : (isArm ? 'Linux arm64' : 'Linux x64');

      // Build one chained command
      _installCmd = 'sudo curl -L ' + BASE + binary + ' -o /usr/local/bin/mekong'
        + ' && sudo chmod +x /usr/local/bin/mekong'
        + (isDarwin ? ' && sudo xattr -d com.apple.quarantine /usr/local/bin/mekong' : '');

      $('install-cmd-text').textContent  = _installCmd;
      $('install-unix').style.display    = 'block';
      $('install-windows').style.display = 'none';
    }
  }

  // Click-to-copy install command
  $('install-cmd-block').addEventListener('click', function() {
    if (!_installCmd) return;
    // Use VS Code clipboard API via postMessage
    send('copyText', { text: _installCmd });
    $('install-copy-icon').textContent  = '\u2713';
    $('install-copied-hint').style.display = 'block';
    setTimeout(function() {
      $('install-copy-icon').textContent     = '\u2398';
      $('install-copied-hint').style.display = 'none';
    }, 2000);
  });

  $('log-toggle').addEventListener('click', function() {
    logCollapsed = !logCollapsed;
    $('log-entries').style.display = logCollapsed ? 'none' : '';
    $('log-toggle-icon').textContent = logCollapsed ? '\u25B6' : '\u25BC';
  });

  // ── Tunnel render ──────────────────────────────────────────────────────────
  var _lastRunning = null, _lastUrl = null;
  function render() {
    var running = state.running;
    var url     = state.url;

    if (_lastRunning === false && running)       addLog('Tunnel connecting\u2026', 'warn');
    if (_lastRunning === true  && !running)      addLog('Tunnel stopped', 'err');
    if (url && url !== _lastUrl)                 addLog('Tunnel live \u2192 ' + url.replace(/^https?:\/\//,''), 'ok');
    _lastRunning = running; _lastUrl = url;

    var card  = $('status-card');
    var dot   = $('status-dot');
    var label = $('status-label');
    var sub   = $('status-sub');
    var badge = $('live-badge');

    if (running && !url) {
      card.className  = 'status-row st-starting';
      dot.className   = 'st-dot d-starting';
      label.textContent = 'Connecting\u2026';
      sub.textContent   = 'Waiting for tunnel URL';
      badge.style.display = 'none';
      $('connecting-box').style.display  = 'block';
      $('config-section').style.display  = 'none';
      $('expire-section').style.display  = 'none';
      $('start-section').style.display   = 'none';
      $('stop-section').style.display    = 'block';
      $('url-section').style.display     = 'none';
    } else if (running && url) {
      card.className  = 'status-row st-running';
      dot.className   = 'st-dot d-running';
      label.textContent = 'Tunnel Active';
      sub.textContent   = url.replace(/^https?:\/\//, '');
      badge.style.display = 'flex';
      $('connecting-box').style.display  = 'none';
      $('config-section').style.display  = 'none';
      $('expire-section').style.display  = 'none';
      $('start-section').style.display   = 'none';
      $('stop-section').style.display    = 'block';
      $('url-section').style.display     = 'block';
      $('url-text').textContent = url;
    } else {
      card.className  = 'status-row';
      dot.className   = 'st-dot';
      label.textContent = 'Ready';
      sub.textContent   = 'No active tunnel';
      badge.style.display = 'none';
      $('connecting-box').style.display  = 'none';
      $('config-section').style.display  = 'block';
      $('expire-section').style.display  = 'block';
      $('start-section').style.display   = 'block';
      $('stop-section').style.display    = 'none';
      $('url-section').style.display     = 'none';
    }
  }

  // ── Live Server render ─────────────────────────────────────────────────────
  var _lastLive = null;
  function renderLive() {
    var live = state.liveRunning;
    var port = state.livePort;
    var url  = port ? 'http://localhost:' + port : '';

    var card     = $('ls-status-card');
    var dot      = $('ls-dot');
    var label    = $('ls-label');
    var sub      = $('ls-sub');
    var offLabel = $('ls-off-label');
    var startSec = $('ls-start-section');
    var runSec   = $('ls-running-section');

    if (live && port) {
      card.className  = 'status-row st-running';
      card.style.opacity = '1';
      dot.className   = 'st-dot d-running';
      label.textContent = 'Live on :' + port;
      sub.textContent   = url;
      offLabel.style.display = 'none';
      startSec.style.display = 'none';
      runSec.style.display   = 'block';
      $('ls-url-text').textContent = url;
      if (_lastLive !== true) addLog('Live Server started on :' + port, 'ok');
    } else {
      card.className  = 'status-row';
      card.style.opacity = '0.5';
      dot.className   = 'st-dot';
      label.textContent = 'Not running';
      sub.textContent   = 'Start to serve HTML files with live reload';
      offLabel.style.display = '';
      startSec.style.display = 'block';
      runSec.style.display   = 'none';
      if (_lastLive === true) addLog('Live Server stopped', 'warn');
    }
    _lastLive = live && !!port;
  }

  // ── Actions ────────────────────────────────────────────────────────────────
  function detectPort() {
    send('detect');
    $('framework-hint').textContent = 'Detecting\u2026';
    $('framework-hint').className   = 'hint';
  }

  function startTunnel() {
    var val  = $('port-input').value.trim();
    var port = parseInt(val, 10);
    var hint = $('framework-hint');
    if (!val) {
      $('port-input').classList.add('error');
      hint.textContent = 'Enter a port or click Detect';
      hint.className   = 'hint err';
      setTimeout(function() { $('port-input').classList.remove('error'); hint.textContent=''; hint.className='hint'; }, 3000);
      return;
    }
    if (isNaN(port) || port < 1 || port > 65535) {
      $('port-input').classList.add('error');
      hint.textContent = 'Invalid port (1\u201365535)';
      hint.className   = 'hint err';
      setTimeout(function() { $('port-input').classList.remove('error'); hint.textContent=''; hint.className='hint'; }, 3000);
      return;
    }
    var expire = $('expire-select').value;
    $('port-warning').style.display   = 'none';
    $('mekong-missing').style.display = 'none';
    state.running = true; state.url = null; render();
    send('start', { port: port, expire: expire });
  }

  // ── Message handler ────────────────────────────────────────────────────────
  window.addEventListener('message', function(e) {
    var msg = e.data;
    if (msg.type === 'state') {
      state.running         = msg.running;
      state.url             = msg.url;
      state.liveRunning     = msg.liveRunning;
      state.livePort        = msg.livePort;
      state.mekongInstalled = msg.mekongInstalled !== false;
      state.loggedIn        = !!msg.loggedIn;
      state.userEmail       = msg.userEmail || '';
      state.userPlan        = msg.userPlan  || '';
      // If we were in signing-in state and now logged in, clear it
      if (state.loggedIn) _signingIn = false;
      // populate platform-specific install instructions
      if (msg.platform) updateInstallUI(msg.platform, msg.arch || 'x64');
      $('port-warning').style.display   = 'none';
      $('mekong-missing').style.display = state.mekongInstalled ? 'none' : 'block';
      render(); renderLive(); renderAuth();
    }

    if (msg.type === 'mekongMissing') {
      $('mekong-missing').style.display = 'block';
      $('port-warning').style.display   = 'none';
    }

    if (msg.type === 'portWarning') {
      _pendingPort   = msg.port;
      _pendingExpire = msg.expire;
      $('warn-port').textContent = ':' + msg.port;
      $('warn-cmd').textContent  = msg.cmd || 'npm run dev';
      $('port-warning').style.display   = 'block';
      $('mekong-missing').style.display = 'none';
      // reset optimistic state
      state.running = false; state.url = null; render();
    }
    if (msg.type === 'detected') {
      var hint = $('framework-hint');
      if (msg.scanning) {
        hint.textContent = 'Scanning for running servers\u2026';
        hint.className   = 'hint';
      } else if (msg.port) {
        $('port-input').value = msg.port;
        hint.textContent      = 'Detected: ' + (msg.framework || 'unknown');
        hint.className        = 'hint ok';
      } else {
        hint.textContent = 'Not detected \u2014 enter port manually';
        hint.className   = 'hint';
      }
      clearPortPicker();
    }

    if (msg.type === 'scanned') {
      var hint = $('framework-hint');
      var ports = msg.ports || [];
      clearPortPicker();

      if (ports.length === 0) {
        // Nothing listening — show static package.json result or blank
        if (msg.basePort) {
          $('port-input').value = msg.basePort;
          hint.textContent = (msg.framework && msg.framework !== 'unknown')
            ? 'Detected: ' + msg.framework + ' (not running yet)'
            : 'Not running \u2014 start your dev server';
          hint.className = 'hint';
        } else {
          hint.textContent = 'No server detected \u2014 enter port manually';
          hint.className   = 'hint';
        }
      } else if (ports.length === 1) {
        // Exactly one server found — auto-fill
        var p = ports[0];
        $('port-input').value = p.port;
        var label = p.framework !== 'detected' ? p.framework : 'server';
        hint.textContent = p.altPort
          ? '\u26A1 Running on :' + p.port + ' (' + label + ' used alt port)'
          : '\u26A1 Running on :' + p.port + ' (' + label + ')';
        hint.className = 'hint ok';
      } else {
        // Multiple servers found — show picker chips
        hint.textContent = 'Multiple servers found \u2014 pick one:';
        hint.className   = 'hint ok';
        showPortPicker(ports);
      }
    }
    if (msg.type === 'copied') {
      var btn = $('copy-btn');
      btn.textContent = 'Copied!';
      btn.classList.add('flashed');
      setTimeout(function() { btn.textContent='Copy URL'; btn.classList.remove('flashed'); }, 1500);
    }
    if (msg.type === 'liveCopied') {
      var lb = $('ls-copy-btn');
      if (lb) {
        lb.textContent = 'Copied!';
        lb.classList.add('flashed');
        setTimeout(function() { lb.textContent='Copy'; lb.classList.remove('flashed'); }, 1500);
      }
    }
  });

  // ── Wire buttons ───────────────────────────────────────────────────────────
  // Install / re-check mekong
  $('install-btn').addEventListener('click', function() { send('install'); });
  $('recheck-btn').addEventListener('click', function() {
    $('mekong-missing').style.display = 'none';
    send('checkMekong');
  });

  // Port warning actions
  $('warn-anyway-btn').addEventListener('click', function() {
    $('port-warning').style.display = 'none';
    state.running = true; state.url = null; render();
    send('startForce', { port: _pendingPort, expire: _pendingExpire });
  });
  $('warn-cancel-btn').addEventListener('click', function() {
    $('port-warning').style.display = 'none';
    _pendingPort = null; _pendingExpire = null;
  });

  $('detect-btn').addEventListener('click', detectPort);
  $('start-btn').addEventListener('click', startTunnel);
  $('stop-btn').addEventListener('click', function() { send('stop'); });
  $('copy-btn').addEventListener('click', function() { send('copy'); });
  $('open-btn').addEventListener('click', function() { send('open'); });
  $('log-btn').addEventListener('click',  function() { send('openOutput'); });

  $('ls-start-btn').addEventListener('click',       function() { send('startLive'); });
  $('ls-stop-btn').addEventListener('click',        function() { send('stopLive'); });
  $('ls-open-btn').addEventListener('click',        function() { send('openLive'); });
  $('ls-copy-btn').addEventListener('click',        function() { send('copyLive'); });
  $('ls-tunnel-btn').addEventListener('click',      function() { send('tunnelLive'); });
  $('ls-header-close-btn').addEventListener('click',function() { send('stopLive'); });

  // Account buttons
  $('acct-login-btn').addEventListener('click', function() {
    _signingIn = true;
    renderAuth();
    addLog('Opening browser login\u2026', 'warn');
    send('login');
  });
  $('acct-logout-btn').addEventListener('click', function() {
    state.loggedIn   = false;
    state.userEmail  = '';
    state.userPlan   = '';
    renderAuth();
    addLog('Logged out', 'warn');
    send('logout');
  });

  detectPort();
  renderLive();
  renderAuth();
})();
