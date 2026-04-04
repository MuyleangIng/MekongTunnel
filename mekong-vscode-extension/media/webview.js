(function() {
  const vscode = acquireVsCodeApi();

  function $(id) { return document.getElementById(id); }
  function send(cmd, extra) { vscode.postMessage(Object.assign({ command: cmd }, extra || {})); }

  var state = {
    running: false,
    url: null,
    tunnelPort: null,
    liveRunning: false,
    livePort: null,
    liveTunnelActive: false,
    mekongInstalled: true,
    loggedIn: false,
    userEmail: '',
    userPlan: '',
  };

  var activeTab = 'tunnel';
  var _pendingPort = null;
  var _pendingExpire = null;
  var _installCmd = '';
  var _signingIn = false;
  var _lastRunning = null;
  var _lastUrl = null;
  var _lastLive = null;
  var _lastLiveTunnel = null;
  var logCollapsed = false;

  function stripUrl(url) {
    return (url || '').replace(/^https?:\/\//, '');
  }

  function flashButton(id, nextText, resetText) {
    var btn = $(id);
    if (!btn) return;
    btn.textContent = nextText;
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = resetText;
      btn.classList.remove('copied');
    }, 1500);
  }

  function wireLogoFallback() {
    var brandLogo = $('brand-logo');
    if (!brandLogo) return;
    brandLogo.addEventListener('error', function() {
      if (brandLogo.dataset.fallbackApplied) return;
      brandLogo.dataset.fallbackApplied = 'true';
      brandLogo.src = 'https://docs.mekongtunnel.dev/MekongNoBG.png';
    });
  }

  function setTab(tab) {
    activeTab = tab;
    $('tab-tunnel').classList.toggle('active', tab === 'tunnel');
    $('tab-live').classList.toggle('active', tab === 'live');
    $('tunnel-screen').style.display = tab === 'tunnel' ? 'block' : 'none';
    $('live-screen').style.display = tab === 'live' ? 'block' : 'none';
  }

  function clearPortPicker() {
    var picker = $('port-picker');
    if (picker) picker.remove();
  }

  function showPortPicker(ports) {
    clearPortPicker();
    var hint = $('framework-hint');
    var picker = document.createElement('div');
    picker.id = 'port-picker';
    picker.className = 'chip-row';

    ports.forEach(function(p) {
      var chip = document.createElement('button');
      chip.className = 'port-chip' + (p.altPort ? ' alt' : '');
      chip.textContent = ':' + p.port + (p.framework !== 'detected' ? ' ' + p.framework : '');
      chip.addEventListener('click', function() {
        $('port-input').value = String(p.port);
        hint.textContent = 'Selected :' + p.port;
        hint.className = 'note ok';
        clearPortPicker();
      });
      picker.appendChild(chip);
    });

    hint.parentNode.insertBefore(picker, hint.nextSibling);
  }

  function ts() {
    var d = new Date();
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2);
  }

  function addLog(msg, type) {
    var entries = $('log-entries');
    var empty = $('log-empty');
    if (empty) empty.remove();

    var row = document.createElement('div');
    row.className = 'alog-row ' + (type || 'info');

    var tsEl = document.createElement('span');
    tsEl.className = 'alog-ts';
    tsEl.textContent = ts();

    var msgEl = document.createElement('span');
    msgEl.className = 'alog-msg';
    msgEl.textContent = msg;

    row.appendChild(tsEl);
    row.appendChild(msgEl);
    entries.appendChild(row);

    while (entries.children.length > 40) {
      entries.removeChild(entries.firstChild);
    }

    if (!logCollapsed) {
      entries.scrollTop = entries.scrollHeight;
    }
  }

  function updateInstallUI(platform, arch) {
    if (platform === 'win32') {
      $('install-platform-badge').textContent = 'Windows';
      _installCmd = 'irm https://mekongtunnel.dev/install.ps1 | iex';
      $('install-cmd-text').textContent = _installCmd;
      $('install-unix').style.display = 'block';
      $('install-windows').style.display = 'none';
      return;
    }

    var isDarwin = platform === 'darwin';
    var isArm = arch === 'arm64';

    $('install-platform-badge').textContent = isDarwin
      ? (isArm ? 'macOS arm64' : 'macOS Intel')
      : (isArm ? 'Linux arm64' : 'Linux x64');

    _installCmd = 'curl -fsSL https://mekongtunnel.dev/install.sh | sh';

    $('install-cmd-text').textContent = _installCmd;
    $('install-unix').style.display = 'block';
    $('install-windows').style.display = 'none';
  }

  function updateTunnelNote() {
    $('tunnel-note-text').textContent = state.loggedIn
      ? 'Your saved token can request a reserved subdomain when the tunnel starts.'
      : 'A public URL is generated when the tunnel starts. Log in to use a reserved subdomain.';
  }

  function renderAuth() {
    var card = $('acct-card');
    var avatar = $('acct-avatar');
    var nameEl = $('acct-name');
    var subEl = $('acct-sub');
    var planEl = $('acct-plan');
    var loginBtn = $('acct-login-btn');
    var logoutBtn = $('acct-logout-btn');

    if (_signingIn) {
      card.className = 'account-card signing-in';
      avatar.textContent = '...';
      nameEl.textContent = 'Waiting for login';
      subEl.textContent = 'Complete `mekong login` in the terminal window';
      planEl.style.display = 'none';
      loginBtn.style.display = '';
      loginBtn.disabled = true;
      loginBtn.textContent = 'Waiting...';
      logoutBtn.style.display = 'none';
    } else if (state.loggedIn && state.userEmail) {
      card.className = 'account-card signed-in';
      avatar.textContent = 'OK';
      nameEl.textContent = state.userEmail;
      subEl.textContent = state.userPlan
        ? state.userPlan + ' plan active'
        : 'Reserved subdomain active';
      if (state.userPlan) {
        planEl.textContent = state.userPlan;
        planEl.style.display = 'inline-flex';
      } else {
        planEl.style.display = 'none';
      }
      loginBtn.style.display = 'none';
      loginBtn.disabled = false;
      loginBtn.textContent = 'Log in';
      logoutBtn.style.display = '';
    } else {
      card.className = 'account-card';
      avatar.textContent = 'MK';
      nameEl.textContent = 'Not logged in';
      subEl.textContent = 'Login for a reserved subdomain';
      planEl.style.display = 'none';
      loginBtn.style.display = '';
      loginBtn.disabled = false;
      loginBtn.textContent = 'Log in';
      logoutBtn.style.display = 'none';
    }

    updateTunnelNote();
  }

  function renderMainStatus() {
    var dot = $('main-dot');
    var label = $('main-label');
    var sub = $('main-sub');
    var liveTunnelConnecting = state.liveRunning && state.livePort && state.running && state.tunnelPort === state.livePort && !state.url;

    dot.className = 'dot';

    if (liveTunnelConnecting) {
      dot.classList.add('amber');
      label.textContent = 'Connecting live tunnel';
      sub.textContent = 'Publishing localhost:' + state.livePort;
      return;
    }

    if (state.liveTunnelActive && state.url && state.livePort) {
      dot.classList.add('green');
      label.textContent = 'Live Server + Tunnel';
      sub.textContent = 'localhost:' + state.livePort + ' -> ' + stripUrl(state.url);
      return;
    }

    if (state.running && !state.url) {
      dot.classList.add('amber');
      label.textContent = 'Connecting tunnel';
      sub.textContent = 'Waiting for public URL';
      return;
    }

    if (state.running && state.url) {
      dot.classList.add('green');
      label.textContent = 'Tunnel active';
      sub.textContent = stripUrl(state.url);
      return;
    }

    if (state.liveRunning && state.livePort) {
      dot.classList.add('green');
      label.textContent = 'Live Server ready';
      sub.textContent = 'localhost:' + state.livePort;
      return;
    }

    label.textContent = 'No active tunnel';
    sub.textContent = 'Ready to connect';
  }

  function renderTunnel() {
    var running = state.running;
    var url = state.url;
    var startBtn = $('start-btn');
    var copyBtn = $('copy-btn');

    if (_lastRunning === false && running) addLog('Tunnel connecting...', 'warn');
    if (_lastRunning === true && !running) addLog('Tunnel stopped', 'err');
    if (url && url !== _lastUrl) addLog('Tunnel live -> ' + url.replace(/^https?:\/\//, ''), 'ok');
    _lastRunning = running;
    _lastUrl = url;

    renderMainStatus();

    startBtn.disabled = !state.mekongInstalled || (running && !url);
    startBtn.textContent = state.mekongInstalled ? 'Start tunnel' : 'Install mekong CLI first';

    if (running && !url) {
      $('config-section').style.display = 'none';
      $('expire-section').style.display = 'none';
      $('start-section').style.display = 'none';
      $('connecting-box').style.display = 'flex';
      $('url-section').style.display = 'none';
      $('stop-section').style.display = 'block';
      return;
    }

    if (running && url) {
      $('config-section').style.display = 'none';
      $('expire-section').style.display = 'none';
      $('start-section').style.display = 'none';
      $('connecting-box').style.display = 'none';
      $('url-section').style.display = 'block';
      $('stop-section').style.display = 'block';
      $('url-text').textContent = url;
      return;
    }

    $('config-section').style.display = 'block';
    $('expire-section').style.display = 'block';
    $('start-section').style.display = 'block';
    $('connecting-box').style.display = 'none';
    $('url-section').style.display = 'none';
    $('stop-section').style.display = 'none';
    copyBtn.textContent = 'Copy';
    copyBtn.classList.remove('copied');
  }

  function renderLive() {
    var live = state.liveRunning;
    var port = state.livePort;
    var url = port ? 'http://localhost:' + port : '';
    var liveTunnelConnecting = !!(live && port && state.running && state.tunnelPort === port && !state.url);
    var liveTunnelActive = !!(live && port && state.liveTunnelActive && state.url);
    var card = $('ls-status-card');
    var dot = $('ls-dot');
    var label = $('ls-label');
    var sub = $('ls-sub');
    var offLabel = $('ls-off-label');
    var publicSection = $('ls-public-section');
    var publicCard = $('ls-public-card');
    var publicUrl = $('ls-public-url-text');
    var publicTag = $('ls-public-tag');
    var publicHelp = $('ls-public-help');
    var tunnelBtn = $('ls-tunnel-btn');
    var stopTunnelBtn = $('ls-stop-tunnel-btn');

    if (live && port) {
      card.classList.add('active');
      dot.className = 'dot green';
      label.textContent = liveTunnelActive
        ? 'Live on :' + port + ' with Tunnel'
        : (liveTunnelConnecting ? 'Publishing :' + port : 'Live on :' + port);
      sub.textContent = url;
      offLabel.style.display = 'none';
      $('ls-start-section').style.display = 'none';
      $('ls-running-section').style.display = 'block';
      $('ls-url-text').textContent = url;
      tunnelBtn.style.display = liveTunnelActive ? 'none' : '';
      tunnelBtn.disabled = liveTunnelConnecting;
      tunnelBtn.textContent = liveTunnelConnecting ? 'Starting public tunnel...' : 'Tunnel to public URL';
      stopTunnelBtn.style.display = liveTunnelActive ? '' : 'none';

      if (liveTunnelActive) {
        publicSection.style.display = 'block';
        publicCard.classList.remove('pending');
        publicTag.textContent = 'Live Server Tunnel';
        publicUrl.textContent = state.url;
        publicHelp.textContent = 'Auto-generated by Mekong Tunnel for localhost:' + port + '.';
        if (_lastLiveTunnel !== true) addLog('Live Server public tunnel -> ' + stripUrl(state.url), 'ok');
      } else if (liveTunnelConnecting) {
        publicSection.style.display = 'block';
        publicCard.classList.add('pending');
        publicTag.textContent = 'Starting';
        publicUrl.textContent = 'Generating public URL...';
        publicHelp.textContent = 'Mekong is creating a public URL for this Live Server.';
      } else {
        publicSection.style.display = 'none';
        publicCard.classList.remove('pending');
      }

      if (_lastLive !== true) addLog('Live Server started on :' + port, 'ok');
    } else {
      card.classList.remove('active');
      dot.className = 'dot';
      label.textContent = 'Not running';
      sub.textContent = 'Start to serve HTML files with live reload.';
      offLabel.style.display = 'inline-flex';
      $('ls-start-section').style.display = 'block';
      $('ls-running-section').style.display = 'none';
      publicSection.style.display = 'none';
      publicCard.classList.remove('pending');
      tunnelBtn.style.display = '';
      tunnelBtn.disabled = false;
      tunnelBtn.textContent = 'Tunnel to public URL';
      stopTunnelBtn.style.display = 'none';
      $('ls-copy-btn').textContent = 'Copy';
      $('ls-copy-btn').classList.remove('copied');
      $('ls-public-copy-btn').textContent = 'Copy';
      $('ls-public-copy-btn').classList.remove('copied');
      $('ls-public-share-btn').textContent = 'Share';
      $('ls-public-share-btn').classList.remove('copied');
      if (_lastLive === true) addLog('Live Server stopped', 'warn');
    }

    if (!liveTunnelActive && _lastLiveTunnel === true) addLog('Live Server public tunnel stopped', 'warn');
    _lastLive = live && !!port;
    _lastLiveTunnel = liveTunnelActive;
  }

  function detectPort() {
    clearPortPicker();
    send('detect');
    $('framework-hint').textContent = 'Scanning for running servers...';
    $('framework-hint').className = 'note';
  }

  function startTunnel() {
    if (!state.mekongInstalled) {
      $('mekong-missing').style.display = 'block';
      $('port-warning').style.display = 'none';
      setTab('tunnel');
      return;
    }

    var val = $('port-input').value.trim();
    var port = parseInt(val, 10);
    var hint = $('framework-hint');

    if (!val) {
      $('port-input').classList.add('error');
      hint.textContent = 'Enter a port or click Detect';
      hint.className = 'note err';
      setTimeout(function() {
        $('port-input').classList.remove('error');
        hint.textContent = '';
        hint.className = 'note';
      }, 3000);
      return;
    }

    if (isNaN(port) || port < 1 || port > 65535) {
      $('port-input').classList.add('error');
      hint.textContent = 'Invalid port (1-65535)';
      hint.className = 'note err';
      setTimeout(function() {
        $('port-input').classList.remove('error');
        hint.textContent = '';
        hint.className = 'note';
      }, 3000);
      return;
    }

    $('port-warning').style.display = 'none';
    $('mekong-missing').style.display = state.mekongInstalled ? 'none' : 'block';
    state.running = true;
    state.url = null;
    renderTunnel();
    send('start', { port: port, expire: $('expire-select').value });
  }

  window.addEventListener('message', function(e) {
    var msg = e.data;

    if (msg.type === 'state') {
      state.running = !!msg.running;
      state.url = msg.url || null;
      state.tunnelPort = typeof msg.tunnelPort === 'number' ? msg.tunnelPort : null;
      state.liveRunning = !!msg.liveRunning;
      state.livePort = msg.livePort || null;
      state.liveTunnelActive = !!msg.liveTunnelActive;
      state.mekongInstalled = msg.mekongInstalled !== false;
      state.loggedIn = !!msg.loggedIn;
      state.userEmail = msg.userEmail || '';
      state.userPlan = msg.userPlan || '';

      if (state.loggedIn) _signingIn = false;
      if (msg.platform) updateInstallUI(msg.platform, msg.arch || 'x64');

      $('port-warning').style.display = 'none';
      $('mekong-missing').style.display = state.mekongInstalled ? 'none' : 'block';

      renderAuth();
      renderTunnel();
      renderLive();
      return;
    }

    if (msg.type === 'mekongMissing') {
      state.mekongInstalled = false;
      _lastRunning = false;
      $('mekong-missing').style.display = 'block';
      $('port-warning').style.display = 'none';
      renderTunnel();
      return;
    }

    if (msg.type === 'portWarning') {
      _pendingPort = msg.port;
      _pendingExpire = msg.expire;
      $('warn-port').textContent = ':' + msg.port;
      $('warn-cmd').textContent = msg.cmd || 'npm run dev';
      $('port-warning').style.display = 'block';
      $('mekong-missing').style.display = 'none';
      state.running = false;
      state.url = null;
      _lastRunning = false;
      renderTunnel();
      return;
    }

    if (msg.type === 'detected') {
      clearPortPicker();
      if (msg.scanning) {
        $('framework-hint').textContent = 'Scanning for running servers...';
        $('framework-hint').className = 'note';
      } else if (msg.port) {
        $('port-input').value = String(msg.port);
        $('framework-hint').textContent = 'Detected: ' + (msg.framework || 'unknown');
        $('framework-hint').className = 'note ok';
      } else {
        $('framework-hint').textContent = 'Not detected - enter the port manually';
        $('framework-hint').className = 'note';
      }
      return;
    }

    if (msg.type === 'scanned') {
      var hint = $('framework-hint');
      var ports = msg.ports || [];
      clearPortPicker();

      if (ports.length === 0) {
        if (msg.basePort) {
          $('port-input').value = String(msg.basePort);
          hint.textContent = (msg.framework && msg.framework !== 'unknown')
            ? 'Detected: ' + msg.framework + ' (not running yet)'
            : 'Not running - start your dev server';
          hint.className = 'note';
        } else {
          hint.textContent = 'No running server detected - enter the port manually';
          hint.className = 'note';
        }
        return;
      }

      if (ports.length === 1) {
        var p = ports[0];
        $('port-input').value = String(p.port);
        hint.textContent = p.altPort
          ? 'Running on :' + p.port + ' (alt port)'
          : 'Running on :' + p.port;
        hint.className = 'note ok';
        return;
      }

      hint.textContent = 'Multiple servers found - pick one:';
      hint.className = 'note ok';
      showPortPicker(ports);
      return;
    }

    if (msg.type === 'copied') {
      flashButton('copy-btn', 'Copied!', 'Copy');
      return;
    }

    if (msg.type === 'liveCopied') {
      flashButton('ls-copy-btn', 'Copied!', 'Copy');
      return;
    }

    if (msg.type === 'livePublicCopied') {
      flashButton('ls-public-copy-btn', 'Copied!', 'Copy');
      return;
    }

    if (msg.type === 'livePublicShared') {
      flashButton('ls-public-share-btn', 'Copied!', 'Share');
    }
  });

  $('install-cmd-block').addEventListener('click', function() {
    if (!_installCmd) return;
    send('copyText', { text: _installCmd });
    $('install-copy-icon').textContent = 'OK';
    $('install-copied-hint').style.display = 'block';
    setTimeout(function() {
      $('install-copy-icon').textContent = '\u2398';
      $('install-copied-hint').style.display = 'none';
    }, 2000);
  });

  $('log-toggle').addEventListener('click', function() {
    logCollapsed = !logCollapsed;
    $('log-entries').style.display = logCollapsed ? 'none' : '';
    $('log-toggle-icon').textContent = logCollapsed ? '\u25B6' : '\u25BC';
  });

  $('tab-tunnel').addEventListener('click', function() { setTab('tunnel'); });
  $('tab-live').addEventListener('click', function() { setTab('live'); });

  $('install-btn').addEventListener('click', function() { send('install'); });
  $('recheck-btn').addEventListener('click', function() {
    $('mekong-missing').style.display = 'none';
    send('checkMekong');
  });

  $('warn-anyway-btn').addEventListener('click', function() {
    $('port-warning').style.display = 'none';
    state.running = true;
    state.url = null;
    renderTunnel();
    send('startForce', { port: _pendingPort, expire: _pendingExpire });
  });

  $('warn-cancel-btn').addEventListener('click', function() {
    $('port-warning').style.display = 'none';
    _pendingPort = null;
    _pendingExpire = null;
  });

  $('detect-btn').addEventListener('click', detectPort);
  $('start-btn').addEventListener('click', startTunnel);
  $('stop-btn').addEventListener('click', function() { send('stop'); });
  $('copy-btn').addEventListener('click', function() { send('copy'); });
  $('open-btn').addEventListener('click', function() { send('open'); });
  $('log-btn').addEventListener('click', function() { send('openOutput'); });

  $('ls-start-btn').addEventListener('click', function() { send('startLive'); });
  $('ls-start-preview-btn').addEventListener('click', function() { send('startLivePreview'); });
  $('ls-stop-btn').addEventListener('click', function() { send('stopLive'); });
  $('ls-open-btn').addEventListener('click', function() { send('openLive'); });
  $('ls-copy-btn').addEventListener('click', function() { send('copyLive'); });
  $('ls-public-copy-btn').addEventListener('click', function() { send('copyLivePublic'); });
  $('ls-public-open-btn').addEventListener('click', function() { send('openLivePublic'); });
  $('ls-public-share-btn').addEventListener('click', function() { send('shareLivePublic'); });
  $('ls-preview-btn').addEventListener('click', function() { send('openPreview'); });
  $('ls-tunnel-btn').addEventListener('click', function() { send('tunnelLive'); });
  $('ls-stop-tunnel-btn').addEventListener('click', function() { send('stopLiveTunnel'); });
  $('ls-header-close-btn').addEventListener('click', function() { send('stopLive'); });

  $('acct-login-btn').addEventListener('click', function() {
    _signingIn = true;
    renderAuth();
    addLog('Opening browser login...', 'warn');
    send('login');
  });

  $('acct-logout-btn').addEventListener('click', function() {
    state.loggedIn = false;
    state.userEmail = '';
    state.userPlan = '';
    _signingIn = false;
    renderAuth();
    addLog('Logged out', 'warn');
    send('logout');
  });

  wireLogoFallback();
  detectPort();
  setTab('tunnel');
  renderAuth();
  renderTunnel();
  renderLive();
})();
