// ===== Tab Navigation =====
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
});

// ===== Toast Notification =====
function showToast(msg, type = 'success') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3000);
}

// ===== Logging =====
let logs = [];
function addLog(msg, type = 'info') {
    const now = new Date().toLocaleTimeString('id-ID');
    logs.unshift({ time: now, msg, type });
    renderLogs();
    renderActivity();
}

function renderLogs() {
    const el = document.getElementById('full-log');
    if (!logs.length) { el.innerHTML = '<div class="log-empty">No logs yet.</div>'; return; }
    el.innerHTML = logs.map(l =>
        `<div class="log-entry ${l.type}"><span class="time">[${l.time}]</span><span>${l.msg}</span></div>`
    ).join('');
}

function renderActivity() {
    const el = document.getElementById('activity-log');
    const recent = logs.slice(0, 8);
    if (!recent.length) { el.innerHTML = '<div class="log-empty">No recent activity.</div>'; return; }
    el.innerHTML = recent.map(l =>
        `<div class="log-entry ${l.type}"><span class="time">[${l.time}]</span><span>${l.msg}</span></div>`
    ).join('');
}

function clearLogs() { logs = []; renderLogs(); renderActivity(); showToast('Logs cleared'); }

// ===== Scan Simulation =====
let scanning = false;

function simulateScan(name, fileCount) {
    if (scanning) return;
    scanning = true;
    const card = document.getElementById('scan-progress-card');
    const fill = document.getElementById('scan-fill');
    const detail = document.getElementById('scan-detail');
    const results = document.getElementById('scan-results');
    card.style.display = 'block';
    fill.style.width = '0%';
    results.innerHTML = '';
    addLog(name + ' started', 'info');

    let current = 0;
    let threats = 0;
    const interval = setInterval(() => {
        current++;
        const pct = Math.min(Math.round((current / fileCount) * 100), 100);
        fill.style.width = pct + '%';
        detail.textContent = `Scanning file ${current}/${fileCount}... (${pct}%)`;

        // Simulate random threat at ~70%
        if (current === Math.floor(fileCount * 0.7) && Math.random() > 0.5) {
            threats++;
            addLog('THREAT: suspicious_payload.exe [SHA-256 match]', 'threat');
        }

        if (current >= fileCount) {
            clearInterval(interval);
            scanning = false;
            fill.style.width = '100%';
            detail.textContent = 'Scan complete!';

            document.getElementById('stat-files').textContent = 
                (parseInt(document.getElementById('stat-files').textContent) + fileCount).toLocaleString();
            document.getElementById('stat-threats').textContent = 
                parseInt(document.getElementById('stat-threats').textContent) + threats;
            
            results.innerHTML = `<div style="margin-top:14px;padding:14px;border-radius:10px;background:${threats?'rgba(239,68,68,.1)':'rgba(34,197,94,.1)'};border:1px solid ${threats?'rgba(239,68,68,.2)':'rgba(34,197,94,.2)'};">
                <strong>${threats ? '⚠️ ' + threats + ' threat(s) detected!' : '✅ No threats found.'}</strong><br>
                <span style="font-size:.82rem;color:var(--dim)">Scanned ${fileCount} files in ${(fileCount * 0.02).toFixed(1)}s</span>
            </div>`;

            addLog(`${name} complete: ${fileCount} files, ${threats} threats`, threats ? 'threat' : 'info');
            if (threats) showToast(threats + ' threat(s) found!', 'error');
            else showToast('Scan clean — no threats');
        }
    }, 20);
}

function startQuickScan() { simulateScan('Quick Scan', 150); }
function startCustomScan() { simulateScan('Custom Scan', 300); }
function startFullScan() { simulateScan('Full Scan', 800); }

// ===== Real-Time Toggle =====
let rtInterval = null;
function toggleRealtime() {
    const on = document.getElementById('rt-toggle').checked;
    const log = document.getElementById('rt-log');
    if (on) {
        log.innerHTML = '';
        addLog('Real-time protection enabled', 'info');
        let evtCount = 0;
        rtInterval = setInterval(() => {
            const events = ['FILE_CREATE: temp_download.tmp','FILE_MODIFY: config.ini','FILE_CREATE: update.exe','FILE_RENAME: doc.pdf','FILE_DELETE: cache.dat'];
            const evt = events[Math.floor(Math.random() * events.length)];
            evtCount++;
            const now = new Date().toLocaleTimeString('id-ID');
            log.innerHTML = `<div class="log-entry info"><span class="time">[${now}]</span><span>${evt}</span></div>` + log.innerHTML;
            if (evtCount > 50) log.lastChild.remove();
        }, 2000);
    } else {
        if (rtInterval) clearInterval(rtInterval);
        rtInterval = null;
        log.innerHTML = '<div class="log-empty">Real-time protection disabled.</div>';
        addLog('Real-time protection disabled', 'info');
    }
}

// ===== Settings =====
function saveSettings() {
    const cfg = {
        db: document.getElementById('cfg-db').value,
        maxSize: document.getElementById('cfg-maxsize').value,
        qDir: document.getElementById('cfg-qdir').value,
        autoQ: document.getElementById('cfg-autoq').checked,
        zip: document.getElementById('cfg-zip').checked,
        pe: document.getElementById('cfg-pe').checked,
        sig: document.getElementById('cfg-sig').checked,
        notif: document.getElementById('cfg-notif').checked,
        sound: document.getElementById('cfg-sound').checked
    };
    localStorage.setItem('av_settings', JSON.stringify(cfg));
    addLog('Settings saved', 'info');
    showToast('Settings saved successfully!');
}

function loadSettings() {
    const raw = localStorage.getItem('av_settings');
    if (!raw) return;
    try {
        const cfg = JSON.parse(raw);
        if (cfg.db) document.getElementById('cfg-db').value = cfg.db;
        if (cfg.maxSize) document.getElementById('cfg-maxsize').value = cfg.maxSize;
        if (cfg.qDir) document.getElementById('cfg-qdir').value = cfg.qDir;
        document.getElementById('cfg-autoq').checked = !!cfg.autoQ;
        document.getElementById('cfg-zip').checked = !!cfg.zip;
        document.getElementById('cfg-pe').checked = !!cfg.pe;
        document.getElementById('cfg-sig').checked = !!cfg.sig;
        document.getElementById('cfg-notif').checked = !!cfg.notif;
        document.getElementById('cfg-sound').checked = !!cfg.sound;
    } catch(e) { /* corrupted settings, ignore */ }
}

// ===== Init =====
loadSettings();
addLog('AV Guard initialized', 'info');
