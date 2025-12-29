/**
 * VulnHunter Pro - Dashboard JavaScript
 * Handles 3 views: Config, Scanning, Results
 */
document.addEventListener('DOMContentLoaded', () => {
    // WebSocket connection
    const socket = io();
    let currentScanId = null;
    let targetUrl = '';

    // Views
    const viewConfig = document.getElementById('view-config');
    const viewScanning = document.getElementById('view-scanning');
    const viewResults = document.getElementById('view-results');

    // Elements
    const connectionStatus = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');
    const logsContainer = document.getElementById('logs-container');
    const progressBar = document.getElementById('progress-bar');
    const progressPhase = document.getElementById('progress-phase');

    // Counters (scanning view)
    const counts = {
        critical: document.getElementById('count-critical'),
        high: document.getElementById('count-high'),
        medium: document.getElementById('count-medium'),
        low: document.getElementById('count-low')
    };

    // Final counters (results view)
    const finalCounts = {
        critical: document.getElementById('final-critical'),
        high: document.getElementById('final-high'),
        medium: document.getElementById('final-medium'),
        low: document.getElementById('final-low')
    };

    // Load saved API keys
    loadApiKeys();

    // --- View Management ---
    function showView(viewName) {
        viewConfig.classList.remove('active');
        viewScanning.classList.remove('active');
        viewResults.classList.remove('active');

        if (viewName === 'config') viewConfig.classList.add('active');
        else if (viewName === 'scanning') viewScanning.classList.add('active');
        else if (viewName === 'results') viewResults.classList.add('active');
    }

    // --- WebSocket Events ---
    socket.on('connect', () => {
        connectionStatus.classList.remove('offline');
        connectionStatus.classList.add('online');
        statusText.textContent = 'Connecté';
        addLog('SYSTEM', 'Connecté au serveur VulnHunter Pro', 'success');
    });

    socket.on('disconnect', () => {
        connectionStatus.classList.remove('online');
        connectionStatus.classList.add('offline');
        statusText.textContent = 'Déconnecté';
        addLog('SYSTEM', 'Connexion perdue', 'error');

        // Try to recover results if scan was in progress
        if (currentScanId) {
            setTimeout(() => pollForResults(currentScanId), 3000);
        }
    });

    socket.on('log_message', (data) => {
        addLog(data.module, data.message, data.level.toLowerCase());
        updateProgressFromLog(data.message);
    });

    socket.on('scan_status', (data) => {
        if (data.status === 'started') {
            currentScanId = data.scan_id;
            showView('scanning');
            resetCounters();
            setProgress(1, 'Reconnaissance', 5);
            addLog('SYSTEM', `Scan démarré: ${currentScanId}`, 'success');

        } else if (data.status === 'completed') {
            handleScanComplete(data);

        } else if (data.status === 'error') {
            addLog('SYSTEM', `Erreur: ${data.message}`, 'error');
        }
    });

    socket.on('vulnerability_found', (data) => {
        const vuln = data.vulnerability;
        const severityMap = { 'CRITIQUE': 'critical', 'ÉLEVÉ': 'high', 'MOYEN': 'medium', 'FAIBLE': 'low' };
        const severity = severityMap[vuln.severite] || 'low';

        if (counts[severity]) {
            counts[severity].textContent = parseInt(counts[severity].textContent) + 1;
        }

        addLog('VULN', `[${vuln.severite}] ${vuln.type}`, 'warning');
    });

    // --- Scan Complete Handler ---
    function handleScanComplete(data) {
        addLog('SYSTEM', '✅ Scan terminé!', 'success');
        setProgress(5, 'Terminé!', 100);

        // Update final stats
        if (data.rapport && data.rapport.stats_severite) {
            const stats = data.rapport.stats_severite;
            finalCounts.critical.textContent = stats.CRITIQUE || 0;
            finalCounts.high.textContent = stats['ÉLEVÉ'] || 0;
            finalCounts.medium.textContent = stats.MOYEN || 0;
            finalCounts.low.textContent = stats.FAIBLE || 0;
        }

        // Set download links
        if (data.rapport) {
            const r = data.rapport;
            if (r.chemin_html) {
                document.getElementById('dl-report').href = `/rapports/output/${r.chemin_html.split('/').pop()}`;
            }
            if (r.chemin_json) {
                document.getElementById('dl-json').href = `/rapports/output/${r.chemin_json.split('/').pop()}`;
            }
            if (r.chemin_executif) {
                document.getElementById('dl-executive').href = `/rapports/output/${r.chemin_executif.split('/').pop()}`;
            }
        }

        // Set logs download link
        document.getElementById('dl-logs').href = `/api/logs/${currentScanId}/download`;

        // Set target in results
        document.getElementById('result-target').textContent = targetUrl;

        // Switch to results view after short delay
        setTimeout(() => showView('results'), 1000);
    }

    // --- Progress Tracking ---
    function setProgress(step, phaseName, percent) {
        progressBar.style.width = percent + '%';
        progressPhase.textContent = phaseName;

        for (let i = 1; i <= 5; i++) {
            const stepEl = document.getElementById('step-' + i);
            if (stepEl) {
                stepEl.classList.remove('active', 'completed');
                if (i < step) stepEl.classList.add('completed');
                else if (i === step) stepEl.classList.add('active');
            }
        }
    }

    function updateProgressFromLog(message) {
        const msg = message.toLowerCase();
        if (msg.includes('reconnaissance') || msg.includes('phase 1')) {
            setProgress(1, 'Reconnaissance', 15);
        } else if (msg.includes('détection') || msg.includes('phase 2')) {
            setProgress(2, 'Détection des vulnérabilités', 35);
        } else if (msg.includes('validation') || msg.includes('phase 3')) {
            setProgress(3, 'Validation', 55);
        } else if (msg.includes('exploit') || msg.includes('phase 4')) {
            setProgress(4, 'Génération d\'exploits', 75);
        } else if (msg.includes('rapport') || msg.includes('phase 5') || msg.includes('phase 6')) {
            setProgress(5, 'Génération du rapport', 90);
        }
    }

    // --- Polling Fallback ---
    async function pollForResults(scanId, attempts = 0) {
        if (attempts > 10) {
            addLog('SYSTEM', 'Impossible de récupérer les résultats', 'error');
            return;
        }

        try {
            const response = await fetch(`/api/scan/results/${scanId}`);
            const data = await response.json();

            if (data.status === 'success' && data.rapport) {
                handleScanComplete({
                    rapport: {
                        ...data.rapport,
                        chemin_html: data.rapport.rapports?.html ? data.rapport.rapports.html : null,
                        chemin_json: data.rapport.rapports?.json ? data.rapport.rapports.json : null,
                        chemin_executif: data.rapport.rapports?.executif ? data.rapport.rapports.executif : null,
                        stats_severite: data.rapport.statistiques?.par_severite || {}
                    }
                });
            } else {
                addLog('SYSTEM', `Attente des résultats... (${attempts + 1}/10)`, 'info');
                setTimeout(() => pollForResults(scanId, attempts + 1), 5000);
            }
        } catch (e) {
            setTimeout(() => pollForResults(scanId, attempts + 1), 5000);
        }
    }

    // --- Logging ---
    function addLog(module, message, level = 'info') {
        const entry = document.createElement('div');
        entry.className = `log-entry ${level}`;

        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `
            <span class="log-time">${time}</span>
            <span class="log-module">${module}</span>
            <span class="log-message">${message}</span>
        `;

        logsContainer.appendChild(entry);
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    function resetCounters() {
        counts.critical.textContent = '0';
        counts.high.textContent = '0';
        counts.medium.textContent = '0';
        counts.low.textContent = '0';
    }

    // --- API Keys ---
    function loadApiKeys() {
        const keys = JSON.parse(localStorage.getItem('vulnhunter_api_keys') || '{}');
        if (keys.openai) document.getElementById('api-openai').value = keys.openai;
        if (keys.anthropic) document.getElementById('api-anthropic').value = keys.anthropic;
        if (keys.nist) document.getElementById('api-nist').value = keys.nist;
    }

    function saveApiKeys() {
        const keys = {
            openai: document.getElementById('api-openai').value,
            anthropic: document.getElementById('api-anthropic').value,
            nist: document.getElementById('api-nist').value
        };
        localStorage.setItem('vulnhunter_api_keys', JSON.stringify(keys));
        addLog('SYSTEM', 'Clés API sauvegardées', 'success');
    }

    // --- Event Listeners ---
    document.getElementById('btn-start-scan').addEventListener('click', async () => {
        targetUrl = document.getElementById('target-url').value;
        if (!targetUrl) {
            alert('Veuillez entrer une URL cible');
            return;
        }

        const payload = {
            url: targetUrl,
            scan_type: 'full',
            modules: document.getElementById('opt-api-fuzzing').checked ? ['sql', 'xss', 'api'] : ['sql', 'xss'],
            auth: document.getElementById('opt-auth').checked ? { cookies: {}, headers: {} } : {},
            intensite: document.getElementById('opt-aggressive').checked ? 'aggressive' : 'normal'
        };

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();

            if (data.status !== 'success') {
                addLog('SYSTEM', `Erreur: ${data.message}`, 'error');
            }
        } catch (e) {
            addLog('SYSTEM', `Erreur réseau: ${e}`, 'error');
        }
    });

    document.getElementById('btn-save-keys').addEventListener('click', saveApiKeys);

    document.getElementById('btn-new-scan').addEventListener('click', () => {
        currentScanId = null;
        logsContainer.innerHTML = '';
        showView('config');
    });

    document.getElementById('btn-pause').addEventListener('click', async () => {
        if (!currentScanId) return;

        try {
            await fetch(`/api/scan/pause/${currentScanId}`, { method: 'POST' });
            addLog('SYSTEM', 'Scan mis en pause', 'warning');
        } catch (e) {
            console.error(e);
        }
    });
});
