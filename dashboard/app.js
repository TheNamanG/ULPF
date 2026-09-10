const METRICS_URL = 'http://127.0.0.1:8080/metrics';

// Chart configuration globals
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Inter', sans-serif";

const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
        duration: 0 // Disable internal animation for real-time smoothness
    },
    scales: {
        x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { maxTicksLimit: 10 }
        },
        y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            beginAtZero: true
        }
    },
    plugins: {
        legend: { display: false }
    }
};

// Initialize Charts
const ctxEps = document.getElementById('epsChart').getContext('2d');
const epsChart = new Chart(ctxEps, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'EPS',
            data: [],
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.2)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
        }]
    },
    options: commonOptions
});

const ctxQueue = document.getElementById('queueChart').getContext('2d');
const queueChart = new Chart(ctxQueue, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Queue Depth',
            data: [],
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.2)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
        }]
    },
    options: commonOptions
});

const ctxPie = document.getElementById('parserPieChart').getContext('2d');
const parserPieChart = new Chart(ctxPie, {
    type: 'doughnut',
    data: {
        labels: [],
        datasets: [{
            data: [],
            backgroundColor: [
                '#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#ec4899'
            ],
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { 
                position: 'right',
                labels: { color: '#94a3b8' }
            }
        }
    }
});

// State tracking
let lastIngested = 0;
const MAX_DATA_POINTS = 30;

function updateStatus(connected) {
    const dot = document.getElementById('connection-status');
    const text = document.getElementById('connection-text');
    if (connected) {
        dot.className = 'status-dot active';
        text.innerText = 'Connected to Pipeline';
    } else {
        dot.className = 'status-dot error';
        text.innerText = 'Disconnected';
    }
}

function parsePrometheus(text) {
    const metrics = {
        ingested: 0,
        parsed: 0,
        dlq: 0,
        queue: 0
    };
    
    const lines = text.split('\n');
    for (const line of lines) {
        if (line.startsWith('#') || !line.trim()) continue;
        const parts = line.split(' ');
        const name = parts[0];
        const val = parseFloat(parts[1]) || 0;

        if (name.startsWith('ulpf_ingest_total')) {
            metrics.ingested = val;
        }
        else if (name.startsWith('ulpf_parse_success_total')) {
            metrics.parsed += val;
        }
        else if (name.startsWith('ulpf_dlq_total')) {
            metrics.dlq += val;
        }
        else if (name.startsWith('ulpf_queue_depth')) {
            metrics.queue = val;
        }
    }
    return metrics;
}

function pushChartData(chart, label, value) {
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(value);
    
    if (chart.data.labels.length > MAX_DATA_POINTS) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.update();
}

async function fetchMetrics() {
    try {
        const response = await fetch(METRICS_URL);
        if (!response.ok) throw new Error('Network error');
        
        const text = await response.text();
        const metrics = parsePrometheus(text);
        
        updateStatus(true);
        
        // Calculate EPS
        const eps = Math.max(0, metrics.ingested - lastIngested);
        lastIngested = metrics.ingested;
        
        // Update DOM
        document.getElementById('val-eps').innerText = eps.toLocaleString();
        document.getElementById('val-ingested').innerText = metrics.ingested.toLocaleString();
        document.getElementById('val-parsed').innerText = metrics.parsed.toLocaleString();
        document.getElementById('val-dlq').innerText = metrics.dlq.toLocaleString();
        
        // Update Charts
        const timeLabel = new Date().toLocaleTimeString('en-US', { hour12: false, hour: "numeric", minute: "numeric", second: "numeric" });
        pushChartData(epsChart, timeLabel, eps);
        pushChartData(queueChart, timeLabel, metrics.queue);
        
    } catch (e) {
        updateStatus(false);
        // Push 0s on error to show downtime
        const timeLabel = new Date().toLocaleTimeString();
        pushChartData(epsChart, timeLabel, 0);
        pushChartData(queueChart, timeLabel, 0);
    }
}

const HISTORY_URL = 'http://127.0.0.1:8080/history';

async function fetchHistory() {
    try {
        const response = await fetch(HISTORY_URL);
        if (!response.ok) return;
        const events = await response.json();
        const tbody = document.getElementById('history-table-body');
        if (!tbody || !events.length) return;

        tbody.innerHTML = '';
        // Most recent first
        const recent = events.slice().reverse();
        for (const evt of recent) {
            const tr = document.createElement('tr');
            const isSuccess = evt.status === 'success';
            
            // Threat Intel Heuristic
            const rawLower = evt.raw_payload.toLowerCase();
            const isHarmful = rawLower.includes('error') || 
                              rawLower.includes('fail') || 
                              rawLower.includes('denied') ||
                              rawLower.includes('exception') ||
                              rawLower.includes('block') ||
                              rawLower.includes('fault');
            
            const threatTag = isHarmful 
                ? '<span class="tag-dlq" style="background: rgba(239,68,68,0.2); border: 1px solid #ef4444; color: #fca5a5;">High (Harmful)</span>'
                : '<span class="tag-success" style="color: #6ee7b7;">Low (Safe)</span>';

            // Attempt to extract EventID for display details
            let details = "N/A";
            const eventIdMatch = evt.raw_payload.match(/"EventID"\s*:\s*(\d+)/i);
            if (eventIdMatch) {
                details = `EventID: ${eventIdMatch[1]}`;
            } else if (evt.type_uid !== null) {
                details = `UID: ${evt.type_uid}`;
            }
            
            const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });

            tr.innerHTML = `
                <td style="color: var(--text-secondary);">${timeStr}</td>
                <td><span class="${isSuccess ? 'tag-success' : 'tag-dlq'}">${isSuccess ? 'NORMALIZED' : 'DLQ'}</span></td>
                <td>${threatTag}</td>
                <td style="color: ${isSuccess ? '#60a5fa' : '#f87171'}">${evt.parser || 'None'}</td>
                <td style="color: #cbd5e1; font-weight: 500;">${details}</td>
                <td class="hash-cell" title="${evt.raw_sha256}">${evt.raw_sha256}</td>
                <td class="payload-cell">
                    <button class="view-btn" onclick="openModal('${encodeURIComponent(evt.raw_payload)}')">View</button>
                    ${evt.raw_payload.substring(0, 50)}...
                </td>
            `;
            tbody.appendChild(tr);
        }

        // Update Pie Chart Data
        const parserCounts = {};
        for (const evt of events) {
            const p = evt.parser || 'Unknown';
            parserCounts[p] = (parserCounts[p] || 0) + 1;
        }
        
        parserPieChart.data.labels = Object.keys(parserCounts);
        parserPieChart.data.datasets[0].data = Object.values(parserCounts);
        parserPieChart.update();

        // Apply Search Filter immediately if there's text
        filterTable();

    } catch (e) {
        // Silent fail for history
    }
}

// --- Search Filter Logic ---
const searchInput = document.getElementById('searchInput');
searchInput.addEventListener('input', filterTable);

function filterTable() {
    const filter = searchInput.value.toLowerCase();
    const rows = document.getElementById('history-table-body').getElementsByTagName('tr');
    
    for (let i = 0; i < rows.length; i++) {
        // Skip the "Waiting for log stream" row if it's there
        if (rows[i].cells.length === 1) continue; 
        
        const textContent = rows[i].textContent.toLowerCase();
        if (textContent.includes(filter)) {
            rows[i].style.display = "";
        } else {
            rows[i].style.display = "none";
        }
    }
}

// --- Modal Logic ---
const modal = document.getElementById('payloadModal');
const closeBtn = document.querySelector('.close-modal');
const modalCodeBlock = document.getElementById('modalCodeBlock');

window.openModal = function(encodedPayload) {
    try {
        const raw = decodeURIComponent(encodedPayload);
        // Try to pretty print JSON if it's valid JSON
        const jsonObj = JSON.parse(raw);
        modalCodeBlock.textContent = JSON.stringify(jsonObj, null, 4);
    } catch (e) {
        // Fallback to raw text
        modalCodeBlock.textContent = decodeURIComponent(encodedPayload);
    }
    modal.style.display = 'block';
};

closeBtn.onclick = function() {
    modal.style.display = 'none';
};

window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = 'none';
    }
};

// Poll metrics and history every 1000ms
setInterval(() => {
    fetchMetrics();
    fetchHistory();
}, 1000);

fetchMetrics();
fetchHistory();
