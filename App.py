from flask import Flask, render_template_string, request, jsonify
from collections import deque
from datetime import datetime
from urllib.parse import urlparse
import time
import threading
import winsound
import re

app = Flask(__name__)

# -----------------------------
# SECURITY DATA
# -----------------------------
logs = deque(maxlen=20)
traffic = deque(maxlen=20)
request_times = deque(maxlen=200)

stats = {
    "phishing": 0,
    "ddos": 0,
    "safe": 0,
    "total_scans": 0
}

lock = threading.Lock()


# -----------------------------
# LOG SYSTEM
# -----------------------------
def add_log(message, level="INFO"):
    with lock:
        logs.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": message,
            "level": level
        })


# -----------------------------
# ALARM
# -----------------------------
def danger_alarm():
    try:
        for _ in range(3):
            winsound.Beep(1200, 350)
            time.sleep(0.1)
    except:
        pass


# -----------------------------
# PHISHING DETECTOR
# -----------------------------
def detect_phishing(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    score = 0
    reasons = []

    suspicious_words = [
        "login", "verify", "verification",
        "secure", "account", "update",
        "password", "bank", "wallet",
        "signin", "confirm", "free"
    ]

    url_lower = url.lower()

    for word in suspicious_words:
        if word in url_lower:
            score += 1
            reasons.append(f"Suspicious keyword: {word}")

    if "@" in url:
        score += 2
        reasons.append("Contains @ symbol")

    if len(url) > 75:
        score += 1
        reasons.append("Very long URL")

    if hostname.count("-") >= 2:
        score += 1
        reasons.append("Multiple hyphens in domain")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        score += 2
        reasons.append("Uses IP address instead of domain")

    if not parsed.netloc:
        score += 2
        reasons.append("Invalid domain")

    if score >= 3:
        return {
            "status": "DANGEROUS",
            "score": score,
            "reasons": reasons
        }

    return {
        "status": "SAFE",
        "score": score,
        "reasons": reasons
    }


# -----------------------------
# DDoS / TRAFFIC ANOMALY
# -----------------------------
def monitor_traffic():

    now = time.time()

    request_times.append(now)

    # Keep only last 10 seconds
    while request_times and now - request_times[0] > 10:
        request_times.popleft()

    current_rate = len(request_times)

    traffic.append(current_rate)

    # Defensive detection threshold
    if current_rate > 80:

        stats["ddos"] += 1

        add_log(
            f"High traffic anomaly detected: {current_rate} requests/10 sec",
            "CRITICAL"
        )

        threading.Thread(
            target=danger_alarm,
            daemon=True
        ).start()


# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home():

    monitor_traffic()

    return render_template_string(
        HTML,
        stats=stats,
        logs=list(logs),
        traffic=list(traffic)
    )


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL"
        })

    result = detect_phishing(url)

    stats["total_scans"] += 1

    if result["status"] == "DANGEROUS":

        stats["phishing"] += 1

        add_log(
            f"Phishing URL detected: {url}",
            "CRITICAL"
        )

        threading.Thread(
            target=danger_alarm,
            daemon=True
        ).start()

    else:

        stats["safe"] += 1

        add_log(
            f"URL checked: {url} - SAFE",
            "SAFE"
        )

    return jsonify(result)


@app.route("/api/data")
def api_data():

    monitor_traffic()

    return jsonify({
        "stats": stats,
        "logs": list(logs),
        "traffic": list(traffic)
    })


# -----------------------------
# DASHBOARD UI
# -----------------------------
HTML = """
<!DOCTYPE html>
<html>
<head>

<title>CyberGuard Security Dashboard</title>

<meta name="viewport"
content="width=device-width, initial-scale=1">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: Arial, sans-serif;
    background: #080b12;
    color: white;
}

.sidebar {
    position: fixed;
    width: 240px;
    height: 100vh;
    background: #0d111a;
    border-right: 1px solid #202735;
    padding: 25px;
}

.logo {
    font-size: 24px;
    font-weight: bold;
    margin-bottom: 40px;
}

.logo span {
    color: #00e5ff;
}

.menu {
    padding: 15px;
    margin: 10px 0;
    border-radius: 8px;
    color: #9ca7b8;
}

.menu.active {
    background: #111c29;
    color: #00e5ff;
}

.main {
    margin-left: 240px;
    padding: 30px;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
}

.status {
    padding: 10px 18px;
    border-radius: 20px;
    background: #10281d;
    color: #35e88c;
}

.cards {
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 20px;
}

.card {
    background: #0e131d;
    border: 1px solid #202735;
    padding: 22px;
    border-radius: 12px;
}

.card h4 {
    color: #8994a5;
    margin-bottom: 12px;
}

.number {
    font-size: 32px;
    font-weight: bold;
}

.red {
    color: #ff4d67;
}

.green {
    color: #35e88c;
}

.blue {
    color: #00e5ff;
}

.orange {
    color: #ffb84d;
}

.section {
    margin-top: 25px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}

.panel {
    background: #0e131d;
    border: 1px solid #202735;
    border-radius: 12px;
    padding: 22px;
}

.panel h2 {
    margin-bottom: 20px;
}

.scanner {
    display: flex;
    gap: 10px;
}

input {
    flex: 1;
    background: #080b12;
    border: 1px solid #30394a;
    padding: 14px;
    border-radius: 7px;
    color: white;
    outline: none;
}

button {
    background: #00bcd4;
    border: none;
    color: white;
    padding: 14px 22px;
    border-radius: 7px;
    cursor: pointer;
    font-weight: bold;
}

button:hover {
    opacity: .85;
}

.result {
    margin-top: 18px;
    padding: 15px;
    border-radius: 8px;
    display: none;
}

.danger {
    background: #3a1118;
    color: #ff6379;
}

.safe {
    background: #102d20;
    color: #35e88c;
}

.log {
    padding: 12px;
    margin: 8px 0;
    background: #111722;
    border-radius: 7px;
    font-size: 14px;
}

.critical {
    border-left: 4px solid #ff4d67;
}

.info {
    border-left: 4px solid #00e5ff;
}

.safe-log {
    border-left: 4px solid #35e88c;
}

.time {
    color: #6f7b8d;
    margin-right: 10px;
}

canvas {
    max-height: 250px;
}

@media(max-width:900px) {

    .sidebar {
        display: none;
    }

    .main {
        margin-left: 0;
    }

    .cards {
        grid-template-columns: repeat(2,1fr);
    }

    .section {
        grid-template-columns: 1fr;
    }
}

</style>

</head>

<body>

<div class="sidebar">

    <div class="logo">
        CYBER<span>GUARD</span>
    </div>

    <div class="menu active">
        🛡️ Dashboard
    </div>

    <div class="menu">
        🔗 URL Scanner
    </div>

    <div class="menu">
        🚨 Threat Detection
    </div>

    <div class="menu">
        🌐 Network Monitor
    </div>

    <div class="menu">
        📋 Security Logs
    </div>

</div>


<div class="main">

<div class="header">

    <div>
        <h1>Security Dashboard</h1>
        <p style="color:#8994a5">
            Real-time Cyber Threat Monitoring
        </p>
    </div>

    <div class="status">
        ● SYSTEM PROTECTED
    </div>

</div>


<div class="cards">

<div class="card">
    <h4>Phishing Threats</h4>
    <div class="number red"
    id="phishing">
        {{stats.phishing}}
    </div>
</div>

<div class="card">
    <h4>DDoS Alerts</h4>
    <div class="number orange"
    id="ddos">
        {{stats.ddos}}
    </div>
</div>

<div class="card">
    <h4>Safe URLs</h4>
    <div class="number green"
    id="safe">
        {{stats.safe}}
    </div>
</div>

<div class="card">
    <h4>Total Scans</h4>
    <div class="number blue"
    id="total">
        {{stats.total_scans}}
    </div>
</div>

</div>


<div class="section">

<div class="panel">

<h2>🔗 Phishing URL Scanner</h2>

<div class="scanner">

<input
id="url"
placeholder="Enter website URL..."
>

<button onclick="scanURL()">
SCAN
</button>

</div>

<div id="result"
class="result">
</div>

</div>


<div class="panel">

<h2>📊 Network Traffic</h2>

<canvas id="trafficChart"></canvas>

</div>

</div>


<div class="section">

<div class="panel">

<h2>🚨 Security Events</h2>

<div id="logs">

{% for log in logs %}

<div class="log
{% if log.level == 'CRITICAL' %}
critical
{% elif log.level == 'SAFE' %}
safe-log
{% else %}
info
{% endif %}
">

<span class="time">
{{log.time}}
</span>

{{log.message}}

</div>

{% endfor %}

</div>

</div>


<div class="panel">

<h2>🛡️ Threat Overview</h2>

<br>

<p>🔴 Phishing Detection</p>
<br>

<p>🟠 Traffic Anomaly Detection</p>
<br>

<p>🟢 Safe Activity</p>
<br>

<p>🔵 System Monitoring Active</p>

</div>

</div>

</div>


<script>

const ctx =
document.getElementById("trafficChart");

const chart =
new Chart(ctx, {

type: "line",

data: {

labels: [],

datasets: [{

label: "Requests / 10 sec",

data: [],

tension: 0.3

}]

},

options: {

responsive: true,

plugins: {

legend: {
display: true
}

},

scales: {

y: {
beginAtZero: true
}

}

}

});


async function scanURL() {

const url =
document.getElementById("url").value;

const result =
document.getElementById("result");

if (!url) {

alert("Enter a URL first!");

return;

}

const response =
await fetch("/scan", {

method: "POST",

headers: {
"Content-Type":
"application/json"
},

body: JSON.stringify({
url: url
})

});

const data =
await response.json();

result.style.display = "block";

if (data.status === "DANGEROUS") {

result.className =
"result danger";

result.innerHTML =

"🚨 <b>DANGER!</b><br>" +
"Potential phishing website detected." +
"<br><br>" +
"Risk Score: " + data.score;

} else {

result.className =
"result safe";

result.innerHTML =

"🟢 <b>SAFE</b><br>" +
"No major suspicious indicators detected." +
"<br><br>" +
"Risk Score: " + data.score;

}

updateDashboard();

}


async function updateDashboard() {

const response =
await fetch("/api/data");

const data =
await response.json();

document.getElementById(
"phishing"
).innerText =
data.stats.phishing;

document.getElementById(
"ddos"
).innerText =
data.stats.ddos;

document.getElementById(
"safe"
).innerText =
data.stats.safe;

document.getElementById(
"total"
).innerText =
data.stats.total_scans;


chart.data.labels =
data.traffic.map(
(_, i) => i + 1
);

chart.data.datasets[0].data =
data.traffic;

chart.update();

}


setInterval(
updateDashboard,
3000
);

</script>

</body>
</html>
"""


if __name__ == "__main__":

    add_log(
        "CyberGuard monitoring system started",
        "INFO"
    )

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
