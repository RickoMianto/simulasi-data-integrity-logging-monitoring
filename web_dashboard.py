from flask import Flask, render_template, jsonify
from log_analyzer import LogAnalyzer
from file_integrity_monitor import FileIntegrityMonitor
import os
from datetime import datetime

app = Flask(__name__)

# Template HTML (simpan sebagai templates/index.html)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Integrity Monitor Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card .icon {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .stat-card.safe { border-left: 5px solid #4caf50; }
        .stat-card.safe .value { color: #4caf50; }
        
        .stat-card.warning { border-left: 5px solid #ff9800; }
        .stat-card.warning .value { color: #ff9800; }
        
        .stat-card.alert { border-left: 5px solid #f44336; }
        .stat-card.alert .value { color: #f44336; }
        
        .stat-card.info { border-left: 5px solid #2196f3; }
        .stat-card.info .value { color: #2196f3; }
        
        .log-section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .log-section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .log-entry {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #ddd;
            background: #f8f9fa;
        }
        
        .log-entry.INFO { border-left-color: #2196f3; }
        .log-entry.WARNING { border-left-color: #ff9800; background: #fff3e0; }
        .log-entry.ALERT { border-left-color: #f44336; background: #ffebee; }
        
        .log-entry .timestamp {
            color: #666;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        
        .log-entry .level {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .log-entry .level.INFO { background: #2196f3; color: white; }
        .log-entry .level.WARNING { background: #ff9800; color: white; }
        .log-entry .level.ALERT { background: #f44336; color: white; }
        
        .log-entry .message {
            color: #333;
            margin-top: 5px;
        }
        
        .actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-success {
            background: #4caf50;
            color: white;
        }
        
        .btn-success:hover {
            background: #45a049;
        }
        
        .refresh-info {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 0.9em;
        }
        
        .last-update {
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 8px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 File Integrity Monitor</h1>
            <p>Real-time Security Monitoring Dashboard</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card safe">
                <div class="icon">✅</div>
                <div class="label">Safe Files</div>
                <div class="value" id="safe-files">{{ stats.safe_files }}</div>
            </div>
            
            <div class="stat-card warning">
                <div class="icon">⚠️</div>
                <div class="label">Failed Integrity</div>
                <div class="value" id="failed-files">{{ stats.failed_files }}</div>
            </div>
            
            <div class="stat-card alert">
                <div class="icon">🚨</div>
                <div class="label">Total Anomalies</div>
                <div class="value" id="anomalies">{{ stats.anomaly_count }}</div>
            </div>
            
            <div class="stat-card info">
                <div class="icon">📁</div>
                <div class="label">Total Logs</div>
                <div class="value" id="total-logs">{{ stats.total_logs }}</div>
            </div>
        </div>
        
        <div class="log-section">
            <h2>📋 Recent Activity</h2>
            {% if stats.last_anomaly %}
            <p style="color: #f44336; margin-bottom: 15px;">
                <strong>⏰ Last Anomaly:</strong> {{ stats.last_anomaly }}
            </p>
            {% else %}
            <p style="color: #4caf50; margin-bottom: 15px;">
                <strong>✅ Status:</strong> No anomalies detected
            </p>
            {% endif %}
            
            <div id="log-entries">
                {% for log in recent_logs %}
                <div class="log-entry {{ log.level }}">
                    <div class="timestamp">{{ log.timestamp }}</div>
                    <span class="level {{ log.level }}">{{ log.level }}</span>
                    <span class="message">{{ log.message }}</span>
                </div>
                {% endfor %}
            </div>
            
            <div class="actions">
                <button class="btn btn-primary" onclick="refreshData()">🔄 Refresh</button>
                <button class="btn btn-success" onclick="runCheck()">🔍 Run Integrity Check</button>
            </div>
        </div>
        
        <div class="refresh-info">
            <div class="last-update">
                Last updated: <span id="last-update">{{ now }}</span>
            </div>
            <p>Dashboard auto-refreshes every 30 seconds</p>
        </div>
    </div>
    
    <script>
        function refreshData() {
            location.reload();
        }
        
        function runCheck() {
            fetch('/api/check')
                .then(response => response.json())
                .then(data => {
                    alert('Integrity check completed!\\n\\nResults:\\n' +
                          'Safe: ' + data.safe + '\\n' +
                          'Corrupted: ' + data.corrupted + '\\n' +
                          'New: ' + data.new + '\\n' +
                          'Deleted: ' + data.deleted);
                    setTimeout(refreshData, 1000);
                })
                .catch(error => {
                    alert('Error running check: ' + error);
                });
        }
        
        // Auto refresh every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Halaman utama dashboard"""
    analyzer = LogAnalyzer()
    stats = analyzer.get_statistics()
    
    if not stats:
        stats = {
            'total_logs': 0,
            'safe_files': 0,
            'failed_files': 0,
            'new_files': 0,
            'deleted_files': 0,
            'last_anomaly': None,
            'anomaly_count': 0
        }
    
    # Ambil 10 log terakhir
    recent_logs = []
    for log in analyzer.logs[-10:]:
        recent_logs.append({
            'timestamp': log['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if log['timestamp'] else 'N/A',
            'level': log['level'],
            'message': log['message']
        })
    recent_logs.reverse()
    
    # Format last anomaly
    if stats['last_anomaly']:
        stats['last_anomaly'] = stats['last_anomaly'].strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('index.html', 
                         stats=stats, 
                         recent_logs=recent_logs,
                         now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/api/stats')
def api_stats():
    """API endpoint untuk mendapatkan statistik"""
    analyzer = LogAnalyzer()
    stats = analyzer.get_statistics()
    
    if stats and stats['last_anomaly']:
        stats['last_anomaly'] = stats['last_anomaly'].isoformat()
    
    return jsonify(stats if stats else {})

@app.route('/api/check')
def api_check():
    """API endpoint untuk menjalankan integrity check"""
    monitor = FileIntegrityMonitor()
    results = monitor.check_integrity()
    return jsonify(results)

@app.route('/api/logs')
def api_logs():
    """API endpoint untuk mendapatkan semua log"""
    analyzer = LogAnalyzer()
    
    logs_data = []
    for log in analyzer.logs:
        logs_data.append({
            'timestamp': log['timestamp'].isoformat() if log['timestamp'] else None,
            'level': log['level'],
            'message': log['message']
        })
    
    return jsonify(logs_data)


def setup_templates():
    """Setup folder templates dan file HTML"""
    os.makedirs('templates', exist_ok=True)
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE)
    
    print("✅ Template files created in 'templates' folder")


if __name__ == '__main__':
    # Setup templates
    setup_templates()
    
    print("\n" + "="*60)
    print("🌐 Starting File Integrity Monitor Web Dashboard")
    print("="*60)
    print("\n📍 Dashboard URL: http://localhost:5000")
    print("🔄 Auto-refresh: Every 30 seconds")
    print("\nPress Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)