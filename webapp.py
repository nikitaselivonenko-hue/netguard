import os
import threading
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import sqlite3
import netguard

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-me-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
csrf = CSRFProtect(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

DB_PATH = netguard.DB_PATH

def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 500")
    alerts = [{'id': r[0], 'timestamp': r[1], 'type': r[2], 'src': r[3], 'dst': r[4], 'desc': r[5]} for r in c.fetchall()]
    conn.close()
    return alerts

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_alerts())

@app.route('/alerts')
def alerts_page():
    alerts = get_alerts()
    return render_template('alerts.html', alerts=alerts)

@app.route('/upload', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            t = threading.Thread(target=netguard.analyze_pcap, args=(filepath,))
            t.start()
            flash('File uploaded and analysis started. Check alerts page.', 'success')
            return redirect(url_for('alerts_page'))
        else:
            flash('Invalid file format. Please upload .pcap or .pcapng', 'danger')
    return render_template('upload.html')

@app.route('/generate-demo')
def generate_demo():
    netguard.log_alert('Port Scanning', '192.168.1.100', '10.0.0.1', 'Ports scanned: 22, 80, 443, 3389, 8080')
    netguard.log_alert('ARP Spoofing', '192.168.1.1', 'broadcast', 'MAC changed from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66')
    netguard.log_alert('DNS Tunneling (High Entropy)', '192.168.1.50', '8.8.8.8', 'Entropy 4.56: xyzsecretdata.tunnel.example.com')
    netguard.log_alert('ICMP Tunneling (Large Payload)', '10.0.0.5', '10.0.0.6', 'Size 256 bytes')
    flash('Demo alerts generated', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
