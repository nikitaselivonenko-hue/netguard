import threading
import queue
import time
import re
import math
import hashlib
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether
from scapy.utils import PcapReader
import requests
import os

DB_PATH = 'netguard.db'
TELEGRAM_BOT_TOKEN = os.environ.get('8607116409:AAEbOq9-foip9HNvYgGl44KzUiptMa4p2wM')
TELEGRAM_CHAT_ID = os.environ.get('1185608474')

alert_queue = queue.Queue()

port_scan_tracker = {}
arp_table = {}
dns_request_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)

def init_db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  alert_type TEXT,
                  source_ip TEXT,
                  dest_ip TEXT,
                  description TEXT)''')
    conn.commit()
    conn.close()

def log_alert(alert_type, src_ip, dst_ip, desc):
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO alerts (timestamp, alert_type, source_ip, dest_ip, description) VALUES (?, ?, ?, ?, ?)",
              (timestamp, alert_type, src_ip, dst_ip, desc))
    conn.commit()
    conn.close()
    alert_data = {
        'timestamp': timestamp,
        'type': alert_type,
        'src': src_ip,
        'dst': dst_ip,
        'desc': desc
    }
    alert_queue.put(alert_data)
    send_telegram_alert(alert_data)

def send_telegram_alert(alert_data):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    msg = f"🚨 [{alert_data['timestamp']}] {alert_data['type']}\n{alert_data['src']} → {alert_data['dst']}\n{alert_data['desc']}"
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                      json={'chat_id': TELEGRAM_CHAT_ID, 'text': msg, 'parse_mode': 'HTML'}, timeout=3)
    except:
        pass

def entropy(string):
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * math.log2(p) for p in prob)

def analyze_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2:
            ip_src = arp.psrc
            mac_src = arp.hwsrc
            if ip_src in arp_table and arp_table[ip_src] != mac_src:
                log_alert('ARP Spoofing', ip_src, 'broadcast', f'MAC changed {arp_table[ip_src]} → {mac_src}')
            arp_table[ip_src] = mac_src

    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]
        if tcp.flags == 'S':
            src = ip.src
            dst = ip.dst
            dport = tcp.dport
            key = f'{src}->{dst}'
            now = time.time()
            if key not in port_scan_tracker:
                port_scan_tracker[key] = {'ports': set(), 'start': now}
            tracker = port_scan_tracker[key]
            tracker['ports'].add(dport)
            if len(tracker['ports']) > 20 and (now - tracker['start']) < 10:
                log_alert('Port Scanning', src, dst, f'Ports: {sorted(tracker["ports"])[:30]}')
                port_scan_tracker[key] = {'ports': set(), 'start': now}

    if packet.haslayer(DNS) and packet.haslayer(UDP):
        dns = packet[DNS]
        if dns.qr == 0 and dns.qdcount > 0:
            qname = dns[DNSQR].qname.decode(errors='ignore').rstrip('.')
            qtype = dns[DNSQR].qtype
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            now = time.time()

            if len(qname) > 50:
                log_alert('DNS Tunneling (Long Domain)', src_ip, dst_ip, f'Domain length {len(qname)}: {qname[:80]}')
            if entropy(qname) > 4.0:
                log_alert('DNS Tunneling (High Entropy)', src_ip, dst_ip, f'Entropy {entropy(qname):.2f}: {qname[:80]}')
            if qtype == 16 or qtype == 16:
                log_alert('DNS Tunneling (TXT Record Request)', src_ip, dst_ip, f'TXT query: {qname[:80]}')

            key = f'{src_ip}->{dst_ip}'
            dns_request_tracker[key].append(now)
            dns_request_tracker[key] = [t for t in dns_request_tracker[key] if now - t < 60]
            if len(dns_request_tracker[key]) > 100:
                log_alert('DNS Tunneling (High Frequency)', src_ip, dst_ip, f'{len(dns_request_tracker[key])} queries/min')
                dns_request_tracker[key].clear()

    if packet.haslayer(ICMP) and packet.haslayer(IP):
        icmp = packet[ICMP]
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        now = time.time()

        if icmp.type == 8:
            payload = bytes(icmp.payload)
            if len(payload) > 100:
                log_alert('ICMP Tunneling (Large Payload)', src_ip, dst_ip, f'Size {len(payload)} bytes')
            try:
                text = payload.decode('utf-8', errors='ignore')
                if re.search(r'[a-zA-Z0-9+/=]{20,}', text):
                    log_alert('ICMP Tunneling (Base64 Payload)', src_ip, dst_ip, 'Base64 data in ICMP')
            except:
                pass

            key = f'{src_ip}->{dst_ip}'
            icmp_tracker[key].append(now)
            icmp_tracker[key] = [t for t in icmp_tracker[key] if now - t < 10]
            if len(icmp_tracker[key]) > 50:
                log_alert('ICMP Tunneling (High Frequency)', src_ip, dst_ip, f'{len(icmp_tracker[key])} pings/10s')
                icmp_tracker[key].clear()

def start_sniffing(interface=None, count=0):
    init_db()
    sniff(iface=interface, prn=analyze_packet, store=False, count=count)

def analyze_pcap(filepath):
    init_db()
    packets = PcapReader(filepath)
    for pkt in packets:
        analyze_packet(pkt)
