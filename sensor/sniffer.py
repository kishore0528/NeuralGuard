import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import time
import pickle
import subprocess
import numpy as np
import psycopg2
import argparse
import warnings

# Suppress annoying scikit-learn warnings about lacking feature names
warnings.filterwarnings('ignore')

from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr
from keras.models import load_model

# Constants
FEATURES_LEN = 12
MAX_PACKETS = 10
DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"

# IPS Confidence Thresholds
THRESH_AUTO_BLOCK = 0.90   # >= 0.90 → AUTO_BLOCKED (ufw deny)
THRESH_NEEDS_REVIEW = 0.75 # >= 0.75 → NEEDS_REVIEW (analyst queue)
                            # <  0.75 → BENIGN (no action)

def get_active_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0" and ip != "127.0.0.1":
                print(f"[+] Auto-detected active interface: {iface} (IP: {ip})")
                return iface
        except:
            continue
    print("[-] Could not auto-detect active external interface. Falling back to default.")
    return None

# Global State
flow_table = {}
model = None
scaler = None
chaos_score = 0.0
last_chaos_calc_time = 0.0
blocked_ips = set()  # Session-level dedup to avoid spamming ufw

def init_db():
    for attempt in range(1, 10):
        try:
            conn = psycopg2.connect(DB_DSN)
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    predicted_class INTEGER
                )
            ''')
            c.execute('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS chaos_score REAL;')
            c.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'BENIGN';")
            c.execute('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence REAL;')
            c.execute('''
                CREATE TABLE IF NOT EXISTS ip_management (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT UNIQUE,
                    status TEXT DEFAULT 'BLACKLISTED',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
            print("[+] Connected to PostgreSQL successfully.")
            print("[+] IPS schema verified (alerts + ip_management tables).")
            return
        except Exception as e:
            print(f"Database Initialization Error (Attempt {attempt}), retrying in 5s... Error: {e}")
            time.sleep(5)
    print("[-] Failed to connect to Database after multiple retries.")

def log_alert(src_ip, dst_ip, src_port, dst_port, protocol, predicted_class, chaos_score, status, confidence):
    """Log alert with IPS status (AUTO_BLOCKED / NEEDS_REVIEW / BENIGN)."""
    try:
        conn = psycopg2.connect(DB_DSN)
        c = conn.cursor()
        c.execute('''
            INSERT INTO alerts (src_ip, dst_ip, src_port, dst_port, protocol, predicted_class, chaos_score, status, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (src_ip, dst_ip, src_port, dst_port, protocol, predicted_class, chaos_score, status, confidence))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Logging Error: {e}")


def block_ip(src_ip):
    """Block an IP via ufw at priority 1 and record it in ip_management. Skips if already blocked this session."""
    global blocked_ips
    if src_ip in blocked_ips:
        return  # Already blocked this session — skip to avoid spamming ufw
    try:
        result = subprocess.run(
            ['sudo', 'ufw', 'insert', '1', 'deny', 'from', src_ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            blocked_ips.add(src_ip)
            print(f"[🛡️  IPS] BLOCKED {src_ip} via ufw")
            print(f"[SYSTEM] Firewall updated at priority 1")
            # Record in ip_management table
            try:
                conn = psycopg2.connect(DB_DSN)
                c = conn.cursor()
                c.execute(
                    "INSERT INTO ip_management (ip_address, status) VALUES (%s, 'BLACKLISTED') ON CONFLICT (ip_address) DO NOTHING",
                    (src_ip,)
                )
                conn.commit()
                conn.close()
                print(f"[📋 DB] Recorded {src_ip} as BLACKLISTED in ip_management")
            except Exception as db_err:
                print(f"[⚠️  DB] Failed to record block in ip_management: {db_err}")
        else:
            print(f"[⚠️  IPS] ufw deny failed for {src_ip}: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        print(f"[⚠️  IPS] ufw command timed out for {src_ip}")
    except Exception as e:
        print(f"[⚠️  IPS] Failed to block {src_ip}: {e}")

def get_flow_key(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol_str = 'TCP'
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol_str = 'UDP'
        else:
            return None, None, None # Unsupported protocol
        
        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol_str)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol_str)
        
        if fwd_key in flow_table:
            return fwd_key, True, protocol_str
        elif bwd_key in flow_table:
            return bwd_key, False, protocol_str
        else:
            # New flow, this is the initiator
            return fwd_key, True, protocol_str
            
    return None, None, None


def evaluate_flow(flow_key, flow, current_time):
    global model, scaler, blocked_ips
    src_ip, dst_ip, src_port, dst_port, protocol_str = flow_key
    total_packets = flow['fwd_packets'] + flow['bwd_packets']
    
    duration_micros = (current_time - flow['start_time']) * 1e6
    duration_secs = max(current_time - flow['start_time'], 1e-9)
    flow_packets_per_sec = total_packets / duration_secs
    fwd_pkt_len_mean = np.mean(flow['fwd_pkt_sizes']) if flow['fwd_pkt_sizes'] else 0.0
    avg_pkt_size = np.mean(flow['all_pkt_sizes']) if flow['all_pkt_sizes'] else 0.0

    feature_vector = [
        flow['dst_port'],
        flow['init_win_bytes_fwd'],
        duration_micros,
        flow['fwd_packets'],
        flow['bwd_packets'],
        flow['fwd_bytes'],
        flow['bwd_bytes'],
        flow_packets_per_sec,
        flow['syn_count'],
        flow['rst_count'],
        fwd_pkt_len_mean,
        avg_pkt_size,
    ]
    
    scaled_features = scaler.transform([feature_vector])
    prediction = model.predict(scaled_features, verbose=0)
    probs = prediction[0]
    predicted_class = np.argmax(probs)
    confidence = float(probs[predicted_class])
    
    # Attack probability is 1.0 minus the benign class probability
    attack_prob = 1.0 - float(probs[0])

    if predicted_class > 0 and confidence >= THRESH_AUTO_BLOCK:
        status = 'AUTO_BLOCKED'
        print(f"[🛡️  AUTO_BLOCKED] Type: {predicted_class} (Conf: {confidence:.2f}) | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        log_alert(src_ip, dst_ip, src_port, dst_port, protocol_str, int(predicted_class), attack_prob, status, confidence)
        block_ip(src_ip)
    elif predicted_class > 0 and confidence >= THRESH_NEEDS_REVIEW:
        status = 'NEEDS_REVIEW'
        print(f"[🔍 NEEDS_REVIEW] Type: {predicted_class} (Conf: {confidence:.2f}) | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        log_alert(src_ip, dst_ip, src_port, dst_port, protocol_str, int(predicted_class), attack_prob, status, confidence)
    else:
        status = 'BENIGN'
        log_alert(src_ip, dst_ip, src_port, dst_port, protocol_str, int(predicted_class), attack_prob, status, confidence)

def process_packet(pkt):
    global flow_table, last_chaos_calc_time
    
    flow_key, is_forward, protocol_str = get_flow_key(pkt)
    if not flow_key:
        return
        
    src_ip, dst_ip, src_port, dst_port, protocol_str = flow_key
    
    # No whitelist: evaluating every packet to test IPS logic
    current_time = time.time()

    # Periodic cleanup of idle flows to prevent mem leak and ensure single-packet attacks are logged!
    if current_time - last_chaos_calc_time >= 5:
        stale_keys = []
        for fk, f in flow_table.items():
            if current_time - f['start_time'] > 5:  # 5s timeout
                stale_keys.append(fk)
        for fk in stale_keys:
            evaluate_flow(fk, flow_table[fk], current_time)
            del flow_table[fk]
        last_chaos_calc_time = current_time
    
    if flow_key not in flow_table:
        init_win_bytes = 0
        if TCP in pkt:
            init_win_bytes = pkt[TCP].window

        flow_table[flow_key] = {
            'start_time': current_time,
            'dst_port': dst_port,
            'init_win_bytes_fwd': init_win_bytes,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'syn_count': 0,
            'rst_count': 0,
            'fwd_pkt_sizes': [],
            'all_pkt_sizes': [],
            'closed': False
        }

    pkt_len = len(pkt[IP].payload) if IP in pkt else 0

    if is_forward:
        flow_table[flow_key]['fwd_packets'] += 1
        flow_table[flow_key]['fwd_bytes'] += pkt_len
        flow_table[flow_key]['fwd_pkt_sizes'].append(pkt_len)
    else:
        flow_table[flow_key]['bwd_packets'] += 1
        flow_table[flow_key]['bwd_bytes'] += pkt_len

    flow_table[flow_key]['all_pkt_sizes'].append(pkt_len)

    if TCP in pkt:
        flags = str(getattr(pkt[TCP], 'flags', 0))
        if 'S' in flags:
            flow_table[flow_key]['syn_count'] += 1
        if 'R' in flags:
            flow_table[flow_key]['rst_count'] += 1
        if 'F' in flags or 'R' in flags:
            flow_table[flow_key]['closed'] = True

    flow = flow_table[flow_key]
    total_packets = flow['fwd_packets'] + flow['bwd_packets']

    if flow['closed'] or total_packets >= MAX_PACKETS:
        evaluate_flow(flow_key, flow, current_time)
        del flow_table[flow_key]

def main():

    global model, scaler
    
    parser = argparse.ArgumentParser(description="Live traffic sniffer for anomaly detection")
    parser.add_argument("--timeout", type=int, default=None, help="Sniffing duration in seconds")
    args = parser.parse_args()

    # Create directories if they don't exist
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    
    print("Initializing Database Logs...")
    init_db()

    print("Loading Brain Models for Analytics...")
    model_path = os.path.join(os.path.dirname(__file__), '../brain/neuralguard_v2.h5')
    scaler_path = os.path.join(os.path.dirname(__file__), '../brain/scaler.pkl')
    
    model = load_model(model_path)
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)

    active_iface = get_active_interface()

    # Force Tailscale to respect local UFW rules
    print("[+] Disabling Tailscale netfilter to enforce local UFW rules...")
    subprocess.run(
        ['sudo', 'tailscale', 'up', '--netfilter-mode=off'],
        capture_output=True, text=True, timeout=15
    )
    print("[+] Tailscale netfilter-mode=off applied.")

    print(f"")
    print(f"══════════════════════════════════════════════════════════")
    print(f"  NeuralGuard IPS v2 — Active Protection Mode")
    print(f"  AUTO_BLOCK threshold : {THRESH_AUTO_BLOCK}")
    print(f"  NEEDS_REVIEW threshold: {THRESH_NEEDS_REVIEW}")
    print(f"  Timeout: {args.timeout}s")
    print(f"══════════════════════════════════════════════════════════")
    try:
        if args.timeout:
            sniff(prn=process_packet, store=False, timeout=args.timeout, iface=["eno1", "tailscale0"])
            print("Completed defined sniffer execution.")
        else:
            sniff(prn=process_packet, store=False, iface=["eno1", "tailscale0"])
    except KeyboardInterrupt:
        print("\nStopping Sniffer Configuration Process...")
        
if __name__ == '__main__':
    main()
