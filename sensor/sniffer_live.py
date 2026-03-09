import asyncio
import time
import sys
import os
import json
from scapy.all import sniff, IP, TCP, conf, L3RawSocket

# Add the project root to sys.path for cross-folder imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.ai_engine import predict_packet
from api import database

# Flow tracking dictionary
active_flows = {}

# Settings cache
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings.json")
last_settings_load = 0
current_settings = {"whitelist": [], "threshold": 0.85}

def load_settings():
    global last_settings_load, current_settings
    current_time = time.time()
    # Reload every 5 seconds to balance performance and freshness
    if current_time - last_settings_load > 5:
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r") as f:
                    current_settings = json.load(f)
                    last_settings_load = current_time
        except Exception as e:
            print(f"Error loading settings: {e}")

# ANSI color codes for printing
RED_ALERT = "\033[91m\033[1m"
GREEN = "\033[92m"
RESET = "\033[0m"

def process_packet(packet):
    """
    Triggers on every captured TCP packet.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    load_settings()
    
    src_ip = packet[IP].src
    dest_ip = packet[IP].dst
    
    # Whitelist check
    if src_ip in current_settings["whitelist"] or dest_ip in current_settings["whitelist"]:
        return

    src_port = packet[TCP].sport
    dest_port = packet[TCP].dport
    window_size = packet[TCP].window

    flow_key = f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
    reverse_key = f"{dest_ip}:{dest_port}-{src_ip}:{src_port}"

    current_time = time.time()

    if flow_key not in active_flows and reverse_key not in active_flows:
        active_flows[flow_key] = {
            'start_time': current_time,
            'init_win_bytes_fwd': window_size,
            'total_fwd_packets': 1,
            'total_bwd_packets': 0,
            'last_duration': 0,
            'is_analyzed': False
        }
    elif flow_key in active_flows:
        flow = active_flows[flow_key]
        flow['total_fwd_packets'] += 1
        flow['last_duration'] = int((current_time - flow['start_time']) * 1000000)
    else:
        flow = active_flows[reverse_key]
        flow['total_bwd_packets'] += 1
        flow['last_duration'] = int((current_time - flow['start_time']) * 1000000)
        flow_key = reverse_key

    flow = active_flows[flow_key]
    total_packets = flow['total_fwd_packets'] + flow['total_bwd_packets']

    if total_packets >= 5 and not flow['is_analyzed']:
        f_dest_port = dest_port
        f_init_win = flow['init_win_bytes_fwd']
        f_duration = flow['last_duration']
        f_fwd_pkts = flow['total_fwd_packets']
        f_bwd_pkts = flow['total_bwd_packets']

        # Pass features to AI Engine
        verdict, score = predict_packet(f_init_win, f_dest_port, f_duration, f_fwd_pkts, f_bwd_pkts)

        # Apply dynamic threshold from settings
        dynamic_threshold = current_settings.get("threshold", 0.85)
        is_malicious = score > dynamic_threshold

        if is_malicious:
            print(f"\n{RED_ALERT}!!! NEURALGUARD ALERT: MALICIOUS TRAFFIC DETECTED !!!{RESET}")
            print(f"Flow: {src_ip} -> {dest_ip} | Type: TCP | Score: {score:.4f} (Threshold: {dynamic_threshold})")
            
            try:
                asyncio.run(database.log_alert(src_ip, dest_ip, f_init_win, score, 1))
            except Exception as e:
                print(f"Error logging to database: {e}")

        flow['is_analyzed'] = True

async def start_sniffing():
    print("NeuralGuard Live Sniffer Starting...")
    print(f"Monitoring TCP on tailscale0 with dynamic threshold and whitelist...")
    conf.L3socket = L3RawSocket
    sniff(iface='tailscale0', prn=process_packet, store=False, filter="tcp")

if __name__ == "__main__":
    try:
        asyncio.run(database.init_db())
        asyncio.run(start_sniffing())
    except KeyboardInterrupt:
        print("\nStopping Live Sniffer...")
    except PermissionError:
        print(f"\n{RED_ALERT}Error: Permission Denied.{RESET}")
    except Exception as e:
        print(f"An error occurred: {e}")
