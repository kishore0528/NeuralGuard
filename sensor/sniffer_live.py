import asyncio
import time
import sys
import os
from scapy.all import sniff, IP, TCP

# Add the project root to sys.path for cross-folder imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.ai_engine import predict_packet
from api import database

# Flow tracking dictionary
# Key: "SrcIP:SrcPort-DstIP:DstPort"
active_flows = {}

# ANSI color codes for printing
RED_ALERT = "\033[91m\033[1m"
RESET = "\033[0m"

def process_packet(packet):
    """
    Triggers on every captured TCP packet.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dest_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dest_port = packet[TCP].dport
    window_size = packet[TCP].window

    # Create a flow key (directional)
    flow_key = f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
    reverse_key = f"{dest_ip}:{dest_port}-{src_ip}:{src_port}"

    current_time = time.time()

    if flow_key not in active_flows and reverse_key not in active_flows:
        # New flow initialization
        active_flows[flow_key] = {
            'start_time': current_time,
            'init_win_bytes_fwd': window_size,
            'total_fwd_packets': 1,
            'total_bwd_packets': 0,
            'last_duration': 0,
            'is_analyzed': False
        }
        # In this context, we treat the first packet as Forward
    elif flow_key in active_flows:
        # Existing Forward flow
        flow = active_flows[flow_key]
        flow['total_fwd_packets'] += 1
        flow['last_duration'] = int((current_time - flow['start_time']) * 1000000) # Microseconds
    else:
        # Existing Backward flow
        flow = active_flows[reverse_key]
        flow['total_bwd_packets'] += 1
        flow['last_duration'] = int((current_time - flow['start_time']) * 1000000) # Microseconds
        flow_key = reverse_key # Use the primary key for consistency

    # Once a flow hits at least 5 total packets, analyze it
    flow = active_flows[flow_key]
    total_packets = flow['total_fwd_packets'] + flow['total_bwd_packets']

    if total_packets >= 5 and not flow['is_analyzed']:
        # Extract the 5 required features
        # [Destination Port, Init_Win_bytes_forward, Flow Duration, Total Fwd Packets, Total Backward Packets]
        f_dest_port = dest_port
        f_init_win = flow['init_win_bytes_fwd']
        f_duration = flow['last_duration']
        f_fwd_pkts = flow['total_fwd_packets']
        f_bwd_pkts = flow['total_bwd_packets']

        # Pass features to AI Engine
        verdict, score = predict_packet(f_init_win, f_dest_port, f_duration, f_fwd_pkts, f_bwd_pkts)

        if verdict == 1:
            # Massive RED alert for malicious traffic
            print(f"\n{RED_ALERT}!!! NEURALGUARD ALERT: MALICIOUS TRAFFIC DETECTED !!!{RESET}")
            print(f"Flow: {src_ip} -> {dest_ip} | Type: TCP | Score: {score:.4f}")
            print(f"Features: Port={f_dest_port}, Win={f_init_win}, Dur={f_duration}, Pkts={f_fwd_pkts}/{f_bwd_pkts}\n")
            
            # Save alert to the database
            try:
                # database.log_alert is an async function
                asyncio.run(database.log_alert(src_ip, dest_ip, f_init_win, score, 1))
            except Exception as e:
                print(f"Error logging to database: {e}")

        # Mark as analyzed to avoid repeated alerts for the same flow
        flow['is_analyzed'] = True

async def start_sniffing():
    print("NeuralGuard Live Sniffer Starting...")
    print("Monitoring live TCP traffic and tracking network flows...")
    # sniff is a blocking call
    # Replace 'tailscale0' if your interface name was different in 'ip addr'
    sniff(iface='tailscale0', prn=process_packet, store=False)

if __name__ == "__main__":
    try:
        # Initialize database first
        asyncio.run(database.init_db())
        asyncio.run(start_sniffing())
    except KeyboardInterrupt:
        print("\nStopping Live Sniffer...")
    except PermissionError:
        print(f"\n{RED_ALERT}Error: Permission Denied.{RESET}")
        print("Please run this script with Administrative/Sudo privileges to capture network packets.")
    except Exception as e:
        print(f"An error occurred: {e}")
