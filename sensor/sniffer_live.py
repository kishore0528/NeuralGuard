import os
import time
import asyncio
from scapy.all import sniff, conf, L3RawSocket, IP, TCP
from brain import ai_engine
from api import database

# IMPORTANT: Force Scapy to use Layer 3 Raw Sockets for Tailscale/VPN compatibility
conf.L3socket = L3RawSocket

print("🔍 NeuralGuard Live Guard starting...")
print("📡 Listening on 'tailscale0' for TCP traffic...")

def process_packet(packet):
    # Check if the packet has IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dest_port = tcp_layer.dport
        window_size = tcp_layer.window

        # Get prediction from our Deep Learning model
        # Passing 0 for duration and 1 for pkts since it's a single-packet check for now
        is_bot, confidence = ai_engine.predict_packet(window_size, dest_port, 0, 1, 0)
        
        if is_bot:
            print(f"🚨 [ALERT] {src_ip} -> {dest_ip} | Port: {dest_port} | Conf: {confidence:.2f}")
            # Log to SQLite
            try:
                asyncio.run(database.log_alert(src_ip, dest_ip, window_size, confidence, "MALICIOUS"))
            except Exception as e:
                print(f"Database error: {e}")
        else:
            # Optional: Print benign traffic for debugging
            # print(f"✅ [SAFE] {src_ip} -> {dest_ip} | Port: {dest_port}")
            pass

# Run with sudo to access tailscale0
try:
    sniff(iface="tailscale0", prn=process_packet, store=False, filter="tcp")
except PermissionError:
    print("❌ Error: You MUST run this script with 'sudo'!")
except Exception as e:
    print(f"❌ Error: {e}")