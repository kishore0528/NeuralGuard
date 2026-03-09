import asyncio
import random
import sys
import os
import pandas as pd
import numpy as np

# Add the project root to sys.path for cross-folder imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.ai_engine import predict_packet
from api.database import log_alert

# ANSI color codes for printing
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def load_replay_data():
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "Tuesday-WorkingHours.pcap_ISCX.csv")
    if not os.path.exists(data_path):
        print(f"{RED}Error: Dataset not found at {data_path}{RESET}")
        sys.exit(1)

    print(f"{YELLOW}Loading replay data...{RESET}")
    df = pd.read_csv(data_path)
    
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Separate into attacks and benign
    attacks = df[df['Label'] != 'BENIGN'].copy()
    benign = df[df['Label'] == 'BENIGN'].copy()
    
    print(f"Loaded {len(attacks)} attack samples and {len(benign)} benign samples.")
    return attacks, benign

async def replay_engine_loop():
    attacks_df, benign_df = load_replay_data()
    
    print(f"{GREEN}Traffic Replay Engine Started! (5 Features Mode){RESET}")
    
    while True:
        # 50% chance to pick from attack pool or benign pool
        is_actual_attack = random.random() < 0.5
        source_pool = attacks_df if is_actual_attack else benign_df
        ground_truth = "ATTACK" if is_actual_attack else "BENIGN"
        
        # Pick a random row
        row = source_pool.sample(n=1).iloc[0]
        
        # Extract 5 features
        src_port = int(row['Destination Port'])
        window_size = int(row['Init_Win_bytes_forward'])
        flow_duration = int(row['Flow Duration'])
        total_fwd = int(row['Total Fwd Packets'])
        total_bwd = int(row['Total Backward Packets'])
        
        # Generate fake IPs for visual logging
        src_ip = f"192.168.1.{random.randint(10, 254)}"
        dest_ip = f"10.0.0.{random.randint(1, 50)}"

        # Get prediction from AI Engine (Using 5 features)
        verdict, score = predict_packet(window_size, src_port, flow_duration, total_fwd, total_bwd)

        # Log to Database
        await log_alert(src_ip, dest_ip, window_size, score, int(verdict))

        # Determine if AI matched Reality
        match_status = "MATCH" if (verdict == 1 and is_actual_attack) or (verdict == 0 and not is_actual_attack) else "MISMATCH"
        match_color = GREEN if match_status == "MATCH" else RED
        
        # Console logging
        truth_label = f"{RED}[TRUE: {ground_truth}]{RESET}" if is_actual_attack else f"{GREEN}[TRUE: {ground_truth}]{RESET}"
        pred_label = f"{RED}[PRED: MALICIOUS]{RESET}" if verdict == 1 else f"{GREEN}[PRED: BENIGN]{RESET}"
        
        print(f"{truth_label} -> {pred_label} | {match_color}{match_status}{RESET}")
        print(f"      Data: {src_ip} -> {dest_ip} | Window: {window_size} | Fwd/Bwd Pkts: {total_fwd}/{total_bwd} | Confidence: {score:.4f}\n")

        # Wait for 1 second
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(replay_engine_loop())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Stopping Replay Engine...{RESET}")
