# 🛡️ NeuralGuard Enterprise IPS

> **An AI-powered Intrusion Prevention System** that sniffs live network traffic, classifies attacks in real-time using a trained Keras neural network, autonomously blocks threats via the system firewall, and visualises everything on a live Grafana SOC dashboard.

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Architecture](#-architecture)
3. [Attack Classification](#-attack-classification)
4. [Prerequisites](#-prerequisites)
5. [Installation](#-installation)
6. [Running the System](#-running-the-system)
7. [Simulating an Attack](#-simulating-an-attack)
8. [Automated Combat Test](#-automated-combat-test-zero-intervention)
9. [Grafana SOC Dashboard](#-grafana-soc-dashboard)
10. [Tools & Utilities](#-tools--utilities)
11. [Project Structure](#-project-structure)
12. [Configuration](#-configuration)
13. [Stopping the System](#-stopping-the-system)
14. [Training the Model](#-training-the-model)
15. [Troubleshooting](#-troubleshooting)

---

## 🔍 Project Overview

NeuralGuard is a full-stack **Intrusion Prevention System (IPS)** built for enterprise network security research. It operates as an autonomous cyber-defence pipeline:

```
Live Traffic → Scapy Sniffer → Feature Extraction → Neural Network → IPS Decision
                                                                         │
                                                    ┌────────────────────┤
                                                    ▼                    ▼
                                             AUTO_BLOCKED          NEEDS_REVIEW
                                            (UFW firewall)      (SOC analyst queue)
                                                    │                    │
                                                    └────────────────────┘
                                                                 │
                                                         Grafana Dashboard
```

**Key capabilities:**
- 🧠 **AI Classification** — Keras MLP neural network trained on the CIC-IDS-2017 dataset
- 🛡️ **Autonomous Blocking** — High-confidence threats are blocked via `ufw` at priority 1 with zero human input
- 🔍 **Analyst Queue** — Medium-confidence threats are routed to a SOC review queue
- 📊 **Live Dashboard** — Real-time Grafana SOC command centre backed by PostgreSQL
- 🖥️ **IP Manager API** — Flask REST API to manage blocked IPs and trigger unblocks from the dashboard

---

## 🏗️ Architecture

| Component | Technology | Role |
|-----------|-----------|------|
| **Sniffer IPS** | Python + Scapy + Keras | Live packet capture, flow aggregation, AI inference, firewall control |
| **Neural Network** | Keras (TensorFlow backend) | Multi-class attack classification |
| **Database** | PostgreSQL 15 (Docker) | Persistent alert storage and IP management |
| **Dashboard** | Grafana (Docker) | Real-time SOC visualisation |
| **IP Manager API** | Flask (Python) | REST API for IP management and unblocking |
| **Firewall** | UFW (Uncomplicated Firewall) | Layer-3 IP blocking at rule priority 1 |
| **Orchestration** | Docker Compose | PostgreSQL + Grafana lifecycle management |

---

## 🎯 Attack Classification

The neural network classifies each network flow into one of **5 classes**:

| Class | Label | IPS Action |
|-------|-------|-----------|
| `0` | **Benign** | Logged only |
| `1` | **DoS / DDoS** | Block if conf ≥ 90%, Review if conf ≥ 75% |
| `2` | **PortScan** | Block if conf ≥ 90%, Review if conf ≥ 75% |
| `3` | **Brute Force** | Block if conf ≥ 90%, Review if conf ≥ 75% |
| `4` | **Other Attack** | Block if conf ≥ 90%, Review if conf ≥ 75% |

### IPS Tri-State Decision Logic

```
Confidence ≥ 90%  →  AUTO_BLOCKED  →  ufw insert 1 deny from <IP>
Confidence ≥ 75%  →  NEEDS_REVIEW  →  Analyst queue (Grafana panel)
Confidence < 75%  →  BENIGN        →  Logged only
```

### Feature Vector (12 features extracted per flow)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `dst_port` | Destination port |
| 2 | `init_win_bytes_fwd` | Initial TCP window size |
| 3 | `duration_micros` | Flow duration in microseconds |
| 4 | `fwd_packets` | Forward packet count |
| 5 | `bwd_packets` | Backward packet count |
| 6 | `fwd_bytes` | Forward byte count |
| 7 | `bwd_bytes` | Backward byte count |
| 8 | `flow_packets_per_sec` | Packets per second |
| 9 | `syn_count` | SYN flag count |
| 10 | `rst_count` | RST flag count |
| 11 | `fwd_pkt_len_mean` | Mean forward packet length |
| 12 | `avg_pkt_size` | Mean packet size |

---

## 📦 Prerequisites

### System Requirements
- **OS:** Linux (Ubuntu 20.04+ recommended)
- **RAM:** 4 GB minimum (8 GB recommended)
- **Privileges:** `sudo` access required (for packet capture and UFW)

### Software Dependencies

```bash
# Core
sudo apt install -y docker.io docker-compose ufw python3 python3-pip python3-venv

# Network tools (for attack simulation)
sudo apt install -y nmap hping3
```

### Python Packages (managed via venv)
```
scapy          # Packet capture and crafting
tensorflow     # Neural network inference
keras          # Model loading
psycopg2       # PostgreSQL driver
scikit-learn   # Feature scaling
flask          # IP Manager REST API
numpy          # Numerical operations
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/neuralguard_enterprise.git
cd neuralguard_enterprise
```

### 2. Create Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install scapy tensorflow keras psycopg2-binary scikit-learn flask numpy
```

### 3. Verify model files exist

```bash
ls brain/
# Expected output:
# neuralguard_v2.h5   scaler.pkl
```

> ⚠️ The model files (`*.h5`, `*.pkl`) are **not included in the repo** (too large / binary).  
> Train them yourself using `train_v2.py` or contact the project maintainer.

### 4. Configure environment

```bash
cp .env.example .env   # edit if needed
```

Default credentials (configured in `docker-compose.yml`):
- **PostgreSQL:** `admin` / `adminpassword` on port `5432`
- **Grafana:** `admin` / `admin` on port `3000`

---

## ▶️ Running the System

### Option A — Full Stack (recommended)

Starts Docker services + IP Manager API + Sniffer IPS in one command:

```bash
sudo ./start.sh
```

This launches:
1. 🐘 **PostgreSQL** on `:5432`
2. 📊 **Grafana** on `:3000`
3. 🌐 **IP Manager API** on `:5001`
4. 🔍 **AI Sniffer IPS** (live capture on `eno1` + `tailscale0`)

### Option B — Manual (component by component)

```bash
# 1. Start Docker services
docker compose up -d

# 2. Start IP Manager API
.venv/bin/python tools/ip_manager_api.py &

# 3. Start Sniffer IPS (requires sudo)
sudo .venv/bin/python sensor/sniffer.py
```

### Option C — Sniffer with timeout (for testing)

```bash
sudo .venv/bin/python sensor/sniffer.py --timeout 120
```

---

## ⚔️ Simulating an Attack

### Quick Attack (manual)

```bash
sudo ./attack.sh [TARGET_IP]
# Default target: 192.168.41.158
```

This runs `tests/simulate_attacks.py` with an optional DB reset prompt.

### Advanced Attack Simulator (direct)

```bash
sudo .venv/bin/python tests/simulate_attacks.py --target <TARGET_IP>
```

#### Attack Modules

| Module | Type | Packets | Technique |
|--------|------|---------|-----------|
| 1 | **PortScan** | 100 | SYN sweep across 100 ports from 1 attacker |
| 2 | **DDoS Botnet** | 500 | 50 spoofed botnet IPs hammering port 80 |
| 3 | **SSH Brute Force** | 200 | 10 attackers rapid-SYN-flooding port 22 |
| 4 | **Blitzkrieg** | 400 | 20 IPs mixed attack types simultaneously |

**Flags:**
```bash
--target 192.168.1.100   # Target IP (default: 192.168.41.158)
--delay 0.01             # Inter-packet delay in seconds (default: 0.005)
--no-spoof               # Disable IP spoofing (use real source IP)
```

> ⚠️ Scapy requires **root/sudo** to send raw packets.

---

## 🤖 Automated Combat Test (Zero Intervention)

The flagship script — runs the entire attack simulation with **zero manual intervention**:

```bash
sudo ./combat_test.sh [TARGET_IP]
```

### What it does automatically:

| Step | Action |
|------|--------|
| 1 | ✅ Verifies prerequisites (venv, model, Docker) |
| 2 | ✅ Starts Docker services if not running |
| 3 | ✅ Starts IP Manager API if not running |
| 4 | ✅ **Resets database** to clean slate (`--force`, no prompt) |
| 5 | ✅ Starts AI Sniffer, waits for model warmup |
| 6 | ✅ **Opens Grafana** dashboard in browser (auto-refresh 5s) |
| 7 | ✅ Fires **1,200+ packet** 4-module attack simulation |
| 8 | ✅ Waits 10s for AI pipeline to flush remaining flows |
| 9 | ✅ Prints **live DB summary** (counts by status + top offending IPs) |
| 10 | ✅ Tails sniffer log for final verdict |

### Expected terminal output

```
[STEP 4] Resetting database for clean combat test…
  ✓  Database wiped — alerts & ip_management tables cleared

[STEP 7] Launching 4-module combat attack simulation…

[MODULE 1] PortScan  ←  attacker: 172.21.40.146  →  target: 192.168.41.158
  [██████████████████████████████] 100/100  ✓

[MODULE 2] DDoS Botnet Burst  →  target: 192.168.41.158:80
  [██████████████████████████████] 500/500  ✓

[MODULE 3] SSH Brute Force  →  target: 192.168.41.158:22
  [██████████████████████████████] 200/200  ✓

[MODULE 4] BLITZKRIEG  →  target: 192.168.41.158
  [██████████████████████████████] 400/400  ✓

[STEP 9] Querying database for combat results…
  ┌──────────────────┬────────┬──────────┬──────────┐
  │ Status           │  Count │ Avg Conf │ Max Conf │
  ├──────────────────┼────────┼──────────┼──────────┤
  │ AUTO_BLOCKED     │    312 │    0.912 │    1.000 │
  │ NEEDS_REVIEW     │     58 │    0.863 │    0.899 │
  │ BENIGN           │    120 │    0.210 │    0.740 │
  └──────────────────┴────────┴──────────┴──────────┘
```

---

## 📊 Grafana SOC Dashboard

**URL:** `http://localhost:3000`  
**Login:** `admin` / `admin`  
**Dashboard:** NeuralGuard IPS Command Center

### Dashboard Panels

| Panel | Type | Description |
|-------|------|-------------|
| **Chaos Score** | Gauge | Real-time attack probability (latest flow confidence, 0–1) |
| **🔥 Top 5 Offending IPs** | Bar Gauge | Most active attacker IPs by alert count |
| **📈 Alerts per Minute** | Time Series | Alert volume over time (spikes during attacks) |
| **🎯 Attack Type Distribution** | Donut Chart | Breakdown: DDoS / PortScan / BruteForce / Other |
| **🛡️ IP Management** | Table | Blocked IPs with timestamp + click-to-unblock link |
| **Active Threats Auto-Blocked** | Table | All `AUTO_BLOCKED` alerts with confidence scores |
| **Analyst Review Queue** | Table | All `NEEDS_REVIEW` alerts awaiting SOC action |
| **Benign Traffic** | Table | Classified-safe flows (for baseline comparison) |

### Recommended Dashboard Settings

- **Time range:** Last 5 minutes (`now-5m`)
- **Auto-refresh:** 5 seconds
- **Grafana URL with optimal settings:**
  ```
  http://localhost:3000/d/postgres_ips_dash_005/neuralguard-ips-command-center?orgId=1&refresh=5s&from=now-5m&to=now
  ```

### Unblocking an IP from the Dashboard

In the **IP Management** table, click any IP address link — it calls:
```
http://localhost:5001/api/unblock/<IP_ADDRESS>
```
This removes the UFW rule and updates the database record.

---

## 🛠️ Tools & Utilities

### Reset Database

Wipes `alerts` and `ip_management` tables and resets ID counters:

```bash
# Interactive (asks for confirmation)
.venv/bin/python tools/reset_db.py

# Non-interactive (for automation)
.venv/bin/python tools/reset_db.py --force
```

### SOC Analyst CLI

Interactive terminal UI for managing the analyst review queue:

```bash
.venv/bin/python tools/soc_analyst_cli.py
```

Features:
- List all `NEEDS_REVIEW` alerts
- Approve/dismiss individual alerts
- Bulk block/allow IPs

### IP Manager API

REST API running on `:5001`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | API health check |
| `/api/blocked` | GET | List all blocked IPs |
| `/api/block/<ip>` | POST | Block an IP manually |
| `/api/unblock/<ip>` | GET | Unblock an IP (also called from Grafana) |

### Evaluate Baseline

Runs the model against a held-out test set (from `raw_data/`) and prints metrics:

```bash
.venv/bin/python brain/evaluate.py
```

---

## 📁 Project Structure

```
neuralguard_enterprise/
│
├── 🔑 Entry Points
│   ├── start.sh              # Start all services (Docker + API + Sniffer)
│   ├── stop.sh               # Gracefully stop all services
│   ├── attack.sh             # Quick attack simulation launcher
│   └── combat_test.sh        # Fully automated combat test (zero intervention)
│
├── 🧠 brain/
│   ├── train.py              # Model training script (CIC-IDS-2017 dataset)
│   ├── evaluate.py           # Model evaluation / accuracy report
│   ├── neuralguard_v2.h5     # Trained Keras model [NOT in git — too large]
│   └── scaler.pkl            # Fitted StandardScaler [NOT in git]
│
├── 📡 sensor/
│   └── sniffer.py            # Core IPS: packet capture → AI inference → UFW block
│
├── 🧪 tests/
│   └── simulate_attacks.py   # 4-module attack simulator (PortScan/DDoS/BruteForce/Blitz)
│
├── 🛠️ tools/
│   ├── reset_db.py           # Database wipe utility (supports --force)
│   ├── soc_analyst_cli.py    # Interactive SOC analyst terminal UI
│   └── ip_manager_api.py     # Flask REST API for IP management
│
├── 📊 grafana/
│   ├── dashboards/
│   │   └── postgres_ips_dashboard.json   # Grafana dashboard definition
│   └── provisioning/         # Auto-provisioned datasource + dashboard configs
│
├── 🐳 docker-compose.yml     # PostgreSQL + Grafana containers
├── 🤖 train.py            # Link to brain/train.py (optional)
├── 📈 evaluate.py         # Link to brain/evaluate.py (optional)
├── 📦 data/                  # Docker volume mounts (postgres + grafana data)
├── 📋 logs/                  # Runtime logs (sniffer.log, ip_manager_api.log)
└── 🔧 .env                   # Environment variables (DB credentials, etc.)
```

---

## ⚙️ Configuration

### IPS Thresholds (`sensor/sniffer.py`)

```python
THRESH_AUTO_BLOCK  = 0.90   # ≥ 90% confidence → AUTO_BLOCKED + UFW deny
THRESH_NEEDS_REVIEW = 0.75  # ≥ 75% confidence → NEEDS_REVIEW (analyst queue)
                             # < 75% confidence → BENIGN (log only)
```

### Database DSN

```python
DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"
```

Configured in: `sensor/sniffer.py`, `tools/reset_db.py`, `tools/ip_manager_api.py`

### Network Interfaces (`sensor/sniffer.py`)

```python
sniff(iface=["eno1", "tailscale0"], ...)
```

Edit this line to match your active network interfaces. Auto-detection is also available.

### Flow Parameters

```python
MAX_PACKETS = 10    # Evaluate flow after this many packets
# Flows also evaluated after 5s of inactivity (stale flow timeout)
```

---

## 🛑 Stopping the System

```bash
sudo ./stop.sh
```

This will:
1. Kill the sniffer process (from saved PID)
2. Kill the IP Manager API process
3. Stop Docker containers (PostgreSQL + Grafana)
4. Optionally remove dangling UFW rules

---

## 🤖 Training the Model

The model was trained on the **CIC-IDS-2017** intrusion detection dataset.

```bash
# Place raw CSV files in raw_data/
.venv/bin/python brain/train.py
```

Output files saved to `brain/`:
- `neuralguard_v2.h5` — Trained Keras model
- `scaler.pkl` — Fitted StandardScaler

### Model Architecture

```
Input (12 features)
  → Dense(128, relu) + BatchNorm + Dropout(0.3)
  → Dense(64, relu)  + BatchNorm + Dropout(0.3)
  → Dense(32, relu)
  → Dense(5, softmax)   ← 5 output classes
```

---

## 🔧 Troubleshooting

### Sniffer not detecting packets
- Ensure you're running with `sudo`
- Check your interface names: `ip link show`
- Update `iface=["eno1", "tailscale0"]` in `sniffer.py` to match your interfaces

### PostgreSQL connection refused
```bash
docker compose up -d         # Restart Docker services
docker ps                    # Check container status
```

### UFW rules not applying
```bash
sudo ufw status              # Check UFW is enabled
sudo ufw enable              # Enable if inactive
```

### Grafana dashboard not loading
```bash
# Check provisioning files exist
ls grafana/provisioning/datasources/
ls grafana/provisioning/dashboards/

# Restart Grafana container
docker restart neural_grafana
```

### Model file missing
```bash
ls brain/
# If empty → train the model or contact maintainer for pre-trained weights
```

### "Permission denied" on attack simulation
```bash
# Scapy requires root to craft raw packets
sudo .venv/bin/python tests/simulate_attacks.py --target <IP>
```

---

## 📄 License

This project is released for **academic and research purposes only**.  
Do not use the attack simulation tools against systems you do not own.

---

## 👤 Author

Built as a final-year/capstone project demonstrating AI-driven autonomous network security.

- **Stack:** Python · Keras/TensorFlow · Scapy · PostgreSQL · Grafana · Docker · UFW
- **Dataset:** CIC-IDS-2017 (Canadian Institute for Cybersecurity)

---

*NeuralGuard IPS — Because your network shouldn't need a human to defend itself.*
