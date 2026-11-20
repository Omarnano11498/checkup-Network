# TP-Link TL-SG2218 Switch Monitor

A Python script that checks network and switch health, monitors per-port traffic over SSH, finds the busiest port, and can optionally capture that port's traffic through port mirroring.

---

## Files

| File | Purpose |
|---|---|
| `switch_monitor.py` | Main script (logic only) |
| `config.json` | All settings: switch address, thresholds, monitoring intervals, CLI commands |
| `reports/` | Created automatically: JSON reports, Word reports, CSV log, pcap files, raw output |

---

## Features

- **Switch health:** CPU, memory, uptime, per-port status, port errors.
- **Alerts:** high CPU or memory, ports with errors, ports running Half-Duplex, ports linked below 1G.
- **Network health:** parallel ping to the gateway, the switch and configured targets (packet loss and average latency).
- **Traffic monitoring:** Rx/Tx in Mbps and utilization per port, sorted busiest first, with heavy ports marked 🔥.
- **Traffic capture (optional):** mirrors the busiest port to your PC's port and captures it with `tshark` into a pcap file, with a summary of top talkers and protocols.
- **Full network discovery (`--scan`):** pings every address in the subnet, then maps each device (IP ↔ MAC ↔ switch port) using the switch's MAC and ARP tables, with hostnames, and flags the gateway, your PC, and ports with another switch or access point behind them (uplinks).
- **Cable diagnostics (`--cables`):** TDR test on every copper port: OK, short, open pair with the approximate distance to the fault, impedance mismatch, cable OK but device off, or no cable. Skips the management port (where your PC is connected) and SFP ports automatically.
- **Word report:** every run also produces a `.docx` report with color-coded tables.
- **Repeated runs:** `--watch` mode repeats the check every N seconds.

---

## Requirements

- Python 3.8 or later
- An SSH library:
  ```bash
  pip install netmiko        # preferred
  # or, as a fallback:
  pip install paramiko
  ```
- For the Word report:
  ```bash
  pip install python-docx
  ```
- Optional, for capture:
  ```bash
  sudo apt install tshark
  ```
- On the switch: enable SSH in the web UI under **Security → SSH Config**.

---

## Setup

Open `config.json` and edit the values:

```json
{
  "switch":     { "host": "192.168.1.110", "port": 22, "username": "", "password": "", "enable_password": "", "timeout": 20 },
  "network":    { "gateway": "192.168.1.1", "ping_targets": ["192.168.1.1", "8.8.8.8"], "subnet": "192.168.1.0/24" },
  "cables":     { "ports": "all", "exclude": [], "skip_mgmt_port": true, "skip_fiber": true, "max_length_m": 100 },
  "thresholds": { "heavy_util_pct": 70.0, "cpu_warn_pct": 80.0, "mem_warn_pct": 85.0 },
  "monitoring": { "interval_sec": 10, "samples": 3, "top_ports": 18, "watch_sec": 0 },
  "mirror":     { "session": 1, "dest_port": "", "keep_mirror": false },
  "capture":    { "iface": "", "duration_sec": 60 },
  "output":     { "out_dir": "reports", "csv_file": "traffic_log.csv", "docx": true },
  "commands":   { "sysinfo": "show system-info", "cpu": "show cpu-utilization", "...": "..." }
}
```

### Sections

| Section | Key | Meaning |
|---|---|---|
| `switch` | `host`, `port` | Switch address and SSH port |
| | `username`, `password`, `enable_password` | Login credentials (best left empty; use environment variables) |
| `network` | `gateway`, `ping_targets` | Gateway and addresses to check connectivity to |
| | `subnet`, `scan_workers` | Subnet to scan (empty = /24 of the gateway) and number of parallel pings |
| | `resolve_names`, `uplink_mac_threshold` | Look up hostnames; number of MACs on a port for it to count as an uplink |
| `cables` | `ports`, `exclude` | Ports to test (`all` or a list) and ports to exclude |
| | `skip_mgmt_port`, `skip_fiber`, `max_length_m` | Skip the management port and fiber ports; maximum cable length |
| `thresholds` | `heavy_util_pct` | Utilization at which a port counts as heavy |
| | `cpu_warn_pct`, `mem_warn_pct` | CPU and memory alert thresholds |
| `monitoring` | `interval_sec`, `samples` | Interval between samples and number of samples |
| | `top_ports` | Number of ports shown in the table |
| | `watch_sec` | Repeat every N seconds (0 = run once) |
| `mirror` | `dest_port` | Capture PC's port, e.g. `1/0/16` (empty = no mirroring) |
| | `keep_mirror` | Keep the mirror session after finishing |
| `capture` | `iface`, `duration_sec` | Local capture interface and duration |
| `output` | `out_dir`, `csv_file`, `docx` | Reports folder, CSV log name, and whether to write the Word report |
| `commands` | — | CLI commands; edit them if they differ on your firmware version |

### Credentials, safely

Don't store the password in `config.json`. Use environment variables:

```bash
export SW_USER=admin
export SW_PASS='your_password'
export SW_ENABLE='enable_password'   # if any
```

PowerShell:

```powershell
$env:SW_USER="admin"; $env:SW_PASS="your_password"
```

If they aren't set anywhere, the script asks for them at startup.

### Settings priority

```
command-line options  >  environment variables  >  config.json  >  built-in fallbacks
```

---

## Usage

```bash
# Full check (default)
python3 switch_monitor.py

# Discover all devices and map them to ports + test all cables
python3 switch_monitor.py --scan --cables

# Test cables on specific ports only (includes the management port if listed explicitly)
python3 switch_monitor.py --cables --cable-ports 1/0/3,1/0/7

# Scan a different subnet
python3 switch_monitor.py --scan --subnet 192.168.10.0/24

# Health check only
python3 switch_monitor.py --health

# Monitor traffic and show the top 5 ports
python3 switch_monitor.py --traffic --interval 10 --samples 3 --top 5

# Continuous monitoring every 5 minutes
python3 switch_monitor.py --all --watch 300

# Monitor + mirror the busiest port to port 16 + capture for 60 seconds
sudo -E python3 switch_monitor.py --traffic --mirror-dest 1/0/16 --capture-iface eth0 --capture-secs 60

# Use a different config file
python3 switch_monitor.py --config /etc/netmon/site-a.json
```

### All options

| Option | Description |
|---|---|
| `--config` | Path to the config file (default: `config.json` next to the script) |
| `--health` / `--traffic` / `--scan` / `--cables` / `--all` | Check type (`--all` = everything, the default) |
| `--cable-ports 1/0/3,1/0/7` | Test cables on specific ports only |
| `--subnet 192.168.1.0/24` | Subnet to scan |
| `--host`, `--port`, `--user`, `--password`, `--enable-pass` | Connection details |
| `--ping IP ...` | Connectivity check targets |
| `--interval`, `--samples`, `--top`, `--heavy` | Monitoring settings |
| `--mirror-dest`, `--keep-mirror` | Port mirroring |
| `--capture-iface`, `--capture-secs` | Packet capture |
| `--watch N` | Repeat every N seconds |
| `--dump-raw` | Save raw switch output for parser troubleshooting |

---

## Sample output

```
🖥  CPU=12.0%  MEM=40.0%  Uptime=3 days
🔌 Ports up: 9  |  down: 9
  ⚠ Port Gi1/0/7 linked at low speed 100M (likely a damaged cable pair or a 100M NIC)

Port     Link     Rx Mbps   Tx Mbps     Total  Speed   Util%   Err
------------------------------------------------------------------
Gi1/0/1  up        812.40     95.12    907.52   1000    81.2     0  🔥
Gi1/0/5  up        120.33     40.01    160.34   1000    12.0     0

🏆 Busiest port: Gi1/0/1  (907.52 Mbps, 81.2%) — 🔥 heavy
```

---

## Report files (`reports/`)

| File | Contents |
|---|---|
| `report_YYYYMMDD_HHMMSS.json` | Full report for each run |
| `report_YYYYMMDD_HHMMSS.docx` | The same report as a Word file with color-coded tables (requires `pip install python-docx`) |
| `report.docx` | Copy of the latest Word report (replaced on every run) |
| `traffic_log.csv` | Cumulative log of port readings (good for Excel or charts) |
| `capture_*.pcapng` | Captured packets (open in Wireshark) |
| `raw_*.txt` | Raw command output (with `--dump-raw`) |

---

## Important notes

- **Output format:** command output can differ between firmware versions. If you see zeros or wrong numbers, run with `--dump-raw` and review the raw file to tune the parser or the commands in `config.json`.
- **Cable tests:** on some devices a TDR test can drop the port's link for a few seconds, so the management port is skipped automatically. If you run the scan from a PC that isn't directly connected to the switch, add the uplink port to `cables.exclude`.
- **Scanning requires your PC to be on the same subnet** so the local ARP table gets populated; otherwise only the switch's `show arp` data is used.
- **Port mirroring:** `dest_port` must be the port your capture PC is actually connected to, and must not be the management port you reach the switch through. Try it first at a time when a brief outage won't hurt.
- **Permissions:** `tshark` usually needs `sudo` or membership in the `wireshark` group.
- **Measurement accuracy:** figures are averages over the interval; very short peaks may not show. For permanent, precise monitoring, enable SNMP on the switch and use Zabbix or LibreNMS.

---

## Scheduled runs (optional)

### Linux — cron every 15 minutes
```bash
*/15 * * * * cd /opt/netmon && SW_USER=admin SW_PASS='xxx' /usr/bin/python3 switch_monitor.py --all >> monitor.log 2>&1
```

### Windows — Task Scheduler
```
Program: python.exe
Arguments: C:\netmon\switch_monitor.py --all
Start in: C:\netmon
```
