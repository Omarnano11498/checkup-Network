#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
switch_monitor.py — Network health check and traffic monitoring via a TP-Link TL-SG2218 switch (JetStream/Omada CLI)

Features:
  1) Switch health: system info, CPU, memory, port status, port errors.
  2) Network health: parallel ping to the gateway and important hosts.
  3) Traffic monitoring: samples port counters and computes Mbps and utilization per port.
  4) Picks the busiest port (heavy port) and alerts when it exceeds the threshold.
  5) (Optional) Configures port mirroring of the busiest port to the monitoring PC's port,
     then captures packets locally with tshark into a pcap with a top-talkers summary.

Requirements:
  pip install netmiko          (preferred)   or   pip install paramiko   (fallback)
  tshark (optional, for capture):  sudo apt install tshark

Settings: config.json (next to the script) or --config path/to/file.json
Priority: command line > environment variables > config.json > built-in fallbacks

Examples:
  export SW_USER=admin SW_PASS='xxxx'
  python3 switch_monitor.py --health
  python3 switch_monitor.py --traffic --interval 10 --samples 3 --top 5
  python3 switch_monitor.py --all --watch 60
  python3 switch_monitor.py --traffic --mirror-dest 1/0/16 --capture-iface eth0 --capture-secs 60
  python3 switch_monitor.py --health --dump-raw      # save raw switch output when tuning the parser
"""

import argparse
import concurrent.futures as cf
import csv
import getpass
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime

# Windows: avoid UnicodeEncodeError when printing symbols to the console or redirecting to a file
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ============================ Load settings ============================
# All settings live in config.json; values here are fallbacks used only when a key is missing.
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

FALLBACK = {
    "switch": {"host": "192.168.1.250", "port": 22, "username": "", "password": "",
               "enable_password": "", "timeout": 20},
    "network": {"gateway": "192.168.1.1", "ping_targets": ["192.168.1.1"],
                "subnet": "", "scan_workers": 64, "resolve_names": True,
                "uplink_mac_threshold": 3},
    "cables": {"ports": "all", "exclude": [], "skip_mgmt_port": True, "skip_fiber": True,
               "max_length_m": 100},
    "thresholds": {"heavy_util_pct": 70.0, "cpu_warn_pct": 80.0, "mem_warn_pct": 85.0},
    "monitoring": {"interval_sec": 10, "samples": 3, "top_ports": 18, "watch_sec": 0},
    "mirror": {"session": 1, "dest_port": "", "keep_mirror": False},
    "capture": {"iface": "", "duration_sec": 60},
    "output": {"out_dir": "reports", "csv_file": "traffic_log.csv"},
    "commands": {
        "sysinfo": "show system-info",
        "cpu": "show cpu-utilization",
        "mem": "show memory-utilization",
        "status": "show interface status",
        "counters": "show interface counters",
        "mac_table": "show mac address-table",
        "arp": "show arp",
        "cable_test": "show cable-diagnostics interface gigabitEthernet {port}",
    },
}

# TP-Link JetStream CLI commands — overridden by config.json on load
CMD = dict(FALLBACK["commands"])


def load_config(path):
    """Read config.json and merge it over the fallbacks (merged per section)."""
    cfg = json.loads(json.dumps(FALLBACK))
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        for section, values in user.items():
            if isinstance(values, dict):
                cfg.setdefault(section, {}).update(values)
            else:
                cfg[section] = values
    elif path != DEFAULT_CONFIG_PATH:
        raise FileNotFoundError(f"Config file not found: {path}")
    CMD.update(cfg["commands"])
    return cfg


# ================================ SSH connection ================================
class SwitchSSH:
    """Unified wrapper: uses netmiko if available, otherwise paramiko with an interactive shell."""

    def __init__(self, host, user, password, port=22, enable_pass=None, timeout=20):
        self.host, self.user, self.password = host, user, password
        self.port, self.enable_pass, self.timeout = port, enable_pass, timeout
        self.conn = None
        self.mode = None

    def connect(self):
        try:
            return self._connect()
        except Exception as e:
            if "Authentication" in type(e).__name__ or "Authentication failed" in str(e):
                raise RuntimeError(
                    f"Switch {self.host} rejected the username/password ({self.user}). "
                    "Verify them by logging into the web UI, and make sure the user has Admin access and SSH is enabled. "
                    "(Set them in config.json or via SW_USER/SW_PASS)") from None
            raise

    def _connect(self):
        try:
            from netmiko import ConnectHandler
            self.conn = ConnectHandler(
                device_type="tplink_jetstream", host=self.host, port=self.port,
                username=self.user, password=self.password,
                secret=self.enable_pass or self.password,
                timeout=self.timeout, fast_cli=False,
            )
            try:
                self.conn.enable()
            except Exception:
                pass
            self.mode = "netmiko"
        except ImportError:
            self._connect_paramiko()
        return self

    def _connect_paramiko(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("No SSH library installed — run: pip install netmiko   (or pip install paramiko)")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.host, port=self.port, username=self.user, password=self.password,
                       timeout=self.timeout, look_for_keys=False, allow_agent=False)
        self.shell = client.invoke_shell(width=250, height=1000)
        self.client = client
        self.mode = "paramiko"
        self._wait_prompt(10)
        out = self._exec("enable", timeout=10, raw=True)
        if "assword" in out:
            self._exec(self.enable_pass or self.password, timeout=10, raw=True)

    # TP-Link's CLI only executes a command on CR ("\r"); a bare "\n" just keeps typing on the same line.
    PROMPT_RE = re.compile(r"(?:^|[\r\n])[\w.\-()]+(?:\(config[\w\-]*\))?[#>]\s*$")
    PAGER_RE = re.compile(r"Press any key to continue \(Q to quit\)|--More--|-- ?More ?--", re.I)

    def _send(self, line):
        self.shell.send(line + "\r")

    def _recv(self):
        buf = ""
        while self.shell.recv_ready():
            buf += self.shell.recv(65535).decode(errors="ignore")
        return buf

    def _wait_prompt(self, timeout):
        buf, end = "", time.time() + timeout
        while time.time() < end:
            buf += self._recv()
            if self.PROMPT_RE.search(buf):
                break
            time.sleep(0.1)
        return buf

    def _exec(self, cmd, timeout=90, raw=False):
        """Send one command and read until the prompt returns, answering the pager along the way."""
        self._recv()                                   # drop anything left over
        self._send(cmd)
        buf, end, last = "", time.time() + timeout, time.time()
        while time.time() < end:
            chunk = self._recv()
            if chunk:
                buf += chunk
                last = time.time()
                if self.PAGER_RE.search(buf[-200:]):
                    buf = self.PAGER_RE.sub("", buf)
                    self.shell.send(" ")
                    continue
                if self.PROMPT_RE.search(buf) and len(buf) > len(cmd):
                    break
            elif "assword" in buf[-40:] and time.time() - last > 1:
                break
            else:
                time.sleep(0.1)
        if raw:
            return buf
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\x08+|\x00", "", buf)
        text = re.sub(r"\r +\r", "", text)             # pager line wipe
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if lines and cmd.strip() and lines[0].strip().endswith(cmd.strip()):
            lines = lines[1:]                          # command echo
        while lines and (not lines[-1].strip() or self.PROMPT_RE.search("\n" + lines[-1])):
            lines.pop()                                # trailing prompt / blanks
        return "\n".join(lines)

    def run(self, cmd, idle_limit=3):
        if self.mode == "netmiko":
            return self.conn.send_command(cmd, read_timeout=90)
        return self._exec(cmd, timeout=max(60, idle_limit * 20))

    def config(self, lines):
        if self.mode == "netmiko":
            return self.conn.send_config_set(lines)
        out = self.run("configure")
        for ln in lines:
            out += "\n" + self.run(ln)
        out += "\n" + self.run("end")
        return out

    def close(self):
        try:
            if self.mode == "netmiko":
                self.conn.disconnect()
            elif self.mode == "paramiko":
                self.client.close()
        except Exception:
            pass


# ================================ Parsers ================================
PORT_RE = r"(?:Gi|gi|GigabitEthernet|Te|te|TenGigabitEthernet)\s*\d+/\d+/\d+"


def norm_port(p):
    p = p.replace(" ", "")
    m = re.search(r"(\d+/\d+/\d+)", p)
    prefix = "Te" if p.lower().startswith("te") else "Gi"
    return f"{prefix}{m.group(1)}" if m else p


def parse_percent(text, keys=("5 sec", "five seconds", "current", "used", "utilization")):
    """Return the first percentage tied to a keyword, or the first percentage in the text."""
    for k in keys:
        m = re.search(rf"{k}[^\d%]*?(\d+(?:\.\d+)?)\s*%", text, re.I)
        if m:
            return float(m.group(1))
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
    return float(m.group(1)) if m else None


def parse_cpu(text):
    """
    Prefer the one-minute average: the five-second value spikes while our own SSH session runs commands.
    TP-Link table:  Unit | Five-Seconds  One-Minute  Five-Minutes  /  1 | 90%  28%  29%
    """
    if re.search(r"One[- ]?Minute", text, re.I):
        for line in text.splitlines():
            vals = re.findall(r"(\d+(?:\.\d+)?)\s*%", line)
            if len(vals) >= 2:
                return float(vals[1])
    return parse_percent(text)


def parse_status(text):
    """Parse the show interface status table → {port: {link, speed_mbps, duplex}}"""
    ports = {}
    for line in text.splitlines():
        m = re.match(rf"\s*({PORT_RE})\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        port, link, speed, duplex = m.groups()
        sp = re.match(r"(\d+)\s*([MG])", speed, re.I)
        speed_mbps = 0
        if sp:
            speed_mbps = int(sp.group(1)) * (1000 if sp.group(2).upper() == "G" else 1)
        ports[norm_port(port)] = {
            "link": "up" if "up" in link.lower() else "down",
            "speed_mbps": speed_mbps,
            "duplex": duplex,
            "medium": "fiber" if re.search(r"fiber|sfp", line, re.I) else "copper",
        }
    return ports


def parse_counters(text):
    """
    Supports two common TP-Link JetStream formats:
      (a) blocks:  Gi1/0/1 ... Rx: Octets: N ... Error Pkts: N ... Tx: Octets: N ...
      (b) table:   Port  Rx-Octets  ...  Tx-Octets ...
    Returns {port: {rx_bytes, tx_bytes, rx_err, tx_err}}
    """
    res = {}
    # (a) block format
    blocks = re.split(rf"(?=^\s*(?:Port\s*:?\s*)?{PORT_RE}\s*:?\s*$)", text, flags=re.M)
    for b in blocks:
        hm = re.match(rf"\s*(?:Port\s*:?\s*)?({PORT_RE})", b)
        if not hm:
            continue
        port = norm_port(hm.group(1))
        parts = re.split(r"^\s*Tx\s*:?\s*$", b, flags=re.M | re.I)
        rx_part = parts[0]
        tx_part = parts[1] if len(parts) > 1 else ""

        def grab(pat, s):
            m = re.search(pat, s, re.I | re.M)
            return int(m.group(1).replace(",", "")) if m else 0

        # (a1) prefixed lines, e.g. TL-SG2218 firmware:  "Rx Bytes:  119,531,277" / "Tx Errors:  0"
        n = r"\s*:?\s*([\d,]+)"
        if re.search(rf"^\s*[RT]x\s*(?:Bytes|Octets){n}", b, re.I | re.M):
            res[port] = {
                "rx_bytes": grab(rf"^\s*Rx\s*(?:Bytes|Octets){n}", b),
                "tx_bytes": grab(rf"^\s*Tx\s*(?:Bytes|Octets){n}", b),
                "rx_err": grab(rf"^\s*Rx\s*(?:Errors|Error\s*Pkts){n}", b),
                "tx_err": grab(rf"^\s*Tx\s*(?:Errors|Error\s*Pkts){n}", b),
            }
            continue

        oct_pat = r"Octets\s*:?\s*(\d+)"
        err_pat = r"Error\s*(?:Pkts|Packets|Frames)?\s*:?\s*(\d+)"
        if tx_part or re.search(oct_pat, rx_part, re.I):
            res[port] = {
                "rx_bytes": grab(oct_pat, rx_part), "tx_bytes": grab(oct_pat, tx_part),
                "rx_err": grab(err_pat, rx_part), "tx_err": grab(err_pat, tx_part),
            }
    if res:
        return res

    # (b) table format: take column order from the header line
    header_cols = None
    for line in text.splitlines():
        if re.search(r"\bPort\b", line, re.I) and re.search(r"Octet|Byte", line, re.I):
            header_cols = re.split(r"\s{2,}|\t", line.strip())
            continue
        m = re.match(rf"\s*({PORT_RE})\s+(.*)", line)
        if not m:
            continue
        nums = [int(x) for x in re.findall(r"\d+", m.group(2))]
        port = norm_port(m.group(1))
        if header_cols:
            cols = [c.lower() for c in header_cols[1:]]

            def idx(*keys):
                for i, c in enumerate(cols):
                    if all(k in c for k in keys):
                        return i
                return None
            first = lambda a, b: a if a is not None else b
            ri = first(idx("rx", "oct"), idx("rx", "byte"))
            ti = first(idx("tx", "oct"), idx("tx", "byte"))
            rei, tei = idx("rx", "err"), idx("tx", "err")
            g = lambda i: nums[i] if i is not None and i < len(nums) else 0
            res[port] = {"rx_bytes": g(ri), "tx_bytes": g(ti), "rx_err": g(rei), "tx_err": g(tei)}
        elif len(nums) >= 2:
            res[port] = {"rx_bytes": nums[0], "tx_bytes": nums[1], "rx_err": 0, "tx_err": 0}
    return res


# =============================== Network check ===============================
def ping(host, count=3, timeout=2):
    """Locale-independent ping: replies are counted from TTL lines (works on any Windows language and Linux)."""
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n" if is_win else "-c", str(count),
           "-w" if is_win else "-W", str(timeout * (1000 if is_win else 1)), str(host)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                             timeout=count * timeout + 5).stdout
    except Exception as e:
        return {"host": str(host), "alive": False, "loss_pct": 100.0, "avg_ms": None, "error": str(e)}
    # "Destination host unreachable" has no TTL, so it is not counted as a reply (unlike the Windows returncode)
    replies = [ln for ln in out.splitlines() if re.search(r"ttl[=:]", ln, re.I)]
    times = [float(t) for ln in replies for t in re.findall(r"[=<]\s*([\d.]+)\s*ms", ln, re.I)[:1]]
    loss_pct = round((count - min(len(replies), count)) / count * 100, 1)
    return {"host": str(host), "alive": bool(replies), "loss_pct": loss_pct,
            "avg_ms": round(sum(times) / len(times), 2) if times else None}


def network_health(targets):
    with cf.ThreadPoolExecutor(max_workers=min(32, len(targets) or 1)) as ex:
        return list(ex.map(ping, targets))


# ============================ Switch health ============================
def switch_health(sw, cfg, raw_dump=None):
    raw = {k: sw.run(CMD[k]) for k in ("sysinfo", "cpu", "mem", "status", "counters")}
    if raw_dump is not None:
        raw_dump.update(raw)
    status = parse_status(raw["status"])
    counters = parse_counters(raw["counters"])
    cpu = parse_cpu(raw["cpu"])
    mem = parse_percent(raw["mem"])
    uptime = re.search(r"(?:Running|Up)\s*Time\s*[-:]*\s*(.+)", raw["sysinfo"], re.I)

    alerts = []
    if cpu is not None and cpu >= cfg["thresholds"]["cpu_warn_pct"]:
        alerts.append(f"High CPU usage: {cpu}%")
    if mem is not None and mem >= cfg["thresholds"]["mem_warn_pct"]:
        alerts.append(f"High memory usage: {mem}%")
    err_ports = {p: c for p, c in counters.items() if c["rx_err"] or c["tx_err"]}
    for p, c in err_ports.items():
        alerts.append(f"Errors on port {p}: Rx={c['rx_err']} Tx={c['tx_err']}")
    for p, s in status.items():
        if s["link"] == "up" and s["duplex"].lower().startswith("half"):
            alerts.append(f"Port {p} is running Half-Duplex (possible duplex mismatch)")
        if s["link"] == "up" and 0 < s["speed_mbps"] < 1000:
            alerts.append(f"Port {p} linked at low speed {s['speed_mbps']}M (likely a damaged cable pair or a 100M NIC)")

    return {
        "cpu_pct": cpu, "mem_pct": mem,
        "uptime": uptime.group(1).strip() if uptime else None,
        "ports_up": sorted(p for p, s in status.items() if s["link"] == "up"),
        "ports_down": sorted(p for p, s in status.items() if s["link"] == "down"),
        "status": status, "error_ports": err_ports, "alerts": alerts,
    }


# ============================== Traffic monitoring ==============================
def monitor_traffic(sw, interval, samples, status=None):
    """Take (samples+1) counter readings and compute the average rate per port."""
    status = status or parse_status(sw.run(CMD["status"]))
    prev, t_prev = parse_counters(sw.run(CMD["counters"])), time.time()
    if not prev:
        raise RuntimeError("Could not parse port counters — run with --dump-raw and send the output to tune the parser.")
    acc = {}
    for i in range(samples):
        time.sleep(interval)
        cur, t_cur = parse_counters(sw.run(CMD["counters"])), time.time()
        dt = max(t_cur - t_prev, 0.001)
        for p, c in cur.items():
            if p not in prev:
                continue
            d_rx = c["rx_bytes"] - prev[p]["rx_bytes"]
            d_tx = c["tx_bytes"] - prev[p]["tx_bytes"]
            if d_rx < 0 or d_tx < 0:          # counter reset/wrap
                continue
            a = acc.setdefault(p, {"rx": [], "tx": [], "err": 0})
            a["rx"].append(d_rx * 8 / dt / 1e6)
            a["tx"].append(d_tx * 8 / dt / 1e6)
            a["err"] += (c["rx_err"] - prev[p]["rx_err"]) + (c["tx_err"] - prev[p]["tx_err"])
        prev, t_prev = cur, t_cur
        print(f"  Sample {i + 1}/{samples} ✔", flush=True)

    rows = []
    for p, a in acc.items():
        rx = sum(a["rx"]) / len(a["rx"])
        tx = sum(a["tx"]) / len(a["tx"])
        speed = (status.get(p) or {}).get("speed_mbps") or 1000
        util = max(rx, tx) / speed * 100        # Full-Duplex: the busier direction is the measure
        rows.append({"port": p, "rx_mbps": round(rx, 3), "tx_mbps": round(tx, 3),
                     "total_mbps": round(rx + tx, 3), "speed_mbps": speed,
                     "util_pct": round(util, 2), "new_errors": a["err"],
                     "link": (status.get(p) or {}).get("link", "?")})
    rows.sort(key=lambda r: r["total_mbps"], reverse=True)
    return rows


# ======================= Network discovery via the switch =======================
MAC_RE = r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])"
IP_RE = r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
ANY_PORT_RE = r"((?:Gi|gi|GigabitEthernet|Te|te|TenGigabitEthernet|Po|po|LAG|lag|Port-channel)\s*\d+(?:/\d+/\d+)?)"


def norm_mac(m):
    h = re.sub(r"[^0-9a-f]", "", m.lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else m.lower()


def is_unicast(mac):
    return (len(mac) == 17 and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
            and not int(mac[:2], 16) & 1)


def port_key(p):
    return tuple(int(x) for x in re.findall(r"\d+", p or "")) or (9999,)


def parse_mac_table(text):
    """show mac address-table → [{mac, vlan, port, type}]"""
    rows = []
    for line in text.splitlines():
        mm = re.search(MAC_RE, line)
        if not mm:
            continue
        pm = re.search(ANY_PORT_RE, line[mm.end():])
        if not pm:
            continue
        mac = norm_mac(mm.group(1))
        if not is_unicast(mac):
            continue
        vlan = re.search(r"\b(\d{1,4})\b", line[mm.end():mm.end() + pm.start()])
        typ = re.search(r"\b(dynamic|static|learned|config\w*|permanent)\b", line, re.I)
        rows.append({"mac": mac, "vlan": int(vlan.group(1)) if vlan else None,
                     "port": norm_port(pm.group(1)), "type": typ.group(1).lower() if typ else ""})
    return rows


def parse_arp(text):
    """Any ARP table (switch, Windows arp -a, Linux ip neigh) → {ip: mac}"""
    res = {}
    for line in text.splitlines():
        ip, mac = re.search(IP_RE, line), re.search(MAC_RE, line)
        if ip and mac:
            m = norm_mac(mac.group(1))
            if is_unicast(m):
                res[ip.group(1)] = m
    return res


def local_arp():
    for cmd in (["arp", "-a"], ["ip", "neigh"], ["arp", "-an"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=15).stdout
            if out.strip():
                return parse_arp(out)
        except Exception:
            continue
    return {}


def local_macs():
    """MAC addresses of this PC's NICs (to find the management port and avoid cutting it during cable tests)."""
    macs = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if re.fullmatch(MAC_RE, a.address or ""):
                    macs.add(norm_mac(a.address))
    except Exception:
        pass
    if platform.system().lower() == "windows":
        try:
            out = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True,
                                 errors="ignore", timeout=10).stdout
            macs.update(norm_mac(m) for m in re.findall(MAC_RE, out))
        except Exception:
            pass
    elif os.path.isdir("/sys/class/net"):
        for d in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{d}/address") as f:
                    macs.add(norm_mac(f.read().strip()))
            except Exception:
                pass
    macs.add(norm_mac(f"{uuid.getnode():012x}"))
    return {m for m in macs if is_unicast(m)}


def resolve_names(ips, timeout=8):
    names = {}
    if not ips:
        return names
    ex = cf.ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    done, _ = cf.wait(futs, timeout=timeout)
    for f in done:
        try:
            names[futs[f]] = f.result()[0]
        except Exception:
            pass
    ex.shutdown(wait=False, cancel_futures=True)
    return names


def ping_sweep(net, workers=64):
    hosts = list(net.hosts())[:4094]
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(lambda h: ping(h, count=1, timeout=1), hosts))
    return {r["host"]: r for r in res if r["alive"]}


def discover_network(sw, cfg, status, raw_dump=None):
    """
    Discovers every device connected to the switch:
      1) Ping every address in the subnet (to populate ARP tables)
      2) Local ARP table + switch ARP table   → IP ↔ MAC
      3) Switch MAC table                     → MAC ↔ port
    """
    net_c = cfg["network"]
    subnet = net_c.get("subnet") or f"{net_c.get('gateway') or cfg['switch']['host']}/24"
    net = ipaddress.ip_network(subnet, strict=False)
    print(f"🔎 Scanning network {net} ({max(net.num_addresses - 2, 1)} addresses)...", flush=True)
    t0 = time.time()
    alive = ping_sweep(net, int(net_c.get("scan_workers") or 64))
    print(f"  {len(alive)} devices replied to ping in {time.time() - t0:.0f}s", flush=True)

    raw_mac = sw.run(CMD["mac_table"])
    raw_arp = sw.run(CMD["arp"])
    if raw_dump is not None:
        raw_dump[CMD["mac_table"]] = raw_mac
        raw_dump[CMD["arp"]] = raw_arp
    mac_rows = parse_mac_table(raw_mac)
    if not mac_rows:
        print("  ⚠ Could not read the switch MAC table — run with --dump-raw to review the output.")

    ip2mac = {**parse_arp(raw_arp), **local_arp()}
    ip2mac = {ip: m for ip, m in ip2mac.items() if ipaddress.ip_address(ip) in net}
    mac2ip = {}
    for ip, m in ip2mac.items():
        mac2ip.setdefault(m, []).append(ip)
    mac2port = {r["mac"]: r for r in mac_rows}

    my_macs = local_macs()
    mgmt_ports = sorted({mac2port[m]["port"] for m in my_macs if m in mac2port}, key=port_key)

    port_macs = {}
    for r in mac_rows:
        port_macs.setdefault(r["port"], set()).add(r["mac"])
    thr = int(net_c.get("uplink_mac_threshold") or 3)
    gw_mac = ip2mac.get(net_c.get("gateway") or "")
    sw_mac = ip2mac.get(cfg["switch"]["host"])          # the switch's own management MAC

    def role_of(mac):
        if mac == gw_mac:
            return "gateway"
        if mac == sw_mac:
            return "switch"
        return "this-pc" if mac in my_macs else ""

    devices = []
    for m in set(mac2port) | set(mac2ip):
        ips = sorted(mac2ip.get(m, []), key=ipaddress.ip_address)
        port = mac2port.get(m, {}).get("port")
        devices.append({
            "ip": ips[0] if ips else None, "other_ips": ips[1:], "mac": m,
            "port": port, "vlan": mac2port.get(m, {}).get("vlan"),
            "ping": any(ip in alive for ip in ips),
            "rtt_ms": next((alive[ip]["avg_ms"] for ip in ips if ip in alive), None),
            "behind_uplink": bool(port and len(port_macs.get(port, ())) >= thr),
            "role": role_of(m),
            "hostname": None,
        })
    # Devices that replied to ping but have no known MAC (usually this PC itself or outside the local network)
    known_ips = {ip for d in devices for ip in [d["ip"], *d["other_ips"]] if ip}
    for ip in alive:
        if ip not in known_ips:
            devices.append({"ip": ip, "other_ips": [], "mac": None, "port": None, "vlan": None,
                            "ping": True, "rtt_ms": alive[ip]["avg_ms"], "behind_uplink": False,
                            "role": "switch" if ip == cfg["switch"]["host"] else "", "hostname": None})

    if net_c.get("resolve_names", True):
        names = resolve_names([d["ip"] for d in devices if d["ip"]])
        for d in devices:
            n = names.get(d["ip"])
            d["hostname"] = n if n and n != d["ip"] else None   # some resolvers echo the IP back

    devices.sort(key=lambda d: (port_key(d["port"]),
                                int(ipaddress.ip_address(d["ip"])) if d["ip"] else 2 ** 32))

    ports = {}
    for p in sorted(set(status) | set(port_macs), key=port_key):
        s = status.get(p, {})
        macs = port_macs.get(p, set())
        ports[p] = {"link": s.get("link", "?"), "speed_mbps": s.get("speed_mbps", 0),
                    "duplex": s.get("duplex", ""), "medium": s.get("medium", "copper"),
                    "mac_count": len(macs), "uplink": len(macs) >= thr, "mgmt": p in mgmt_ports,
                    "ips": sorted({ip for m in macs for ip in mac2ip.get(m, [])}, key=ipaddress.ip_address)}

    alerts = []
    if mac_rows:
        for p, info in ports.items():
            if info["link"] == "up" and info["mac_count"] == 0:
                alerts.append(f"Port {p} is up but has learned no MAC (silent device or VLAN issue)")
        not_on_sw = [d["ip"] for d in devices if d["ip"] and d["mac"] and not d["port"] and d["role"] not in ("this-pc", "switch")]
        if not_on_sw:
            alerts.append(f"{len(not_on_sw)} device(s) on the network not seen on this switch (wireless/another switch/another VLAN): "
                          + ", ".join(not_on_sw[:10]) + (" ..." if len(not_on_sw) > 10 else ""))
    return {"subnet": str(net), "alive_count": len(alive), "devices": devices,
            "ports": ports, "mgmt_ports": mgmt_ports, "alerts": alerts}


# ============================ Cable diagnostics (TDR) ============================
CABLE_STATUS_RE = (r"(Normal|OK|Good|Open|Short(?:[- ]?(?:Within|Cross)[- ]?Pair)?|Cross[- ]?talk|"
                   r"Impedance[- ]?Mismatch|Mismatch|Abnormal|No[- ]?Cable|Not[- ]?Support\w*|"
                   r"Fail\w*|Unknown|Busy|Error)")
LEN_RE = r"(\d+(?:\.\d+)?)\s*(?:m\b|M\b|meter|metre)"


def parse_cable(text):
    """Parse cable-diagnostics output → [{pair, status, length_m}]"""
    pairs = []
    for line in text.splitlines():
        pm = re.search(r"Pair\s*[-_]?\s*([A-D1-4])\b", line, re.I)
        if not pm:
            continue
        rest = line[pm.end():]
        st = re.search(CABLE_STATUS_RE, rest, re.I)
        if not st:
            continue
        ln = re.search(LEN_RE, rest[st.end():]) or re.search(LEN_RE, rest)
        pairs.append({"pair": "ABCD"["ABCD1234".index(pm.group(1).upper()) % 4],
                      "status": re.sub(r"[\s_]+", "-", st.group(1).lower()),
                      "length_m": float(ln.group(1)) if ln else None})
    if pairs:
        return pairs
    # Horizontal table format: Port  StatusA LenA StatusB LenB ...
    body = "\n".join(l for l in text.splitlines() if re.search(PORT_RE, l)) or text
    sts = re.findall(CABLE_STATUS_RE, body, re.I)
    lens = re.findall(LEN_RE, body)
    for i, st in enumerate(sts[:4]):
        pairs.append({"pair": "ABCD"[i], "status": re.sub(r"[\s_]+", "-", st.lower()),
                      "length_m": float(lens[i]) if i < len(lens) else None})
    return pairs


def assess_cable(pairs, link, speed, max_len=100):
    """Turn per-pair results into a clear verdict: ok / warn / fault / unplugged / unknown"""
    if not pairs:
        return "unknown", "Could not interpret the test result (check raw output with --dump-raw)"
    if any("support" in p["status"] for p in pairs):
        return "unknown", "Port does not support cable diagnostics"
    lens = [p["length_m"] for p in pairs if p["length_m"]]
    L = f"~{max(lens):.0f}m" if lens else ""
    st = {p["pair"]: p["status"] for p in pairs}
    short = [k for k, v in st.items() if "short" in v]
    bad = [k for k, v in st.items() if any(x in v for x in ("mismatch", "talk", "abnormal", "fail", "error"))]
    opn = [k for k, v in st.items() if "open" in v or "no-cable" in v]
    ok = [k for k, v in st.items() if v in ("normal", "ok", "good")]
    plen = {p["pair"]: p["length_m"] for p in pairs}

    def at(keys):   # distance from the switch to the fault on the affected pairs
        ds = [plen[k] for k in keys if plen.get(k)]
        return f"at ~{min(ds):.0f}m" if ds else ""

    if short:
        return "fault", f"Short on pair {','.join(short)} {at(short)} — damaged cable or miswired RJ45 connector"
    if bad:
        return "warn", f"Impedance mismatch/crosstalk on pair {','.join(bad)} {at(bad)} — poor-quality cable or bad joint/patch"
    if opn and not ok:
        if link == "down":
            if not lens or max(lens) <= 2:          # open right at the port = nothing plugged in
                return "unplugged", "No cable connected"
            return "unplugged", f"Cable present (~{max(lens):.0f}m) but nothing at the far end, or cable cut there"
        return "warn", "All pairs Open although the port is up — re-run the test"
    if opn and ok:
        if link == "up" and speed == 100 and set(opn) <= {"C", "D"}:
            return "warn", f"Pairs {','.join(opn)} are open — link dropped to 100M because of the cable (re-crimp the connector)"
        return "fault", f"Pair {','.join(opn)} open {at(opn)} — damaged cable or bad RJ45 connector"
    if lens and max(lens) > max_len:
        return "warn", f"Cable length {L} exceeds the standard limit of {max_len}m"
    if link == "down":
        return "warn", f"Cable OK {L} but the port is down — far-end device is off or faulty"
    if link == "up" and 0 < speed < 1000:
        return "warn", f"Cable looks OK {L} but speed is {speed}M — check the device NIC or cable category (Cat5e/Cat6)"
    return "ok", f"OK {L}".strip()


def cable_diagnostics(sw, cfg, status, mgmt_ports=(), only=None, raw_dump=None):
    c = cfg["cables"]
    wanted = only or c.get("ports") or "all"
    if isinstance(wanted, str):
        wanted = "all" if wanted.strip().lower() == "all" else [x for x in re.split(r"[,\s]+", wanted) if x]
    if wanted != "all":
        wanted = {m.group(0) for w in wanted for m in [re.search(r"\d+/\d+/\d+", w)] if m}
    exclude = {m.group(0) for x in c.get("exclude", []) for m in [re.search(r"\d+/\d+/\d+", x)] if m}

    results = {}
    for p in sorted(status, key=port_key):
        m = re.search(r"\d+/\d+/\d+", p)
        if not m:
            continue
        num, s = m.group(0), status[p]
        if wanted != "all" and num not in wanted:
            continue
        reason = None
        if num in exclude:
            reason = "Excluded in settings"
        elif c.get("skip_fiber", True) and s.get("medium") == "fiber":
            reason = "Fiber/SFP port"
        elif c.get("skip_mgmt_port", True) and p in mgmt_ports and wanted == "all":
            reason = "Management port (this PC) — skipped to avoid losing the connection"
        if reason:
            results[p] = {"verdict": "skipped", "message": reason, "pairs": []}
            continue
        print(f"  🧪 Testing cable on {p}...", flush=True)
        cmd = CMD["cable_test"].format(port=num)
        out = sw.run(cmd, idle_limit=6)
        if raw_dump is not None:
            raw_dump[cmd] = out
        pairs = parse_cable(out)
        verdict, msg = assess_cable(pairs, s.get("link"), s.get("speed_mbps", 0), c.get("max_length_m", 100))
        results[p] = {"verdict": verdict, "message": msg, "pairs": pairs}
    return results


def print_network_map(disc, cables):
    icon = {"ok": "✅", "warn": "⚠", "fault": "❌", "unplugged": "⭕", "unknown": "❔", "skipped": "⏭"}
    print(f"\n🗺  Port map ({disc['subnet']}):")
    print(f"{'Port':<9}{'Link':<6}{'Speed':>6}  {'Cable':<6}{'MACs':>5}  Devices / cable note")
    print("-" * 90)
    for p, info in disc["ports"].items():
        cb = cables.get(p, {})
        tag = " [uplink]" if info["uplink"] else ""
        tag += " [mgmt]" if info["mgmt"] else ""
        ips = ", ".join(info["ips"][:4]) + (" ..." if len(info["ips"]) > 4 else "")
        note = ips + tag
        if cb and cb["verdict"] not in ("ok", "skipped"):
            note = (note + " | " if note else "") + cb["message"]
        sp = f"{info['speed_mbps']}M" if info["speed_mbps"] else "-"
        print(f"{p:<9}{info['link']:<6}{sp:>6}  {icon.get(cb.get('verdict'), '·'):<6}{info['mac_count']:>5}  {note}")

    print(f"\n💻 Discovered devices: {len(disc['devices'])}  (replied to ping: {disc['alive_count']})")
    print(f"{'IP':<16}{'MAC':<19}{'Port':<11}{'Ping':<6}{'RTT':>6}  Hostname")
    print("-" * 90)
    for d in disc["devices"]:
        role = {"gateway": " (gateway)", "this-pc": " (this PC)", "switch": " (this switch)"}.get(d["role"], "")
        port = (d["port"] or "-") + ("*" if d["behind_uplink"] else "")
        rtt = f"{d['rtt_ms']:.0f}" if d["rtt_ms"] is not None else "-"
        print(f"{d['ip'] or '-':<16}{d['mac'] or '-':<19}{port:<11}{'✔' if d['ping'] else '✖':<6}{rtt:>6}  "
              f"{d['hostname'] or ''}{role}")
    if any(d["behind_uplink"] for d in disc["devices"]):
        print("  * = behind an uplink port (another switch/access point)")


# ====================== Port mirroring and packet capture ======================
def set_mirror(sw, src_port, dest_port, session=1):
    s = re.search(r"\d+/\d+/\d+", src_port).group(0)
    d = re.search(r"\d+/\d+/\d+", dest_port).group(0)
    if s == d:
        raise ValueError("Source port cannot be the destination port.")
    return sw.config([
        f"no monitor session {session}",
        f"monitor session {session} destination interface gigabitEthernet {d}",
        f"monitor session {session} source interface gigabitEthernet {s} both",
    ])


def clear_mirror(sw, session=1):
    return sw.config([f"no monitor session {session}"])


def capture(iface, seconds, out_dir):
    if not shutil.which("tshark"):
        print("⚠ tshark is not installed — skipping capture.")
        return None
    pcap = os.path.join(out_dir, f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    print(f"⏺ Capturing on {iface} for {seconds}s → {pcap}")
    subprocess.run(["tshark", "-i", iface, "-a", f"duration:{seconds}", "-w", pcap, "-q"], check=False)
    summary = {}
    for name, stat in (("top_ip_conversations", "conv,ip"), ("protocols", "io,phs")):
        r = subprocess.run(["tshark", "-r", pcap, "-q", "-z", stat], capture_output=True, text=True)
        summary[name] = "\n".join(r.stdout.splitlines()[:30])
    return {"pcap": pcap, "summary": summary}


# ================================ Output ================================
def print_table(rows, top, heavy_pct):
    print(f"\n{'Port':<9}{'Link':<6}{'Rx Mbps':>10}{'Tx Mbps':>10}{'Total':>10}{'Speed':>7}{'Util%':>8}{'Err':>6}")
    print("-" * 66)
    for r in rows[:top]:
        flag = "  🔥" if r["util_pct"] >= heavy_pct else ""
        print(f"{r['port']:<9}{r['link']:<6}{r['rx_mbps']:>10.2f}{r['tx_mbps']:>10.2f}"
              f"{r['total_mbps']:>10.2f}{r['speed_mbps']:>7}{r['util_pct']:>8.1f}{r['new_errors']:>6}{flag}")


def save_csv(rows, path):
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp"] + list(rows[0].keys()))
        if new:
            w.writeheader()
        ts = datetime.now().isoformat(timespec="seconds")
        for r in rows:
            w.writerow({"timestamp": ts, **r})


# ============================ Word report (docx) ============================
def save_docx(report, path, heavy_pct=70.0):
    """Write the report as a Word file with color-coded tables. Requires: pip install python-docx"""
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    GREEN, YELLOW, RED, GREY, HEAD = "D9F2DC", "FFF2CC", "F8D7DA", "EEEEEE", "1F4E79"
    doc = Document()
    st = doc.styles["Normal"]
    st.font.name, st.font.size = "Arial", Pt(10)
    for s in doc.sections:
        s.left_margin = s.right_margin = Pt(40)
        s.top_margin = s.bottom_margin = Pt(40)

    def add_text(par, text, bold=False, color=None, size=None):
        """Add a formatted run of text to a paragraph."""
        r = par.add_run(str(text))
        r.bold = bold
        if color:
            r.font.color.rgb = RGBColor.from_string(color)
        if size:
            r.font.size = Pt(size)
        return par

    def para(text, bold=False, color=None, size=None):
        return add_text(doc.add_paragraph(), text, bold, color, size)

    def heading(text, level=1):
        h = add_text(doc.add_heading("", level=level), text)
        for r in h.runs:
            r.font.name = "Arial"
        return h

    def shade(cell, fill):
        tcPr = cell._tc.get_or_add_tcPr()
        sh = OxmlElement("w:shd")
        sh.set(qn("w:val"), "clear"), sh.set(qn("w:color"), "auto"), sh.set(qn("w:fill"), fill)
        tcPr.append(sh)

    def table(headers, rows, fills=None, widths=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for c, h in zip(t.rows[0].cells, headers):
            add_text(c.paragraphs[0], h, bold=True, color="FFFFFF")
            shade(c, HEAD)
        for i, row in enumerate(rows):
            cells = t.add_row().cells
            for c, v in zip(cells, row):
                add_text(c.paragraphs[0], "" if v is None else v)
                if fills and fills[i]:
                    shade(c, fills[i])
        if widths:                                  # column widths as proportions of the usable page width
            t.autofit = False
            total = sum(widths)
            for row in t.rows:
                for c, w in zip(row.cells, widths):
                    c.width = Pt(515 * w / total)
        doc.add_paragraph()
        return t

    ts = report.get("timestamp", "")
    title = doc.add_heading("Network & Switch Health Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para(f"Date: {ts.replace('T', '  ')}    |    Switch: {report.get('switch', '')}", color="555555")

    # ---------- Summary ----------
    h = report.get("switch_health") or {}
    disc = report.get("discovery") or {}
    cables = report.get("cables") or {}
    alerts = (h.get("alerts") or []) + (report.get("network_alerts") or [])
    heading("Summary")
    cnt = lambda v: sum(1 for c in cables.values() if c["verdict"] == v)
    summary = [
        ("Discovered devices", len(disc.get("devices", [])) if disc else "-"),
        ("Ports up / down",
         f"{len(h.get('ports_up', []))} / {len(h.get('ports_down', []))}" if h else "-"),
        ("Cables: OK / warning / fault",
         f"{cnt('ok')} / {cnt('warn')} / {cnt('fault')}" if cables else "-"),
        ("CPU / memory", f"{h.get('cpu_pct')}% / {h.get('mem_pct')}%" if h else "-"),
        ("Total alerts", len(alerts)),
    ]
    if report.get("heaviest_port"):
        hp = report["heaviest_port"]
        summary.append(("Busiest port", f"{hp['port']} — {hp['total_mbps']} Mbps ({hp['util_pct']}%)"))
    table(["Item", "Value"], summary)

    # ---------- Alerts ----------
    heading("Alerts & Issues")
    if alerts:
        for a in alerts:
            para(f"⚠  {a}", color="9C0006")
    else:
        para("No issues found ✅", color="006100", bold=True)

    # ---------- Connectivity ----------
    if report.get("network"):
        heading("Connectivity (Ping)")
        rows = [(n["host"], "Reachable" if n["alive"] else "No response", f"{n['loss_pct']}%",
                 n["avg_ms"] if n["avg_ms"] is not None else "-") for n in report["network"]]
        table(["Address", "Status", "Loss", "Avg latency (ms)"], rows,
              [GREEN if n["alive"] else RED for n in report["network"]])

    # ---------- Switch health ----------
    if h:
        heading("Switch Health")
        table(["Item", "Value"], [
            ("CPU", f"{h.get('cpu_pct')}%"), ("Memory", f"{h.get('mem_pct')}%"),
            ("Uptime", h.get("uptime") or "-"),
            ("Ports up", ", ".join(h.get("ports_up", [])) or "-"),
            ("Ports down", ", ".join(h.get("ports_down", [])) or "-"),
        ])

    # ---------- Port & cable map ----------
    vname = {"ok": "OK", "warn": "Warning", "fault": "Fault", "unplugged": "Unplugged",
             "unknown": "Unknown", "skipped": "Skipped"}
    vfill = {"ok": GREEN, "warn": YELLOW, "fault": RED, "unplugged": GREY, "skipped": None, "unknown": None}
    ports = disc.get("ports") or {p: {} for p in cables}
    if ports:
        heading("Ports & Cables")
        rows, fills = [], []
        for p, info in ports.items():
            cb = cables.get(p, {})
            tags = (" [uplink]" if info.get("uplink") else "") + (" [mgmt]" if info.get("mgmt") else "")
            sp = info.get("speed_mbps")
            rows.append((p, info.get("link", "-"), f"{sp}M" if sp else "-",
                         info.get("mac_count", "-"), (", ".join(info.get("ips", [])) + tags).strip() or "-",
                         vname.get(cb.get("verdict"), "-"), cb.get("message", "")))
            fills.append(vfill.get(cb.get("verdict")))
        table(["Port", "Link", "Speed", "MACs", "Devices", "Cable", "Cable details"], rows, fills,
              widths=[9, 7, 8, 7, 17, 10, 25])

        pr = [(p, ", ".join(f"{x['pair']}:{x['status']}" + (f" {x['length_m']:.0f}m" if x["length_m"] else "")
                            for x in c["pairs"])) for p, c in cables.items() if c.get("pairs")]
        if pr:
            heading("Cable Pair Details (TDR)", 2)
            table(["Port", "Pairs"], pr, widths=[1, 5])

    # ---------- Devices ----------
    if disc.get("devices"):
        heading(f"Discovered Devices ({len(disc['devices'])}) — Subnet {disc.get('subnet', '')}")
        role = {"gateway": "Gateway", "this-pc": "This PC", "switch": "This switch"}
        rows = [(d["ip"] or "-", d["mac"] or "-",
                 (d["port"] or "-") + (" *" if d["behind_uplink"] else ""),
                 "✔" if d["ping"] else "✖", d["rtt_ms"] if d["rtt_ms"] is not None else "-",
                 d["hostname"] or "", role.get(d["role"], "")) for d in disc["devices"]]
        table(["IP", "MAC", "Port", "Ping", "RTT ms", "Hostname", "Role"], rows,
              [None if d["port"] else YELLOW for d in disc["devices"]], widths=[12, 15, 8, 5, 6, 16, 9])
        para("* Behind an uplink port (another switch or access point).  Yellow: device not seen on this switch.",
             color="777777", size=8)

    # ---------- Traffic ----------
    if report.get("traffic"):
        heading("Port Traffic")
        tr = report["traffic"]
        rows = [(r["port"], r["link"], r["rx_mbps"], r["tx_mbps"], r["total_mbps"], r["speed_mbps"],
                 f"{r['util_pct']}%", r["new_errors"]) for r in tr]
        table(["Port", "Link", "Rx Mbps", "Tx Mbps", "Total", "Speed", "Utilization", "Errors"], rows,
              [RED if r["util_pct"] >= heavy_pct else (YELLOW if r["new_errors"] else None) for r in tr])

    doc.save(path)
    return path


# ================================ Run ================================
def run_once(args, cfg):
    os.makedirs(cfg["output"]["out_dir"], exist_ok=True)
    report = {"timestamp": datetime.now().isoformat(timespec="seconds"), "switch": args.host}
    raw = {} if args.dump_raw else None

    if args.health or args.all:
        print("🌐 Checking network connectivity...")
        report["network"] = network_health(sorted(set(args.ping + [args.host])))
        for n in report["network"]:
            st = "✅" if n["alive"] else "❌"
            print(f"  {st} {n['host']:<16} loss={n['loss_pct']}% avg={n['avg_ms']}ms")

    sw = SwitchSSH(args.host, args.user, args.password, args.port, args.enable_pass,
                   cfg["switch"]["timeout"]).connect()
    print(f"🔐 Connected to switch {args.host} via {sw.mode}")
    try:
        status = None
        if (args.scan or args.cables) and not (args.health or args.all):
            out = sw.run(CMD["status"])
            if raw is not None:
                raw["status"] = out
            status = parse_status(out)
            if not status:
                print("⚠ Could not parse port status — run with --dump-raw to review the output.")
        if args.health or args.all:
            h = switch_health(sw, cfg, raw)
            status = h["status"]
            report["switch_health"] = {k: v for k, v in h.items() if k != "status"}
            print(f"🖥  CPU={h['cpu_pct']}%  MEM={h['mem_pct']}%  Uptime={h['uptime']}")
            print(f"🔌 Ports up: {len(h['ports_up'])}  |  down: {len(h['ports_down'])}")
            for a in h["alerts"] or ["No alerts ✅"]:
                print(f"  ⚠ {a}" if h["alerts"] else f"  {a}")

        disc, cables = None, {}
        if args.scan or args.all:
            disc = discover_network(sw, cfg, status or {}, raw)
            report["discovery"] = disc
        if args.cables or args.all:
            print("🔌 Testing cables (Cable Diagnostics / TDR)...")
            mgmt = disc["mgmt_ports"] if disc else []
            if not disc and cfg["cables"].get("skip_mgmt_port", True):
                mac_rows = parse_mac_table(sw.run(CMD["mac_table"]))
                mine = local_macs()
                mgmt = sorted({r["port"] for r in mac_rows if r["mac"] in mine}, key=port_key)
            if mgmt:
                print(f"  ℹ Management port (this PC is connected to it): {', '.join(mgmt)} — will not be tested")
            cables = cable_diagnostics(sw, cfg, status or {}, mgmt, args.cable_ports, raw)
            report["cables"] = cables
            if not disc:
                for p, c in cables.items():
                    print(f"  {p:<9}{c['verdict']:<10}{c['message']}")
        if disc:
            print_network_map(disc, cables)
        all_alerts = (disc["alerts"] if disc else []) + [
            f"Cable on {p}: {c['message']}" for p, c in cables.items() if c["verdict"] in ("fault", "warn")]
        if disc or cables:
            report["network_alerts"] = all_alerts
            print("\n📋 Network & cable issues summary:")
            for a in all_alerts or ["No issues found ✅"]:
                print(f"  ⚠ {a}" if all_alerts else f"  {a}")

        if args.traffic or args.all:
            print(f"📈 Monitoring traffic: {args.samples} samples × {args.interval}s")
            rows = monitor_traffic(sw, args.interval, args.samples, status)
            print_table(rows, args.top, args.heavy)
            report["traffic"] = rows
            if rows:
                save_csv(rows, os.path.join(cfg["output"]["out_dir"], cfg["output"]["csv_file"]))
                heavy = rows[0]
                report["heaviest_port"] = heavy
                lvl = "🔥 heavy" if heavy["util_pct"] >= args.heavy else "normal"
                print(f"\n🏆 Busiest port: {heavy['port']}  "
                      f"({heavy['total_mbps']} Mbps, {heavy['util_pct']}%) — {lvl}")

                if args.mirror_dest:
                    print(f"🪞 Setting up port mirroring: {heavy['port']} → {args.mirror_dest}")
                    set_mirror(sw, heavy["port"], args.mirror_dest, cfg["mirror"]["session"])
                    try:
                        if args.capture_iface:
                            report["capture"] = capture(args.capture_iface, args.capture_secs, cfg["output"]["out_dir"])
                    finally:
                        if not args.keep_mirror:
                            clear_mirror(sw, cfg["mirror"]["session"])
                            print("🧹 Mirror session removed.")
    finally:
        sw.close()

    if raw is not None:
        rp = os.path.join(cfg["output"]["out_dir"], f"raw_{datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(rp, "w", encoding="utf-8") as f:
            for k, v in raw.items():
                f.write(f"===== {CMD.get(k, k)} =====\n{v}\n\n")
        print(f"📝 Raw output: {rp}")

    jp = os.path.join(cfg["output"]["out_dir"], f"report_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"💾 Report: {jp}")

    if cfg["output"].get("docx", True):
        try:
            dp = save_docx(report, jp[:-5] + ".docx", args.heavy)
            print(f"📄 Word report: {dp}")
            latest = os.path.join(cfg["output"]["out_dir"], "report.docx")
            try:
                shutil.copyfile(dp, latest)
                print(f"📄 Latest report: {latest}")
            except PermissionError:
                print(f"⚠ {latest} was not updated because it is open in Word — close it and run again.")
        except ImportError:
            print("⚠ To produce the Word report run: pip install python-docx")
    return report


def main():
    # Stage 1: determine the config file path only
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    known, _ = pre.parse_known_args()
    try:
        cfg = load_config(known.config)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Config file error: {e}")
        sys.exit(1)
    sw_c, net, th, mon = cfg["switch"], cfg["network"], cfg["thresholds"], cfg["monitoring"]
    mir, cap = cfg["mirror"], cfg["capture"]

    # Stage 2: command-line options override config.json, and environment variables override the file
    p = argparse.ArgumentParser(description="TL-SG2218 health & traffic monitor", parents=[pre])
    p.add_argument("--host", default=os.getenv("SW_HOST") or sw_c["host"])
    p.add_argument("--port", type=int, default=sw_c["port"])
    p.add_argument("--user", default=os.getenv("SW_USER") or sw_c["username"] or None)
    p.add_argument("--password", default=os.getenv("SW_PASS") or sw_c["password"] or None)
    p.add_argument("--enable-pass", default=os.getenv("SW_ENABLE") or sw_c["enable_password"] or None)
    p.add_argument("--health", action="store_true", help="Check switch and network health")
    p.add_argument("--traffic", action="store_true", help="Monitor traffic and pick the busiest port")
    p.add_argument("--scan", action="store_true", help="Discover all network devices and map them to switch ports")
    p.add_argument("--cables", action="store_true", help="Run cable diagnostics (TDR) on switch ports")
    p.add_argument("--cable-ports", default=None, help="Specific ports for cable tests, e.g. 1/0/3,1/0/7")
    p.add_argument("--subnet", default=None, help="Subnet to scan, e.g. 192.168.1.0/24")
    p.add_argument("--all", action="store_true", help="All checks (default)")
    p.add_argument("--ping", nargs="*", default=net["ping_targets"])
    p.add_argument("--interval", type=float, default=mon["interval_sec"], help="Seconds between samples")
    p.add_argument("--samples", type=int, default=mon["samples"])
    p.add_argument("--top", type=int, default=mon["top_ports"])
    p.add_argument("--heavy", type=float, default=th["heavy_util_pct"], help="Heavy-port threshold %%")
    p.add_argument("--mirror-dest", default=mir["dest_port"] or None, help="Capture PC port, e.g. 1/0/16")
    p.add_argument("--keep-mirror", action="store_true", default=mir["keep_mirror"])
    p.add_argument("--capture-iface", default=cap["iface"] or None, help="Local capture interface, e.g. eth0")
    p.add_argument("--capture-secs", type=int, default=cap["duration_sec"])
    p.add_argument("--watch", type=int, default=mon["watch_sec"], help="Repeat every N seconds (0 = run once)")
    p.add_argument("--dump-raw", action="store_true")
    args = p.parse_args()

    if not (args.health or args.traffic or args.scan or args.cables or args.all):
        args.all = True
    if args.subnet:
        cfg["network"]["subnet"] = args.subnet
    cfg["switch"]["host"] = args.host        # so discovery recognises the switch even with --host / SW_HOST
    if net.get("gateway") and net["gateway"] not in args.ping:
        args.ping.append(net["gateway"])
    args.user = args.user or input("Username: ")
    args.password = args.password or getpass.getpass("Password: ")

    try:
        while True:
            run_once(args, cfg)
            if not args.watch:
                break
            print(f"\n⏳ Next run in {args.watch}s (Ctrl+C to stop)\n")
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
