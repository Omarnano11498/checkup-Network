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
    "switch": {"host": "write ip-address switch", "port": 22, "username": "", "password": "",
               "enable_password": "", "timeout": 20},
    "network": {"gateway": "write gateway ip-address", "ping_targets": ["write ip-address target1", "write ip-address target2"],
                "subnet": "write subnet in CIDR format    r", "scan_workers": 64, "resolve_names": True,
                "uplink_mac_threshold": 3},
    "devices": {"port_scan": True, "scan_ports": [], "scan_timeout": 0.6, "scan_workers": 256,
                "netbios": True, "mdns": True, "snmp": True, "snmp_communities": ["public"],
                "http_title": True, "vendor_lookup": True, "oui_file": "manuf.txt",
                "oui_url": "https://www.wireshark.org/download/automated/data/manuf"},
    "sites": {"duration_sec": 120, "mirror_sources": "auto", "mirror_dest": "", "iface": "", "top_sites": 10},
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
        "lldp": "show lldp neighbor-information",
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


CMD_ALTERNATIVES = {
    "mac_table": ["show mac address-table", "show mac address-table all", "show mac-address-table"],
    "arp": ["show arp", "show ip arp"],
    "lldp": ["show lldp neighbor-information", "show lldp neighbors"],
}
CLI_ERROR_RE = re.compile(r"Error:|Invalid (?:parameter|input|command)|Unrecognized|Incomplete command|^\s*%", re.I | re.M)


def run_cmd(sw, key):
    """Run CMD[key]; if the switch rejects it, try known alternatives and remember the one that works."""
    tried = []
    for cmd in [CMD.get(key)] + CMD_ALTERNATIVES.get(key, []):
        if not cmd or cmd in tried:
            continue
        tried.append(cmd)
        out = sw.run(cmd)
        if not CLI_ERROR_RE.search(out):
            if cmd != CMD.get(key):
                print(f"  ℹ '{CMD.get(key)}' is not supported here — using '{cmd}' (update config.json to skip this)")
                CMD[key] = cmd
            return out
    return out if tried else ""


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

    raw_mac = run_cmd(sw, "mac_table")
    raw_arp = run_cmd(sw, "arp")
    raw_lldp = run_cmd(sw, "lldp") if CMD.get("lldp") else ""
    if raw_dump is not None:
        raw_dump[CMD["mac_table"]] = raw_mac
        raw_dump[CMD["arp"]] = raw_arp
        if raw_lldp:
            raw_dump[CMD["lldp"]] = raw_lldp
    lldp_rows = parse_lldp(raw_lldp)
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

    identify_devices(devices, cfg, lldp_rows)

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
            "ports": ports, "mgmt_ports": mgmt_ports, "alerts": alerts, "lldp": lldp_rows}


# ======================= Device identification (name, vendor, open ports) =======================
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb", 515: "lpd", 548: "afp", 554: "rtsp",
    631: "ipp", 1433: "mssql", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5000: "upnp/http",
    5060: "sip", 5357: "wsd", 5900: "vnc", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9100: "jetdirect", 37777: "dahua-dvr", 62078: "apple-sync",
}
HTTP_PORTS = (80, 8080, 8000, 8008, 8888, 5000)
HTTPS_PORTS = (443, 8443)


def parse_lldp(text):
    """show lldp neighbor-information → [{port, device_id, port_id, mgmt_ip, port_desc, sys_name}] (fixed-width columns)."""
    lines = text.splitlines()
    hdr = next((l for l in lines if re.search(r"\bPort\b", l) and re.search(r"Device\s*ID", l, re.I)), None)
    if not hdr:
        return []
    names = ["port", "device_id", "port_id", "mgmt_ip", "port_desc", "sys_name"]
    heads = [r"\bPort\b", r"Device\s*ID", r"Port\s*ID", r"management\s*address", r"Port\s*Description", r"System\s*Name"]
    starts = []
    for h in heads:
        m = re.search(h, hdr, re.I)
        starts.append(m.start() if m else None)
    cols = sorted((s, n) for s, n in zip(starts, names) if s is not None)
    rows = []
    for l in lines:
        if not re.match(rf"\s*{PORT_RE}", l):
            continue
        r = {}
        for i, (s, n) in enumerate(cols):
            e = cols[i + 1][0] if i + 1 < len(cols) else None
            r[n] = l[s:e].strip() if len(l) > s else ""
        r["port"] = norm_port(re.search(PORT_RE, l).group(0))
        rows.append(r)
    return rows


def is_random_mac(mac):
    """Locally administered bit set → randomized/virtual MAC (phones with privacy MAC, VMs, hotspots)."""
    return bool(mac) and bool(int(mac[:2], 16) & 2)


_OUI = None


def load_oui(cfg):
    """MAC vendor database (Wireshark 'manuf'), downloaded once and cached next to the script."""
    global _OUI
    if _OUI is not None:
        return _OUI
    _OUI = {}
    dev = cfg.get("devices", {})
    if not dev.get("vendor_lookup", True):
        return _OUI
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dev.get("oui_file") or "manuf.txt")
    if not os.path.exists(path):
        try:
            import urllib.request
            print("  ⬇ Downloading MAC vendor database (one time)...", flush=True)
            req = urllib.request.Request(dev.get("oui_url") or "https://www.wireshark.org/download/automated/data/manuf",
                                         headers={"User-Agent": "switch-monitor"})
            with urllib.request.urlopen(req, timeout=30) as r, open(path, "wb") as f:
                f.write(r.read())
        except Exception as e:
            print(f"  ⚠ Could not download the vendor database ({e}); vendors will be blank.")
            return _OUI
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                pfx, short = parts[0].strip(), parts[1].strip()
                full = parts[2].strip() if len(parts) > 2 and parts[2].strip() else short
                bits = 24
                if "/" in pfx:
                    pfx, b = pfx.split("/")
                    bits = int(b)
                hexs = re.sub(r"[^0-9A-Fa-f]", "", pfx).lower()[: bits // 4]
                _OUI[(bits, hexs)] = full
    except Exception:
        pass
    return _OUI


def mac_vendor(mac, cfg):
    if not mac:
        return None
    if is_random_mac(mac):
        return "Private (random) MAC"
    db = load_oui(cfg)
    h = mac.replace(":", "")
    for bits in (36, 28, 24):
        v = db.get((bits, h[: bits // 4]))
        if v:
            return v
    return None


# ---------- NetBIOS node status (Windows PCs, NAS, many printers) ----------
def netbios_names(ips, timeout=2.0):
    q = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01")
    res = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    try:
        for ip in ips:
            try:
                s.sendto(q, (ip, 137))
            except OSError:
                pass
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                off = 12 + 34 + 4 + 4 + 2          # header + name + type/class + ttl + rdlength
                n = data[off]
                off += 1
                name = group = None
                for i in range(n):
                    raw = data[off + i * 18: off + i * 18 + 18]
                    nm = raw[:15].decode("ascii", "ignore").strip()
                    suffix, flags = raw[15], int.from_bytes(raw[16:18], "big")
                    if suffix == 0x00 and not flags & 0x8000 and not name:
                        name = nm
                    elif suffix == 0x00 and flags & 0x8000 and not group:
                        group = nm
                if name:
                    res[src] = {"name": name, "workgroup": group}
            except Exception:
                pass
    finally:
        s.close()
    return res


# ---------- mDNS reverse lookup (Apple, Linux/Avahi, printers, Chromecast...) ----------
def _dns_name(data, off):
    labels, jumped, end = [], False, off
    for _ in range(64):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        labels.append(data[off + 1: off + 1 + ln].decode("utf-8", "ignore"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def mdns_names(ips, timeout=2.0):
    res = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    try:
        for i, ip in enumerate(ips):
            qname = b"".join(bytes([len(p)]) + p.encode() for p in (ip.split(".")[::-1] + ["in-addr", "arpa"])) + b"\x00"
            pkt = (i & 0xFFFF).to_bytes(2, "big") + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x80\x01"
            try:
                s.sendto(pkt, (ip, 5353))
            except OSError:
                pass
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                qd, an = int.from_bytes(data[4:6], "big"), int.from_bytes(data[6:8], "big")
                off = 12
                for _ in range(qd):
                    _, off = _dns_name(data, off)
                    off += 4
                for _ in range(an):
                    _, off = _dns_name(data, off)
                    typ = int.from_bytes(data[off:off + 2], "big")
                    rdlen = int.from_bytes(data[off + 8:off + 10], "big")
                    off += 10
                    if typ == 12:
                        name, _ = _dns_name(data, off)
                        res[src] = re.sub(r"\.local\.?$", "", name)
                        break
                    off += rdlen
            except Exception:
                pass
    finally:
        s.close()
    return res


# ---------- SNMP v1 sysName / sysDescr (printers, APs, switches, NAS) ----------
def _ber_len(n):
    return bytes([n]) if n < 128 else bytes([0x81, n])


def _ber(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _snmp_get(community, req_id):
    def oid(o):
        p = [int(x) for x in o.split(".")]
        body = bytes([40 * p[0] + p[1]])
        for v in p[2:]:
            enc = [v & 0x7F]
            v >>= 7
            while v:
                enc.insert(0, 0x80 | (v & 0x7F))
                v >>= 7
            body += bytes(enc)
        return _ber(0x06, body)
    binds = b"".join(_ber(0x30, oid(o) + b"\x05\x00") for o in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"))
    pdu = _ber(0xA0, _ber(0x02, req_id.to_bytes(2, "big")) + b"\x02\x01\x00\x02\x01\x00" + _ber(0x30, binds))
    return _ber(0x30, b"\x02\x01\x00" + _ber(0x04, community.encode()) + pdu)


def snmp_info(ips, communities=("public",), timeout=2.0):
    res = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    try:
        for c in communities:
            for i, ip in enumerate(ips):
                try:
                    s.sendto(_snmp_get(c, i + 1), (ip, 161))
                except OSError:
                    pass
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (src, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            # Values follow each OID; pull the OCTET STRINGs (tag 0x04) after the sysName/sysDescr OIDs.
            vals = []
            for marker in (b"\x2b\x06\x01\x02\x01\x01\x05\x00", b"\x2b\x06\x01\x02\x01\x01\x01\x00"):
                k = data.find(marker)
                if k < 0 or k + len(marker) + 2 > len(data) or data[k + len(marker)] != 0x04:
                    vals.append(None)
                    continue
                p = k + len(marker) + 1
                ln = data[p]
                p += 1
                if ln & 0x80:
                    nb = ln & 0x7F
                    ln = int.from_bytes(data[p:p + nb], "big")
                    p += nb
                vals.append(data[p:p + ln].decode("utf-8", "ignore").strip() or None)
            if any(vals) and src not in res:
                res[src] = {"sys_name": vals[0], "sys_descr": vals[1]}
    finally:
        s.close()
    return res


# ---------- TCP port scan + web page title ----------
def port_scan(ips, ports, timeout=0.6, workers=256):
    open_ports = {ip: [] for ip in ips}

    def probe(job):
        ip, port = job
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return ip, port
        except OSError:
            return None

    jobs = [(ip, p) for ip in ips for p in ports]
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, jobs):
            if r:
                open_ports[r[0]].append(r[1])
    return {ip: sorted(p) for ip, p in open_ports.items()}


def http_title(ip, port, https=False, timeout=3):
    """Web page title + Server header, following up to 3 redirects (e.g. http → https login page)."""
    import html
    import http.client
    import ssl
    from urllib.parse import urljoin, urlsplit
    url = f"{'https' if https else 'http'}://{ip}:{port}/"
    server = ""
    try:
        for _ in range(4):
            u = urlsplit(url)
            if u.scheme == "https":
                conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout,
                                                   context=ssl._create_unverified_context())
            else:
                conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
            conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""),
                         headers={"User-Agent": "switch-monitor", "Host": u.netloc})
            r = conn.getresponse()
            body = r.read(65536).decode("utf-8", "ignore")
            server = r.getheader("Server") or server
            loc = r.getheader("Location")
            conn.close()
            if r.status in (301, 302, 303, 307, 308) and loc:
                url = urljoin(url, loc)
                continue
            m = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", body, re.I | re.S)
            title = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:80] if m else ""
            return " | ".join(x for x in (title, server) if x) or None
        return server or None
    except Exception:
        return server or None


def guess_type(d):
    """Best-effort device type from role, open ports, vendor and names."""
    ports = set(d.get("open_ports") or [])
    v = (d.get("vendor") or "").lower()
    txt = " ".join(str(x or "") for x in (d.get("hostname"), d.get("web"), d.get("snmp_descr"), d.get("lldp_name"))).lower()
    if d.get("role") == "gateway":
        return "Router / gateway"
    if d.get("role") == "switch":
        return "This switch"
    if ports & {9100, 515, 631} or re.search(r"printer|laserjet|officejet|epson|canon|brother|kyocera|ricoh|xerox", txt + v):
        return "Printer"
    if ports & {554, 37777} or re.search(r"hikvision|dahua|camera|nvr|dvr|ipc", txt + v):
        return "IP camera / NVR"
    if 62078 in ports or "iphone" in txt or "ipad" in txt:
        return "iPhone / iPad"
    if 3389 in ports or {135, 445} <= ports or "windows" in txt:
        return "Windows PC / server"
    if 548 in ports or "macbook" in txt or "imac" in txt:
        return "Mac"
    if 5060 in ports or re.search(r"yealink|grandstream|polycom|voip|sip", txt + v):
        return "VoIP phone"
    if re.search(r"tp-?link|ubiquiti|mikrotik|cisco|aruba|ruckus|omada|access point|router|switch|huawei tech|"
                 r"zxhn|fiberhome|\bont\b|gpon", txt + v):
        return "Network device (AP/switch/router)"
    if re.search(r"synology|qnap|nas", txt + v):
        return "NAS / storage"
    if "random" in v:
        return "Phone / laptop (private MAC)"
    if re.search(r"samsung|xiaomi|oppo|vivo|realme|oneplus|apple", v):
        return "Phone / tablet / Apple device"
    if 22 in ports and (80 in ports or 443 in ports):
        return "Linux / embedded device"
    if ports & {80, 443, 8080}:
        return "Device with web interface"
    return "Unknown"


def identify_devices(devices, cfg, lldp_rows):
    """Fill in name, name source, vendor, open TCP ports, web title, SNMP info and a type guess for each device."""
    dc = cfg.get("devices", {})
    ips = [d["ip"] for d in devices if d["ip"]]
    t0 = time.time()
    print(f"🪪 Identifying {len(ips)} devices (names, vendors{', open ports' if dc.get('port_scan', True) else ''})...", flush=True)

    lldp_by_mac = {}
    for r in lldp_rows:
        for key in ("device_id", "port_id"):
            mm = re.fullmatch(MAC_RE, r.get(key, "") or "")
            if mm:
                lldp_by_mac[norm_mac(mm.group(1))] = r
    lldp_by_port = {}
    for r in lldp_rows:
        lldp_by_port.setdefault(r["port"], []).append(r)

    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        f_nb = ex.submit(netbios_names, ips) if dc.get("netbios", True) else None
        f_md = ex.submit(mdns_names, ips) if dc.get("mdns", True) else None
        f_sn = ex.submit(snmp_info, ips, tuple(dc.get("snmp_communities") or ["public"])) if dc.get("snmp", True) else None
        f_dns = ex.submit(resolve_names, ips) if cfg["network"].get("resolve_names", True) else None
        f_ps = ex.submit(port_scan, ips, [int(p) for p in dc.get("scan_ports") or SERVICES],
                         float(dc.get("scan_timeout") or 0.6), int(dc.get("scan_workers") or 256)) \
            if dc.get("port_scan", True) else None
        nb = f_nb.result() if f_nb else {}
        md = f_md.result() if f_md else {}
        sn = f_sn.result() if f_sn else {}
        dns = f_dns.result() if f_dns else {}
        ps = f_ps.result() if f_ps else {}

    web_jobs = {}
    if dc.get("http_title", True):
        with cf.ThreadPoolExecutor(max_workers=32) as ex:
            for ip, ports in ps.items():
                hp = next((p for p in ports if p in HTTP_PORTS), None)
                sp = next((p for p in ports if p in HTTPS_PORTS), None)
                if hp or sp:
                    web_jobs[ip] = ex.submit(http_title, ip, hp or sp, https=not hp)
            web = {ip: f.result() for ip, f in web_jobs.items()}
    else:
        web = {}

    for d in devices:
        ip, mac = d["ip"], d["mac"]
        l = lldp_by_mac.get(mac)
        lname = None
        if l:
            for key in ("sys_name", "device_id"):
                v = (l.get(key) or "").strip()
                if v and not re.fullmatch(MAC_RE, v):
                    lname = v
                    break
        d["lldp_name"] = lname
        dns_name = dns.get(ip)
        if dns_name == ip:
            dns_name = None
        candidates = [("LLDP", lname), ("NetBIOS", (nb.get(ip) or {}).get("name")), ("mDNS", md.get(ip)),
                      ("DNS", dns_name), ("SNMP", (sn.get(ip) or {}).get("sys_name"))]
        d["hostname"], d["name_source"] = next(((v, s) for s, v in candidates if v), (None, None))
        d["workgroup"] = (nb.get(ip) or {}).get("workgroup")
        d["vendor"] = mac_vendor(mac, cfg)
        d["open_ports"] = ps.get(ip, []) if ip else []
        d["services"] = [f"{p}/{SERVICES.get(p, 'tcp')}" for p in d["open_ports"]]
        d["web"] = web.get(ip)
        d["snmp_descr"] = (sn.get(ip) or {}).get("sys_descr")
        d["type"] = guess_type(d)

    # A "random" MAC that equals a real device's MAC with only the locally-administered bit flipped
    # is a virtual interface of that same device (routers, Wi-Fi APs, VMs), not a separate phone.
    by_mac = {d["mac"]: d for d in devices if d["mac"]}
    for d in devices:
        if d["mac"] and is_random_mac(d["mac"]):
            base = f"{int(d['mac'][:2], 16) & ~2:02x}" + d["mac"][2:]
            owner = by_mac.get(base)
            if owner:
                label = owner.get("hostname") or owner.get("ip") or owner["mac"]
                d["type"] = f"Virtual MAC of {label}"
                d["vendor"] = owner.get("vendor")
                d["hostname"] = d["hostname"] or owner.get("hostname")

    named = sum(1 for d in devices if d["hostname"])
    print(f"  names found for {named}/{len(devices)} devices "
          f"(LLDP {sum(1 for d in devices if d.get('name_source') == 'LLDP')}, NetBIOS {len(nb)}, mDNS {len(md)}, "
          f"DNS {sum(1 for ip, v in dns.items() if v and v != ip)}, SNMP {len(sn)}) in {time.time() - t0:.0f}s", flush=True)
    return devices


def print_port_devices(disc):
    """Terminal view: every switch port with the devices behind it."""
    print(f"\n🔍 Devices per switch port:")
    by_port = {}
    for d in disc["devices"]:
        by_port.setdefault(d["port"] or "-", []).append(d)
    for p in sorted(by_port, key=lambda x: port_key(x) if x != "-" else (99999,)):
        info = disc["ports"].get(p, {})
        if p == "-":
            head = "Not on this switch (seen via ARP/ping only)"
        else:
            sp = f"{info.get('speed_mbps')}M" if info.get("speed_mbps") else "-"
            tag = " [uplink: switch/AP behind]" if info.get("uplink") else ""
            tag += " [mgmt]" if info.get("mgmt") else ""
            head = f"{p}  ({info.get('link', '?')}, {sp}, {len(by_port[p])} device(s)){tag}"
        print(f"\n  ▸ {head}")
        for d in by_port[p]:
            role = {"gateway": " (gateway)", "this-pc": " (this PC)", "switch": " (this switch)"}.get(d["role"], "")
            name = (d.get("hostname") or "?") + (f" [{d['name_source']}]" if d.get("name_source") else "")
            print(f"     {d['ip'] or '-':<15} {d['mac'] or '-':<17}  {name}{role}")
            print(f"       type: {d.get('type') or '-'}   vendor: {d.get('vendor') or '-'}")
            if d.get("services"):
                print(f"       open ports: {', '.join(d['services'])}")
            if d.get("web"):
                print(f"       web: {d['web']}")
            if d.get("snmp_descr"):
                print(f"       snmp: {d['snmp_descr'][:100]}")


# ======================= Websites / social media / browser per IP =======================
# domain suffix → (display name, category)
SITE_DB = {
    # Social media
    "facebook.com": ("Facebook", "Social media"), "fbcdn.net": ("Facebook", "Social media"),
    "fb.com": ("Facebook", "Social media"), "facebook.net": ("Facebook", "Social media"),
    "fbsbx.com": ("Facebook", "Social media"), "messenger.com": ("Messenger", "Messaging"),
    "instagram.com": ("Instagram", "Social media"), "cdninstagram.com": ("Instagram", "Social media"),
    "tiktok.com": ("TikTok", "Social media"), "tiktokcdn.com": ("TikTok", "Social media"),
    "tiktokv.com": ("TikTok", "Social media"), "tiktokcdn-us.com": ("TikTok", "Social media"),
    "byteoversea.com": ("TikTok", "Social media"), "ibytedtos.com": ("TikTok", "Social media"),
    "musical.ly": ("TikTok", "Social media"), "twitter.com": ("X (Twitter)", "Social media"),
    "x.com": ("X (Twitter)", "Social media"), "twimg.com": ("X (Twitter)", "Social media"),
    "t.co": ("X (Twitter)", "Social media"), "snapchat.com": ("Snapchat", "Social media"),
    "sc-cdn.net": ("Snapchat", "Social media"), "snapkit.com": ("Snapchat", "Social media"),
    "linkedin.com": ("LinkedIn", "Social media"), "licdn.com": ("LinkedIn", "Social media"),
    "pinterest.com": ("Pinterest", "Social media"), "pinimg.com": ("Pinterest", "Social media"),
    "reddit.com": ("Reddit", "Social media"), "redd.it": ("Reddit", "Social media"),
    "redditmedia.com": ("Reddit", "Social media"), "threads.net": ("Threads", "Social media"),
    "tumblr.com": ("Tumblr", "Social media"), "vk.com": ("VK", "Social media"),
    # Messaging
    "whatsapp.com": ("WhatsApp", "Messaging"), "whatsapp.net": ("WhatsApp", "Messaging"),
    "telegram.org": ("Telegram", "Messaging"), "t.me": ("Telegram", "Messaging"),
    "telegram.me": ("Telegram", "Messaging"), "telesco.pe": ("Telegram", "Messaging"),
    "signal.org": ("Signal", "Messaging"), "viber.com": ("Viber", "Messaging"),
    "discord.com": ("Discord", "Messaging"), "discord.gg": ("Discord", "Messaging"),
    "discordapp.com": ("Discord", "Messaging"), "discordapp.net": ("Discord", "Messaging"),
    "skype.com": ("Skype", "Messaging"), "imo.im": ("imo", "Messaging"), "botim.me": ("BOTIM", "Messaging"),
    "zoom.us": ("Zoom", "Meetings"), "zoom.com": ("Zoom", "Meetings"),
    "teams.microsoft.com": ("Microsoft Teams", "Meetings"), "teams.live.com": ("Microsoft Teams", "Meetings"),
    "meet.google.com": ("Google Meet", "Meetings"), "anydesk.com": ("AnyDesk", "Remote access"),
    "teamviewer.com": ("TeamViewer", "Remote access"),
    # Video / streaming / music
    "youtube.com": ("YouTube", "Video"), "googlevideo.com": ("YouTube", "Video"),
    "ytimg.com": ("YouTube", "Video"), "youtu.be": ("YouTube", "Video"),
    "youtube-nocookie.com": ("YouTube", "Video"), "netflix.com": ("Netflix", "Video"),
    "nflxvideo.net": ("Netflix", "Video"), "nflximg.net": ("Netflix", "Video"),
    "shahid.net": ("Shahid", "Video"), "mbc.net": ("Shahid", "Video"), "watchit.com": ("WATCH IT", "Video"),
    "osnplus.com": ("OSN+", "Video"), "primevideo.com": ("Prime Video", "Video"),
    "disneyplus.com": ("Disney+", "Video"), "twitch.tv": ("Twitch", "Video"), "ttvnw.net": ("Twitch", "Video"),
    "vimeo.com": ("Vimeo", "Video"), "dailymotion.com": ("Dailymotion", "Video"),
    "spotify.com": ("Spotify", "Music"), "scdn.co": ("Spotify", "Music"), "anghami.com": ("Anghami", "Music"),
    "soundcloud.com": ("SoundCloud", "Music"), "deezer.com": ("Deezer", "Music"),
    # Search / AI
    "google.com": ("Google", "Search"), "google.com.eg": ("Google", "Search"), "bing.com": ("Bing", "Search"),
    "yahoo.com": ("Yahoo", "Search"), "duckduckgo.com": ("DuckDuckGo", "Search"),
    "yandex.ru": ("Yandex", "Search"), "yandex.com": ("Yandex", "Search"),
    "openai.com": ("ChatGPT", "AI"), "chatgpt.com": ("ChatGPT", "AI"), "oaiusercontent.com": ("ChatGPT", "AI"),
    "claude.ai": ("Claude", "AI"), "anthropic.com": ("Claude", "AI"), "gemini.google.com": ("Gemini", "AI"),
    "deepseek.com": ("DeepSeek", "AI"), "perplexity.ai": ("Perplexity", "AI"), "copilot.microsoft.com": ("Copilot", "AI"),
    # Email / office / cloud
    "mail.google.com": ("Gmail", "Email"), "gmail.com": ("Gmail", "Email"),
    "outlook.com": ("Outlook", "Email"), "outlook.office.com": ("Outlook", "Email"),
    "outlook.office365.com": ("Outlook", "Email"), "mail.yahoo.com": ("Yahoo Mail", "Email"),
    "office.com": ("Microsoft 365", "Office"), "office.net": ("Microsoft 365", "Office"),
    "sharepoint.com": ("SharePoint/OneDrive", "Cloud storage"), "onedrive.live.com": ("OneDrive", "Cloud storage"),
    "drive.google.com": ("Google Drive", "Cloud storage"), "docs.google.com": ("Google Docs", "Office"),
    "dropbox.com": ("Dropbox", "Cloud storage"), "dropboxapi.com": ("Dropbox", "Cloud storage"),
    "icloud.com": ("iCloud", "Cloud storage"), "mega.nz": ("MEGA", "Cloud storage"),
    "wetransfer.com": ("WeTransfer", "Cloud storage"),
    # Shopping / finance
    "amazon.com": ("Amazon", "Shopping"), "amazon.eg": ("Amazon", "Shopping"), "amazon.sa": ("Amazon", "Shopping"),
    "noon.com": ("noon", "Shopping"), "jumia.com.eg": ("Jumia", "Shopping"), "aliexpress.com": ("AliExpress", "Shopping"),
    "alibaba.com": ("Alibaba", "Shopping"), "temu.com": ("Temu", "Shopping"), "shein.com": ("SHEIN", "Shopping"),
    "ebay.com": ("eBay", "Shopping"), "olx.com.eg": ("OLX", "Shopping"), "paypal.com": ("PayPal", "Finance"),
    "binance.com": ("Binance", "Finance"),
    # News / reference
    "wikipedia.org": ("Wikipedia", "Reference"), "bbc.com": ("BBC", "News"), "bbc.co.uk": ("BBC", "News"),
    "cnn.com": ("CNN", "News"), "aljazeera.net": ("Al Jazeera", "News"), "youm7.com": ("Youm7", "News"),
    "masrawy.com": ("Masrawy", "News"), "elwatannews.com": ("El Watan", "News"), "ahram.org.eg": ("Al-Ahram", "News"),
    "skynewsarabia.com": ("Sky News Arabia", "News"), "filgoal.com": ("FilGoal", "Sports"), "kooora.com": ("Kooora", "Sports"),
    # Gaming
    "steampowered.com": ("Steam", "Gaming"), "steamcontent.com": ("Steam", "Gaming"), "epicgames.com": ("Epic Games", "Gaming"),
    "roblox.com": ("Roblox", "Gaming"), "pubgmobile.com": ("PUBG Mobile", "Gaming"), "igamecj.com": ("PUBG Mobile", "Gaming"),
    "freefiremobile.com": ("Free Fire", "Gaming"), "supercell.com": ("Supercell games", "Gaming"),
    "xboxlive.com": ("Xbox Live", "Gaming"), "playstation.net": ("PlayStation", "Gaming"),
    # Dev / work
    "github.com": ("GitHub", "Development"), "githubusercontent.com": ("GitHub", "Development"),
    "stackoverflow.com": ("Stack Overflow", "Development"),
}

# Background/system traffic: counted but hidden from "top websites" so real browsing stands out.
NOISE_SUFFIXES = (
    "gstatic.com", "googleapis.com", "googleusercontent.com", "googlesyndication.com", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "googleadservices.com", "gvt1.com", "gvt2.com", "1e100.net",
    "windowsupdate.com", "update.microsoft.com", "msftncsi.com", "msftconnecttest.com", "microsoft.com",
    "live.com", "windows.com", "windows.net", "msn.com", "bing.net", "msedge.net", "azureedge.net",
    "akamaized.net", "akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net", "cloudfront.net",
    "cloudflare.com", "cloudflare-dns.com", "fastly.net", "llnwd.net", "apple.com", "icloud-content.com",
    "mzstatic.com", "aaplimg.com", "digicert.com", "lencr.org", "sectigo.com", "globalsign.com", "pki.goog",
    "ocsp.", "crl.", "in-addr.arpa", "local", "lan", "localdomain", "wpad", "mozilla.com", "mozilla.net",
    "mozilla.org", "firefox.com", "xiaomi.net", "miui.com", "samsungcloudsolution.com", "samsungapps.com",
    "tp-link.com", "tplinkcloud.com", "ntp.org", "time.windows.com", "adnxs.com", "criteo.com", "taboola.com",
    "scorecardresearch.com", "hotjar.com", "appsflyer.com", "adjust.com", "branch.io", "crashlytics.com",
    "app-measurement.com", "firebaseio.com", "amazonaws.com", "azure.com", "office365.com", "trafficmanager.net",
)

# Hosts that only a given browser contacts in the background → "likely browser"
BROWSER_HINTS = {
    "Microsoft Edge": ("edge.microsoft.com", "msedge.net", "edge.activity.windows.com", "ntp.msn.com",
                       "config.edge.skype.com", "msedge.api.cdp.microsoft.com"),
    "Google Chrome": ("optimizationguide-pa.googleapis.com", "content-autofill.googleapis.com",
                      "clientservices.googleapis.com", "chromewebstore.googleapis.com", "chrome.google.com",
                      "chromesyncpasswords-pa.googleapis.com", "redirector.gvt1.com"),
    "Mozilla Firefox": ("firefox.settings.services.mozilla.com", "detectportal.firefox.com",
                        "push.services.mozilla.com", "incoming.telemetry.mozilla.org", "aus5.mozilla.org",
                        "content-signature-2.cdn.mozilla.net", "firefox-settings-attachments.cdn.mozilla.net"),
    "Opera": ("opera.com", "operacdn.com", "opera-api.com", "opera-api2.com"),
    "Brave": ("brave.com", "bravesoftware.com", "brave.software"),
    "Yandex Browser": ("browser.yandex.net", "api.browser.yandex.net"),
    "Samsung Internet": ("samsungbrowser", "sbrowser.samsung"),
}

TWO_LEVEL_SLD = {"com", "co", "net", "org", "gov", "edu", "ac", "sch", "gob", "mil"}


def site_of(host):
    """Map a hostname to (site name, category, registered domain)."""
    h = host.lower().rstrip(".")
    parts = h.split(".")
    for i in range(len(parts) - 1):
        suf = ".".join(parts[i:])
        if suf in SITE_DB:
            name, cat = SITE_DB[suf]
            return name, cat, suf
    if len(parts) >= 3 and parts[-2] in TWO_LEVEL_SLD and len(parts[-1]) == 2:
        reg = ".".join(parts[-3:])
    else:
        reg = ".".join(parts[-2:])
    return None, None, reg


def is_noise(host):
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) or (s.endswith(".") and h.startswith(s)) for s in NOISE_SUFFIXES) \
        or "." not in h


def parse_user_agent(ua):
    """Return (browser, os) from an HTTP User-Agent string."""
    b = ("Microsoft Edge" if re.search(r"Edg(e|A|iOS)?/", ua) else
         "Opera" if re.search(r"OPR/|Opera", ua) else
         "Samsung Internet" if "SamsungBrowser" in ua else
         "Yandex Browser" if "YaBrowser" in ua else
         "Mozilla Firefox" if re.search(r"Firefox/|FxiOS", ua) else
         "Google Chrome" if re.search(r"Chrome/|CriOS", ua) else
         "Safari" if "Safari/" in ua and "Version/" in ua else None)
    o = ("Windows" if "Windows" in ua else "Android" if "Android" in ua else
         "iOS" if re.search(r"iPhone|iPad", ua) else "macOS" if "Mac OS X" in ua else
         "Linux" if "Linux" in ua else None)
    return b, o


# ---------- packet parsing (works on raw IPv4 packets from any capture source) ----------
def _dns_qname(payload):
    if len(payload) < 13 or payload[2] & 0x80:      # only queries (QR=0)
        return None
    if int.from_bytes(payload[4:6], "big") < 1:
        return None
    try:
        name, _ = _dns_name(payload, 12)
        return name or None
    except Exception:
        return None


def _tls_sni(p):
    """Server name from a TLS ClientHello (record type 0x16, handshake type 1)."""
    try:
        if len(p) < 43 or p[0] != 0x16 or p[5] != 0x01:
            return None
        i = 9 + 2 + 32                                   # record+handshake headers, version, random
        i += 1 + p[i]                                    # session id
        i += 2 + int.from_bytes(p[i:i + 2], "big")       # cipher suites
        i += 1 + p[i]                                    # compression
        end = i + 2 + int.from_bytes(p[i:i + 2], "big")
        i += 2
        while i + 4 <= min(end, len(p)):
            et, el = int.from_bytes(p[i:i + 2], "big"), int.from_bytes(p[i + 2:i + 4], "big")
            if et == 0:                                  # server_name
                ln = int.from_bytes(p[i + 7:i + 9], "big")
                return p[i + 9:i + 9 + ln].decode("ascii", "ignore") or None
            i += 4 + el
    except Exception:
        pass
    return None


def parse_ip_packet(pkt):
    """IPv4 packet → (src_ip, kind, value) for DNS queries, TLS SNI, HTTP Host / User-Agent; or None."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    seg = pkt[ihl:]
    if proto == 17 and len(seg) >= 8:                    # UDP
        dport = int.from_bytes(seg[2:4], "big")
        if dport in (53, 5353):
            q = _dns_qname(seg[8:])
            return [(src, "dns", q)] if q and dport == 53 else None
    elif proto == 6 and len(seg) >= 20:                  # TCP
        dport = int.from_bytes(seg[2:4], "big")
        data = seg[(seg[12] >> 4) * 4:]
        if not data:
            return None
        if data[0] == 0x16:
            sni = _tls_sni(data)
            return [(src, "sni", sni)] if sni else None
        if data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or data[:7] == b"OPTIONS":
            head = data[:4096].decode("latin-1", "ignore")
            out = []
            m = re.search(r"^Host:\s*([^\r\n:]+)", head, re.I | re.M)
            if m:
                out.append((src, "http", m.group(1).strip()))
            m = re.search(r"^User-Agent:\s*([^\r\n]+)", head, re.I | re.M)
            if m:
                out.append((src, "ua", m.group(1).strip()))
            return out or None
        if dport == 53 and len(data) > 2:                # DNS over TCP
            q = _dns_qname(data[2:])
            return [(src, "dns", q)] if q else None
    return None


def _eth_to_ip(frame):
    """Strip Ethernet (and 802.1Q tags) → IPv4 packet bytes, or None."""
    i, et = 12, int.from_bytes(frame[12:14], "big")
    while et in (0x8100, 0x88A8) and len(frame) >= i + 6:
        i += 4
        et = int.from_bytes(frame[i:i + 2], "big")
    return frame[i + 2:] if et == 0x0800 else None


def read_pcap(path):
    """Yield IPv4 packets from a classic pcap file (Ethernet or raw-IP link type)."""
    import struct
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            incl = struct.unpack(endian + "I", ph[8:12])[0]
            data = f.read(incl)
            if link == 1:
                ip = _eth_to_ip(data)
                if ip:
                    yield ip
            elif link in (101, 228, 12):
                yield data


def find_tshark():
    t = shutil.which("tshark")
    if t:
        return t
    for p in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.exists(p):
            return p
    return None


def is_admin():
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def local_ip_towards(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def capture_packets(seconds, local_ip, out_dir, iface=None):
    """
    Capture for `seconds` and yield IPv4 packets.
    Order: tshark (Npcap) if installed → built-in raw socket (needs Administrator / root).
    """
    tshark = find_tshark()
    if tshark:
        pcap = os.path.join(out_dir, f"sites_{datetime.now():%Y%m%d_%H%M%S}.pcap")
        cmd = [tshark, "-q", "-a", f"duration:{seconds}", "-F", "pcap", "-w", pcap,
               "-f", "udp port 53 or tcp port 53 or tcp port 443 or tcp port 80"]
        if iface:
            cmd[1:1] = ["-i", iface]
        print(f"  ⏺ Capturing with tshark for {seconds}s...", flush=True)
        subprocess.run(cmd, capture_output=True, text=True)
        if os.path.exists(pcap):
            yield from read_pcap(pcap)
            return
        print("  ⚠ tshark produced no capture file — falling back to the built-in capture.")
    if not is_admin():
        raise RuntimeError("Capturing traffic needs Administrator rights (or Wireshark/tshark installed). "
                           "Open PowerShell with 'Run as administrator' and run the script again.")
    print(f"  ⏺ Capturing (built-in) on {local_ip} for {seconds}s...", flush=True)
    if platform.system().lower() == "windows":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)     # promiscuous: also see mirrored traffic
        strip = lambda b: b
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            s.bind((iface, 0))
        strip = _eth_to_ip
    s.settimeout(0.5)
    end = time.time() + seconds
    try:
        while time.time() < end:
            try:
                data = s.recvfrom(65535)[0]
            except socket.timeout:
                continue
            ip = strip(data)
            if ip:
                yield ip
    finally:
        if platform.system().lower() == "windows":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()


def summarize_sites(events, net, devices, top=10):
    """Aggregate (src, kind, value) events into a per-IP summary."""
    from collections import Counter
    per = {}
    for src, kind, val in events:
        try:
            if ipaddress.ip_address(src) not in net:
                continue
        except ValueError:
            continue
        p = per.setdefault(src, {"hosts": Counter(), "uas": set()})
        if kind == "ua":
            p["uas"].add(val)
        else:
            p["hosts"][val.lower().rstrip(".")] += 1

    by_ip = {d["ip"]: d for d in devices if d.get("ip")}
    out = []
    for ip, p in per.items():
        apps, cats, sites = Counter(), Counter(), Counter()
        browsers, oses = {}, set()
        for h, n in p["hosts"].items():
            for b, hints in BROWSER_HINTS.items():
                if any(h == x or h.endswith("." + x) or (x in h and "." not in x) for x in hints):
                    browsers.setdefault(b, "background traffic")
            name, cat, reg = site_of(h)
            if name:
                apps[name] += n
                cats[cat] += n
            elif not is_noise(h):
                sites[reg] += n
        for ua in p["uas"]:
            b, o = parse_user_agent(ua)
            if b:
                browsers[b] = "user-agent"
            if o:
                oses.add(o)
        d = by_ip.get(ip, {})
        out.append({
            "ip": ip, "hostname": d.get("hostname"), "port": d.get("port"), "type": d.get("type"),
            "social": sorted({a for a in apps if SITE_DB_CAT.get(a) in ("Social media", "Messaging")}),
            "apps": [{"name": a, "category": SITE_DB_CAT.get(a), "hits": n} for a, n in apps.most_common()],
            "top_sites": [{"domain": s, "hits": n} for s, n in sites.most_common(top)],
            "categories": dict(cats.most_common()),
            "browsers": [{"name": b, "evidence": e} for b, e in browsers.items()],
            "os": sorted(oses), "user_agents": sorted(p["uas"])[:5],
            "lookups": sum(p["hosts"].values()),
        })
    out.sort(key=lambda r: (-r["lookups"]))
    return out


SITE_DB_CAT = {name: cat for name, cat in SITE_DB.values()}


def mirror_sources_auto(disc):
    """Ports to mirror so that all internet + DNS traffic is seen: the gateway's port and the local DNS servers' ports."""
    ports = []
    for d in disc.get("devices", []):
        if d.get("port") and (d.get("role") == "gateway" or (53 in (d.get("open_ports") or []) and not d.get("behind_uplink"))):
            ports.append(d["port"])
    return sorted(set(ports), key=port_key)


def sites_monitor(sw, cfg, disc, args, out_dir):
    """Mirror the gateway/DNS ports to this PC's port, capture, and report websites/apps/browsers per IP."""
    sc = cfg.get("sites", {})
    seconds = int(args.sites_secs or sc.get("duration_sec") or 120)
    srcs = [x.strip() for x in str(sc.get("mirror_sources") or "auto").split(",") if x.strip()]
    if srcs == ["auto"]:
        srcs = mirror_sources_auto(disc)
    dest = args.mirror_dest or sc.get("mirror_dest") or (disc.get("mgmt_ports") or [None])[0]
    if not srcs or not dest:
        raise RuntimeError("Could not determine mirror ports (set sites.mirror_sources / sites.mirror_dest in config.json).")
    if not find_tshark() and not is_admin():          # check before touching the switch config
        raise RuntimeError("Capturing traffic needs Administrator rights (or Wireshark/tshark installed). "
                           "Open PowerShell with 'Run as administrator' and run the script again.")
    norm = lambda p: re.search(r"\d+/\d+/\d+", p).group(0)
    srcs = [s for s in srcs if norm(s) != norm(dest)]
    print(f"🌍 Website/app monitoring for {seconds}s — mirroring {', '.join(srcs)} → {dest} (this PC)")
    print("  ℹ Monitor users' traffic only on networks you manage and in line with your organisation's policy.")
    session = cfg["mirror"]["session"]
    net = ipaddress.ip_network(disc["subnet"])
    local_ip = local_ip_towards(cfg["switch"]["host"])
    events = []
    lines = [f"no monitor session {session}",
             f"monitor session {session} destination interface gigabitEthernet {norm(dest)}"]
    lines += [f"monitor session {session} source interface gigabitEthernet {norm(s)} both" for s in srcs]
    sw.config(lines)
    try:
        for pkt in capture_packets(seconds, local_ip, out_dir, sc.get("iface") or None):
            r = parse_ip_packet(pkt)
            if r:
                events.extend(r)
    finally:
        try:
            sw.config([f"no monitor session {session}"])
        except Exception:
            # The SSH session may have dropped; reconnect once just to remove the mirror.
            sw2 = SwitchSSH(sw.host, sw.user, sw.password, sw.port, sw.enable_pass, sw.timeout).connect()
            sw2.config([f"no monitor session {session}"])
            sw2.close()
        print("  🧹 Port mirroring removed.")
    res = summarize_sites(events, net, disc.get("devices", []), int(sc.get("top_sites") or 10))
    print(f"  {len(events)} lookups/connections captured from {len(res)} device(s).")
    return {"duration_sec": seconds, "mirror_sources": srcs, "mirror_dest": dest, "devices": res}


def print_sites(sites):
    print(f"\n🌍 Websites, apps & browsers per device ({sites['duration_sec']}s sample):")
    if not sites["devices"]:
        print("  No traffic captured — check that mirroring reached this PC (see README).")
    for r in sites["devices"]:
        who = r["hostname"] or "?"
        print(f"\n  ▸ {r['ip']}  {who}  ({r['port'] or '-'}, {r['type'] or '-'})  — {r['lookups']} lookups")
        if r["browsers"]:
            print("     browser: " + ", ".join(f"{b['name']} ({b['evidence']})" for b in r["browsers"])
                  + (f"   os: {', '.join(r['os'])}" if r["os"] else ""))
        if r["social"]:
            print("     social/messaging: " + ", ".join(r["social"]))
        other = [a["name"] for a in r["apps"] if a["name"] not in r["social"]]
        if other:
            print("     apps/sites: " + ", ".join(other[:12]))
        if r["top_sites"]:
            print("     other sites: " + ", ".join(f"{s['domain']} ({s['hits']})" for s in r["top_sites"]))


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
    print_port_devices(disc)


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

    def table(headers, rows, fills=None, widths=None, size=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for c, h in zip(t.rows[0].cells, headers):
            add_text(c.paragraphs[0], h, bold=True, color="FFFFFF", size=size)
            shade(c, HEAD)
        for i, row in enumerate(rows):
            cells = t.add_row().cells
            for c, v in zip(cells, row):
                add_text(c.paragraphs[0], "" if v is None else v, size=size)
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
        heading(f"Devices per Switch Port ({len(disc['devices'])}) — Subnet {disc.get('subnet', '')}")
        role = {"gateway": " (gateway)", "this-pc": " (this PC)", "switch": " (this switch)"}
        rows = []
        for d in disc["devices"]:
            name = (d.get("hostname") or "?") + (f"\n[{d['name_source']}]" if d.get("name_source") else "")
            extra = "\n".join(x for x in (d.get("web") and f"web: {d['web']}",
                                          d.get("snmp_descr") and f"snmp: {d['snmp_descr'][:120]}") if x)
            rows.append(((d["port"] or "-") + (" *" if d["behind_uplink"] else ""),
                         f"{d['ip'] or '-'}\n{d['mac'] or '-'}",
                         name + role.get(d["role"], ""),
                         f"{d.get('type') or '-'}\n{d.get('vendor') or ''}".strip(),
                         ", ".join(d.get("services") or []) or "-",
                         extra or "-"))
        table(["Port", "IP / MAC", "Name [source]", "Type / vendor", "Open ports", "Web / SNMP"], rows,
              [None if d["port"] else YELLOW for d in disc["devices"]], widths=[8, 15, 15, 17, 18, 22], size=8)
        para("* Behind an uplink port (another switch or access point).  Yellow: device not seen on this switch.  "
             "Name sources: LLDP (switch), NetBIOS, mDNS, DNS, SNMP.", color="777777", size=8)

    # ---------- Websites / apps / browsers ----------
    sites = report.get("sites")
    if sites:
        heading(f"Websites, Social Media & Browsers per Device ({sites['duration_sec']}s sample)")
        para(f"Mirrored ports: {', '.join(sites['mirror_sources'])} → {sites['mirror_dest']}.  "
             "Browser 'user-agent' = exact (unencrypted HTTP); 'background traffic' = inferred from the "
             "browser's own update/service servers.", color="777777", size=8)
        rows, fills = [], []
        for r in sites["devices"]:
            other = [a["name"] for a in r["apps"] if a["name"] not in r["social"]]
            rows.append((f"{r['ip']}\n{r['hostname'] or '?'}\n{r['port'] or '-'}",
                         "\n".join(f"{b['name']} ({b['evidence']})" for b in r["browsers"]) or "-",
                         ", ".join(r["social"]) or "-",
                         ", ".join(other[:12]) or "-",
                         ", ".join(f"{s['domain']} ({s['hits']})" for s in r["top_sites"]) or "-"))
            fills.append(YELLOW if r["social"] else None)
        if rows:
            table(["Device", "Browser", "Social / messaging", "Apps & known sites", "Other sites (lookups)"],
                  rows, fills, widths=[14, 15, 16, 22, 28], size=8)
        else:
            para("No traffic captured during the sample.")

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
def tcp_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def save_config_values(path, section, values):
    """Update a few keys in config.json in place (keeps every other setting as the user wrote it)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault(section, {}).update(values)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"  ⚠ Could not update {path}: {e}")
        return False


def locate_switch(args, cfg):
    """
    The switch did not answer at its configured IP (usually its DHCP address changed).
    Find it again by its MAC address: ping-sweep the subnet, then look the MAC up in the ARP table.
    """
    mac = norm_mac(cfg["switch"].get("mac") or "")
    if not is_unicast(mac):
        return None
    net_c = cfg["network"]
    net = ipaddress.ip_network(net_c.get("subnet") or f"{net_c.get('gateway') or args.host}/24", strict=False)
    print(f"🔎 Looking for the switch (MAC {mac}) on {net}...", flush=True)
    ping_sweep(net, int(net_c.get("scan_workers") or 64))
    for ip, m in local_arp().items():
        if m == mac and tcp_open(ip, args.port):
            return ip
    return None


def connect_switch(args, cfg):
    """Connect over SSH; if the switch moved to another IP, find it by MAC and update config.json."""
    if not tcp_open(args.host, args.port):
        print(f"⚠ The switch does not answer at {args.host}:{args.port}.")
        new = locate_switch(args, cfg)
        if not new:
            hint = ("" if cfg["switch"].get("mac") else
                    " Set \"mac\" under \"switch\" in config.json so the script can find it automatically.")
            raise RuntimeError(f"Cannot reach the switch at {args.host}:{args.port} (no reply). Check that it is powered on, "
                               f"connected, and that its IP has not changed (look it up in the router's DHCP list).{hint}")
        print(f"✅ Switch found at its new IP {new} (was {args.host}).")
        if save_config_values(args.config, "switch", {"host": new}):
            print(f"  📝 config.json updated: switch.host = {new}.  Tip: give the switch a static IP or a DHCP "
                  f"reservation on the router so it stops changing.")
        args.host = cfg["switch"]["host"] = new
    sw = SwitchSSH(args.host, args.user, args.password, args.port, args.enable_pass,
                   cfg["switch"]["timeout"]).connect()
    # Remember the switch's MAC so it can be found again if its IP changes.
    if not cfg["switch"].get("mac"):
        try:
            line = next((l for l in sw.run(CMD["sysinfo"]).splitlines() if re.search(r"Mac\s*Address", l, re.I)), "")
            mm = re.search(MAC_RE, line)
            if mm:
                cfg["switch"]["mac"] = norm_mac(mm.group(1))
                save_config_values(args.config, "switch", {"mac": cfg["switch"]["mac"]})
        except Exception:
            pass
    return sw


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

    sw = connect_switch(args, cfg)
    report["switch"] = args.host
    print(f"🔐 Connected to switch {args.host} via {sw.mode}")
    try:
        status = None
        if (args.scan or args.cables or args.sites) and not (args.health or args.all):
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
        if args.scan or args.all or args.sites:          # --sites needs the device map
            disc = discover_network(sw, cfg, status or {}, raw)
            report["discovery"] = disc
        if args.cables or args.all:
            print("🔌 Testing cables (Cable Diagnostics / TDR)...")
            mgmt = disc["mgmt_ports"] if disc else []
            if not disc and cfg["cables"].get("skip_mgmt_port", True):
                mac_rows = parse_mac_table(run_cmd(sw, "mac_table"))
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

        if args.sites:
            try:
                report["sites"] = sites_monitor(sw, cfg, disc, args, cfg["output"]["out_dir"])
                print_sites(report["sites"])
            except RuntimeError as e:
                print(f"⚠ Website monitoring skipped: {e}")

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
    p.add_argument("--no-port-scan", action="store_true", help="Identify devices without scanning their TCP ports")
    p.add_argument("--sites", action="store_true",
                   help="Show websites/social media/browser per IP (mirrors the gateway port to this PC; needs admin or tshark)")
    p.add_argument("--sites-secs", type=int, default=None, help="How long to sample traffic for --sites (seconds)")
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

    if not (args.health or args.traffic or args.scan or args.cables or args.sites or args.all):
        args.all = True
    if args.subnet:
        cfg["network"]["subnet"] = args.subnet
    if args.no_port_scan:
        cfg["devices"]["port_scan"] = False
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
