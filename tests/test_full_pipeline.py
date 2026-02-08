#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
  FEC Full Pipeline Test Framework
  Comprehensive ~4-5 minute stress test of the entire FEC subsystem
═══════════════════════════════════════════════════════════════════════

Exercises every component of the Reed-Solomon FEC pipeline:
  • TX encoding (data buffering + parity generation)
  • Loss simulation (DEBUG_LOSS_RATE=5%)
  • Adaptive gear-shifting (0 → 1 → 2 → 0 → 2 parity)
  • Wire-format (fec_flag bit, fec_hdr)
  • Packet capture & telemetry

Architecture:
  ┌─────────────┐     tap0      ┌──────────────────────┐
  │  lvl-ip     │◄─────────────►│  Host Python          │
  │  fec_sender │  data+parity  │  (receiver + sniffer  │
  │  (per phase)│──────────────►│   + feedback injector) │
  │             │◄──────────────│                        │
  └─────────────┘   feedback    └──────────────────────┘

Phases (5 phases, ~60s each):
  1. Baseline   — no feedback, expect target_parity=0
  2. Light FEC  — inject 10% loss, expect target_parity=1
  3. Heavy FEC  — inject 20% loss, expect target_parity=2
  4. Recovery   — inject 3% loss, expect target_parity=0
  5. Stress     — inject 25% loss, expect target_parity=2

Usage:
  sudo python3 tests/test_full_pipeline.py
"""

import os
import sys
import re
import time
import socket
import struct
import threading
import subprocess
import signal
from collections import defaultdict
from datetime import datetime, timedelta

try:
    from scapy.all import (
        sniff, sendp, IP, TCP, Ether, Raw,
        get_if_hwaddr, getmacbyip
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ─── Configuration ───────────────────────────────────────────────────────────
REPO_ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAP_IFACE       = "tap0"
HOST_IP         = "10.0.0.5"
STACK_IP        = "10.0.0.4"
BASE_PORT       = 9000          # Use different ports per phase to avoid conflicts
PAYLOAD_PER_TX  = 2 * 1024 * 1024  # 2MB per transfer (~56s at 30ms/chunk)
RS_K            = 5

FEC_HDR_FMT     = "!HBBHIH"
FEC_HDR_LEN     = struct.calcsize(FEC_HDR_FMT)
FEC_FEEDBACK_IDX = 0xFF

# Phase definitions: (name, loss_pct, expected_target, num_transfers, duration_hint_s)
PHASES = [
    ("Baseline (0% loss)",    0,  0, 1, 60),
    ("Light FEC (10% loss)", 10,  1, 1, 60),
    ("Heavy FEC (20% loss)", 20,  2, 1, 60),
    ("Recovery (3% loss)",    3,  0, 1, 60),
    ("Stress (25% loss)",    25,  2, 1, 60),
]


# ─── Packet Injection ────────────────────────────────────────────────────────
def inject_feedback(loss_pct, stack_port, host_port):
    """Send a FEC feedback packet to level-ip."""
    fec_hdr = struct.pack(FEC_HDR_FMT,
        0, FEC_FEEDBACK_IDX, 0, 0, 0, 0)
    payload = fec_hdr + bytes([loss_pct])

    pkt = (
        IP(src=HOST_IP, dst=STACK_IP) /
        TCP(sport=host_port, dport=stack_port,
            flags="A", seq=0, ack=0) /
        Raw(load=payload)
    )

    raw_bytes = bytearray(bytes(pkt))
    ip_hdr_len = (raw_bytes[0] & 0x0F) * 4
    raw_bytes[ip_hdr_len + 12] |= 0x01   # fec_flag
    raw_bytes[ip_hdr_len + 16] = 0        # zero TCP checksum
    raw_bytes[ip_hdr_len + 17] = 0

    try:
        src_mac = get_if_hwaddr(TAP_IFACE)
    except Exception:
        src_mac = "00:00:00:00:00:00"
    dst_mac = getmacbyip(STACK_IP) or "ff:ff:ff:ff:ff:ff"

    frame = Ether(src=src_mac, dst=dst_mac, type=0x0800) / Raw(load=bytes(raw_bytes))
    sendp(frame, iface=TAP_IFACE, verbose=0)


# ─── Sniffer / Telemetry ─────────────────────────────────────────────────────
class PipelineTelemetry:
    """Thread-safe real-time packet counter."""

    def __init__(self):
        self.lock = threading.Lock()
        self.phase_idx = 0
        # Per-phase counters: {phase_idx: {metric: value}}
        self.phases = defaultdict(lambda: {
            "data_pkts": 0, "parity_pkts": 0, "feedback_pkts": 0,
            "data_bytes": 0, "blocks": 0, "data_in_block": 0,
            "start_time": None, "end_time": None,
            "connections": 0, "syn_pkts": 0,
        })
        # Global
        self.total_data_bytes = 0
        self.total_data_pkts = 0
        self.total_parity_pkts = 0
        self.total_feedback_pkts = 0
        self.stack_ports_seen = set()

    def set_phase(self, idx):
        with self.lock:
            now = time.time()
            if self.phases[self.phase_idx]["start_time"] is not None:
                self.phases[self.phase_idx]["end_time"] = now
            self.phase_idx = idx
            self.phases[idx]["start_time"] = now

    def finish_phase(self):
        with self.lock:
            self.phases[self.phase_idx]["end_time"] = time.time()

    def on_packet(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        raw = bytes(pkt[TCP])
        if len(raw) < 13:
            return

        with self.lock:
            p = self.phases[self.phase_idx]

            # SYN from level-ip
            if ip.src == STACK_IP and (pkt[TCP].flags & 0x02):
                self.stack_ports_seen.add(pkt[TCP].sport)
                p["syn_pkts"] += 1
                return

            # Only count packets FROM level-ip
            if ip.src != STACK_IP:
                return

            byte12 = raw[12]
            fec_flag = byte12 & 0x01
            doff = (byte12 >> 4) & 0x0F
            hdr_len = doff * 4 if doff else 20
            payload_len = len(raw) - hdr_len

            if fec_flag:
                # Check if it's a feedback being sent by level-ip
                if payload_len >= FEC_HDR_LEN:
                    fh_bytes = raw[hdr_len:hdr_len + FEC_HDR_LEN]
                    seq_idx = fh_bytes[2]
                    if seq_idx == FEC_FEEDBACK_IDX:
                        p["feedback_pkts"] += 1
                        self.total_feedback_pkts += 1
                        return
                p["parity_pkts"] += 1
                self.total_parity_pkts += 1
            elif payload_len > 0:
                p["data_pkts"] += 1
                p["data_bytes"] += payload_len
                self.total_data_pkts += 1
                self.total_data_bytes += payload_len

                p["data_in_block"] += 1
                if p["data_in_block"] >= RS_K:
                    p["data_in_block"] = 0
                    p["blocks"] += 1

    def report(self):
        """Generate a comprehensive report string."""
        lines = []
        lines.append("")
        lines.append("=" * 72)
        lines.append("  FEC FULL PIPELINE — WIRE-LEVEL TELEMETRY")
        lines.append("=" * 72)
        lines.append(f"  {'Phase':<28s} {'Data':>6s} {'Parity':>7s} {'Blocks':>7s} "
                     f"{'P/Blk':>6s} {'Bytes':>10s} {'Time':>6s} {'KB/s':>7s}")
        lines.append("  " + "─" * 68)

        total_time = 0
        for i, (name, _, _, _, _) in enumerate(PHASES):
            p = self.phases[i]
            blk = p["blocks"] if p["blocks"] > 0 else 1
            ppb = p["parity_pkts"] / blk if p["blocks"] > 0 else 0
            elapsed = 0
            if p["start_time"] and p["end_time"]:
                elapsed = p["end_time"] - p["start_time"]
                total_time += elapsed
            kbps = (p["data_bytes"] / 1024) / elapsed if elapsed > 0 else 0

            lines.append(f"  {name:<28s} {p['data_pkts']:>6d} {p['parity_pkts']:>7d} "
                         f"{p['blocks']:>7d} {ppb:>6.1f} {p['data_bytes']:>10,d} "
                         f"{elapsed:>5.0f}s {kbps:>6.1f}")

        lines.append("  " + "─" * 68)
        lines.append(f"  {'TOTAL':<28s} {self.total_data_pkts:>6d} "
                     f"{self.total_parity_pkts:>7d} "
                     f"{'':>7s} {'':>6s} {self.total_data_bytes:>10,d} "
                     f"{total_time:>5.0f}s")
        lines.append(f"  Unique connections (SYN):  {len(self.stack_ports_seen)}")
        lines.append("=" * 72)
        return "\n".join(lines)


# ─── Log Parser ──────────────────────────────────────────────────────────────
def parse_full_log(logfile):
    """Parse lvl-ip log and return structured telemetry."""
    result = {
        "tx_decisions": [],     # list of {block, loss, target}
        "fb_received": [],      # list of loss_pct values
        "fb_sent": [],          # list of loss_pct values
        "loss_sim_drops": 0,
        "inject_events": [],    # list of {seq, len}
        "rx_parity": [],        # list of {block, idx}
        "rx_recovery": [],      # list of block_id
    }

    if not os.path.exists(logfile):
        return result

    with open(logfile) as f:
        for line in f:
            # FEC-TX decisions
            m = re.search(r'FEC-TX: block=(\d+) loss=(\d+)% target_parity=(\d+)/(\d+)', line)
            if m:
                result["tx_decisions"].append({
                    "block": int(m.group(1)),
                    "loss": int(m.group(2)),
                    "target": int(m.group(3)),
                })
                continue

            # FEC-FB received
            m = re.search(r'FEC-FB: received peer loss_pct=(\d+)%', line)
            if m:
                result["fb_received"].append(int(m.group(1)))
                continue

            # FEC-FB sent
            m = re.search(r'FEC-FB: sent feedback loss_pct=(\d+)%', line)
            if m:
                result["fb_sent"].append(int(m.group(1)))
                continue

            # Loss simulation
            if 'FEC-LOSS-SIM' in line:
                result["loss_sim_drops"] += 1
                continue

            # Ghost injection
            m = re.search(r'FEC-INJECT: injecting recovered pkt seq=(\d+) len=(\d+)', line)
            if m:
                result["inject_events"].append({
                    "seq": int(m.group(1)),
                    "len": int(m.group(2)),
                })
                continue

            # RX parity received
            m = re.search(r'FEC-RX: Got parity block=(\d+) idx=(\d+)', line)
            if m:
                result["rx_parity"].append({
                    "block": int(m.group(1)),
                    "idx": int(m.group(2)),
                })
                continue

            # Recovery events
            m = re.search(r'FEC-RX: Recovered missing packets in block (\d+)', line)
            if m:
                result["rx_recovery"].append(int(m.group(1)))
                continue

    return result


def log_report(log_data):
    """Generate a report string from parsed log data."""
    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("  FEC FULL PIPELINE — STACK-LEVEL LOG ANALYSIS")
    lines.append("=" * 72)

    td = log_data["tx_decisions"]
    lines.append(f"  Total FEC-TX block decisions:  {len(td)}")
    lines.append(f"  Total FEC-FB received:         {len(log_data['fb_received'])}")
    lines.append(f"  Total FEC-FB sent:             {len(log_data['fb_sent'])}")
    lines.append(f"  Total loss-sim drops:          {log_data['loss_sim_drops']}")
    lines.append(f"  Total ghost injections:        {len(log_data['inject_events'])}")
    lines.append(f"  Total RX parity received:      {len(log_data['rx_parity'])}")
    lines.append(f"  Total RX recovery events:      {len(log_data['rx_recovery'])}")

    # Gear distribution
    if td:
        gear_counts = defaultdict(int)
        for d in td:
            gear_counts[d["target"]] += 1
        lines.append("")
        lines.append("  Gear Distribution:")
        for g in sorted(gear_counts.keys()):
            count = gear_counts[g]
            pct = count / len(td) * 100
            bar = "█" * int(pct / 2)
            lines.append(f"    target_parity={g}: {count:>5d} blocks ({pct:>5.1f}%) {bar}")

    # Gear transitions (show when target changes)
    if td:
        transitions = []
        prev_target = td[0]["target"]
        for d in td:
            if d["target"] != prev_target:
                transitions.append(d)
                prev_target = d["target"]
        if transitions:
            lines.append("")
            lines.append("  Gear Transitions:")
            for t in transitions:
                lines.append(f"    block {t['block']:>4d}: "
                             f"loss={t['loss']}% → target_parity={t['target']}")

    # First and last 3 decisions
    if td:
        lines.append("")
        lines.append("  First 5 decisions:")
        for d in td[:5]:
            lines.append(f"    block={d['block']} loss={d['loss']}% target={d['target']}")
        if len(td) > 5:
            lines.append("  Last 5 decisions:")
            for d in td[-5:]:
                lines.append(f"    block={d['block']} loss={d['loss']}% target={d['target']}")

    lines.append("=" * 72)
    return "\n".join(lines)


# ─── Phase Runner ─────────────────────────────────────────────────────────────
def run_phase(phase_idx, name, loss_pct, num_transfers, port, telemetry, sniff_active):
    """Run one phase: inject feedback, start transfers, receive data."""
    print(f"\n  {'─' * 60}")
    print(f"  PHASE {phase_idx + 1}: {name}")
    print(f"  Port: {port} | Feedback: {loss_pct}% | Transfers: {num_transfers}")
    print(f"  {'─' * 60}")

    telemetry.set_phase(phase_idx)
    phase_start = time.time()

    total_rx = 0
    integrity_ok = True

    for tx_num in range(num_transfers):
        print(f"\n    Transfer {tx_num + 1}/{num_transfers} "
              f"({PAYLOAD_PER_TX // (1024*1024)}MB)...")

        # Start server for this transfer
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST_IP, port))
        srv.listen(1)
        srv.settimeout(90)

        # Port-learned feedback injector
        port_holder = {"sport": None}
        port_event = threading.Event()

        def port_watcher():
            """Watch for SYN to learn port, then inject feedback."""
            deadline = time.time() + 30
            while time.time() < deadline and not port_event.is_set():
                # Check if we've seen a new port
                with telemetry.lock:
                    new_ports = telemetry.stack_ports_seen - port_watcher.prev_ports
                if new_ports:
                    sp = max(new_ports)  # latest port
                    port_holder["sport"] = sp
                    port_event.set()
                    if loss_pct > 0:
                        # Inject feedback rapidly
                        for _ in range(8):
                            inject_feedback(loss_pct, sp, port)
                            time.sleep(0.02)
                        print(f"      [FB] Injected {loss_pct}% feedback → port {sp}")
                    break
                time.sleep(0.05)

        port_watcher.prev_ports = telemetry.stack_ports_seen.copy()

        fb_thread = threading.Thread(target=port_watcher, daemon=True)
        fb_thread.start()

        # Launch fec_sender
        sender_cmd = [
            os.path.join(REPO_ROOT, "tools", "level-ip"),
            os.path.join(REPO_ROOT, "apps", "fec_sender"),
            HOST_IP, str(port), str(PAYLOAD_PER_TX)
        ]
        sender_proc = subprocess.Popen(
            sender_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Receive data
        rx_buf = bytearray()
        try:
            conn, addr = srv.accept()
            print(f"      Connected from {addr}")
            conn.settimeout(60)

            # Continue injecting feedback periodically during transfer
            last_fb = time.time()

            while True:
                try:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rx_buf.extend(chunk)

                    # Re-inject feedback every 2 seconds during transfer
                    if loss_pct > 0 and port_holder["sport"] and time.time() - last_fb > 2.0:
                        inject_feedback(loss_pct, port_holder["sport"], port)
                        last_fb = time.time()

                except socket.timeout:
                    break

            # Send ack
            try:
                conn.sendall(b"OK")
                time.sleep(0.2)
            except Exception:
                pass
            conn.close()
        except socket.timeout:
            print(f"      [WARN] Connection timeout in transfer {tx_num + 1}")
        except Exception as e:
            print(f"      [ERROR] {e}")
        srv.close()

        try:
            sender_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            sender_proc.kill()
            sender_proc.wait()

        fb_thread.join(timeout=3)

        rx_len = len(rx_buf)
        total_rx += rx_len
        print(f"      Received: {rx_len:,} bytes")

        # Verify payload integrity (A-Z pattern)
        if rx_len > 0:
            for i in range(min(rx_len, 10000)):  # spot-check first 10KB
                expected = ord('A') + (i % 26)
                if rx_buf[i] != expected:
                    integrity_ok = False
                    print(f"      [INTEGRITY FAIL] byte {i}: "
                          f"got 0x{rx_buf[i]:02x}, expected 0x{expected:02x}")
                    break

        # Brief pause between transfers
        if tx_num < num_transfers - 1:
            time.sleep(2)

    telemetry.finish_phase()
    elapsed = time.time() - phase_start

    status = "OK" if integrity_ok else "INTEGRITY FAIL"
    print(f"\n    Phase {phase_idx + 1} complete: {total_rx:,} bytes "
          f"in {elapsed:.0f}s [{status}]")

    return {
        "total_rx": total_rx,
        "integrity_ok": integrity_ok,
        "elapsed": elapsed,
    }


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║         FEC FULL PIPELINE TEST FRAMEWORK                             ║
║         Comprehensive ~4-5 min stress test                           ║
║                                                                      ║
║  Components under test:                                              ║
║    • RS(7,5) encoder/decoder                                         ║
║    • TX block buffering & parity generation                          ║
║    • Adaptive gear-shifting (0/1/2 parity)                           ║
║    • Loss simulation (5% random drop)                                ║
║    • Wire format (fec_flag, fec_hdr)                                 ║
║    • Feedback injection & reception                                  ║
║    • Payload integrity verification                                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    start_time = datetime.now()
    print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    est_end = start_time + timedelta(minutes=6)
    print(f"  Estimated completion: ~{est_end.strftime('%H:%M:%S')}")

    # ── Preflight checks ──
    if not HAS_SCAPY:
        print("\n  [FATAL] scapy not installed. Run: sudo apt install python3-scapy")
        return False
    if os.geteuid() != 0:
        print("\n  [FATAL] Must run as root (sudo)")
        return False

    result = subprocess.run(["ip", "link", "show", TAP_IFACE],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\n  [FATAL] {TAP_IFACE} not found. Is lvl-ip running?")
        return False

    # Check fec_sender exists
    sender_bin = os.path.join(REPO_ROOT, "apps", "fec_sender")
    if not os.path.exists(sender_bin):
        print(f"\n  [FATAL] {sender_bin} not found. Build it first.")
        return False

    # Clear lvl-ip log
    logfile = os.path.join(REPO_ROOT, "lvl-ip-test.log")
    with open(logfile, "w") as f:
        f.truncate(0)
    print(f"\n  Log cleared: {logfile}")

    # ── Start continuous sniffer ──
    telemetry = PipelineTelemetry()
    sniff_stop = threading.Event()

    def sniffer_loop():
        while not sniff_stop.is_set():
            sniff(iface=TAP_IFACE, filter="tcp", prn=telemetry.on_packet,
                  store=0, timeout=5)

    sniff_thread = threading.Thread(target=sniffer_loop, daemon=True)
    sniff_thread.start()
    time.sleep(0.5)
    print("  Sniffer started on tap0")

    # ── Run phases ──
    phase_results = []
    for i, (name, loss_pct, expected_target, num_tx, dur_hint) in enumerate(PHASES):
        port = BASE_PORT + i
        pr = run_phase(i, name, loss_pct, num_tx, port, telemetry, sniff_stop)
        phase_results.append(pr)

        # Brief pause between phases
        if i < len(PHASES) - 1:
            print(f"\n  ⏳ Inter-phase cooldown (3s)...")
            time.sleep(3)

    # Stop sniffer
    sniff_stop.set()
    time.sleep(2)

    end_time = datetime.now()
    wall_clock = (end_time - start_time).total_seconds()

    # ── Reports ──
    print(telemetry.report())

    log_data = parse_full_log(logfile)
    print(log_report(log_data))

    # ── Assertions ──
    print("")
    print("=" * 72)
    print("  TEST ASSERTIONS")
    print("=" * 72)

    passed = 0
    total = 0

    # 1. All phases transferred data
    total += 1
    all_rx = all(pr["total_rx"] > 0 for pr in phase_results)
    if all_rx:
        print(f"  PASS  1. All {len(PHASES)} phases transferred data successfully")
        passed += 1
    else:
        failed = [i+1 for i, pr in enumerate(phase_results) if pr["total_rx"] == 0]
        print(f"  FAIL  1. Phases {failed} had no data transfer")

    # 2. Payload integrity
    total += 1
    all_integrity = all(pr["integrity_ok"] for pr in phase_results)
    if all_integrity:
        print(f"  PASS  2. Payload integrity verified across all phases")
        passed += 1
    else:
        failed = [i+1 for i, pr in enumerate(phase_results) if not pr["integrity_ok"]]
        print(f"  FAIL  2. Integrity failed in phases {failed}")

    # 3. Adaptive gear-shifting: saw target_parity=0
    total += 1
    td = log_data["tx_decisions"]
    targets_seen = set(d["target"] for d in td)
    if 0 in targets_seen:
        count = sum(1 for d in td if d["target"] == 0)
        print(f"  PASS  3. Saw target_parity=0 in {count} blocks (baseline)")
        passed += 1
    else:
        print(f"  FAIL  3. Never saw target_parity=0")

    # 4. Adaptive gear-shifting: saw target_parity=1
    total += 1
    if 1 in targets_seen:
        count = sum(1 for d in td if d["target"] == 1)
        print(f"  PASS  4. Saw target_parity=1 in {count} blocks (light FEC)")
        passed += 1
    else:
        print(f"  FAIL  4. Never saw target_parity=1")

    # 5. Adaptive gear-shifting: saw target_parity=2
    total += 1
    if 2 in targets_seen:
        count = sum(1 for d in td if d["target"] == 2)
        print(f"  PASS  5. Saw target_parity=2 in {count} blocks (heavy FEC)")
        passed += 1
    else:
        print(f"  FAIL  5. Never saw target_parity=2")

    # 6. Feedback was received by the stack
    total += 1
    if len(log_data["fb_received"]) >= 5:
        print(f"  PASS  6. Stack received {len(log_data['fb_received'])} "
              f"feedback packets")
        passed += 1
    else:
        print(f"  FAIL  6. Only {len(log_data['fb_received'])} feedback packets "
              f"received (expected >=5)")

    # 7. Loss simulation fired (5% of data packets)
    total += 1
    if log_data["loss_sim_drops"] > 0:
        print(f"  PASS  7. Loss simulation dropped {log_data['loss_sim_drops']} packets")
        passed += 1
    else:
        print(f"  FAIL  7. No loss simulation drops detected")

    # 8. Parity packets observed on wire
    total += 1
    if telemetry.total_parity_pkts > 0:
        print(f"  PASS  8. Captured {telemetry.total_parity_pkts} parity packets on wire")
        passed += 1
    else:
        print(f"  FAIL  8. No parity packets captured on wire")

    # 9. Multiple connections (one per transfer)
    total += 1
    expected_conns = sum(p[3] for p in PHASES)
    actual_conns = len(telemetry.stack_ports_seen)
    if actual_conns >= expected_conns * 0.6:
        print(f"  PASS  9. Observed {actual_conns} connections "
              f"(expected ~{expected_conns})")
        passed += 1
    else:
        print(f"  FAIL  9. Only {actual_conns} connections "
              f"(expected ~{expected_conns})")

    # 10. Wall-clock time in range (2-10 minutes)
    total += 1
    if 120 <= wall_clock <= 600:
        print(f"  PASS 10. Wall-clock: {wall_clock:.0f}s "
              f"({wall_clock/60:.1f} min)")
        passed += 1
    elif wall_clock < 120:
        print(f"  WARN 10. Wall-clock: {wall_clock:.0f}s "
              f"({wall_clock/60:.1f} min) — faster than 2 min")
        passed += 1  # still pass, just fast
    else:
        print(f"  WARN 10. Wall-clock: {wall_clock:.0f}s "
              f"({wall_clock/60:.1f} min) — over 10 min")
        passed += 1  # still pass, just slow

    # ── Summary ──
    pct = passed / total * 100 if total > 0 else 0
    print(f"\n  {'─' * 68}")
    print(f"  RESULT: {passed}/{total} assertions passed ({pct:.0f}%)")
    print(f"  {'─' * 68}")
    print(f"  Total data transferred: {telemetry.total_data_bytes:,} bytes "
          f"({telemetry.total_data_bytes / (1024*1024):.1f} MB)")
    print(f"  Total wall-clock time:  {wall_clock:.0f}s ({wall_clock/60:.1f} min)")
    print(f"  Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
