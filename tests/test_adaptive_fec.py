#!/usr/bin/env python3
"""
Adaptive FEC "Gear Shift" Test

Verifies that the level-ip sender adjusts parity output in response to
FEC feedback packets injected by this script.

Architecture:
  - Single large transfer (~200KB = ~27 FEC blocks)
  - Feedback injected at block boundaries via scapy
  - Assertions based on lvl-ip log (ground truth)

Usage:
  sudo python3 tests/test_adaptive_fec.py
"""

import os, sys, time, re, socket, struct, threading, subprocess

try:
    from scapy.all import (
        sniff, sendp, IP, TCP, Ether, Raw,
        get_if_hwaddr, getmacbyip
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ─── Constants ───────────────────────────────────────────────────────────────
REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAP_IFACE   = "tap0"
HOST_IP     = "10.0.0.5"
STACK_IP    = "10.0.0.4"
TEST_PORT   = 8080
PAYLOAD     = 200 * 1024   # 200KB

FEC_HDR_FMT = "!HBBHIH"
FEC_HDR_LEN = struct.calcsize(FEC_HDR_FMT)
FEC_FEEDBACK_IDX = 0xFF

# Phase boundaries (block count thresholds from sniffer's view)
PHASE2_BLOCK = 5     # inject 10% after 5 blocks
PHASE3_BLOCK = 15    # inject 20% after 15 blocks


def inject_feedback(loss_pct, stack_port):
    """Send a FEC feedback packet to level-ip."""
    fec_hdr = struct.pack(FEC_HDR_FMT,
        0, FEC_FEEDBACK_IDX, 0, 0, 0, 0)
    payload = fec_hdr + bytes([loss_pct])

    pkt = (
        IP(src=HOST_IP, dst=STACK_IP) /
        TCP(sport=TEST_PORT, dport=stack_port,
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


def parse_log(logfile):
    """Parse lvl-ip log for FEC decisions. Returns list of (block_id, loss, target)."""
    decisions = []
    feedbacks = []
    with open(logfile) as f:
        for line in f:
            m = re.search(r'FEC-TX: block=(\d+) loss=(\d+)% target_parity=(\d+)/(\d+)', line)
            if m:
                decisions.append({
                    'block': int(m.group(1)),
                    'loss': int(m.group(2)),
                    'target': int(m.group(3)),
                })
            m = re.search(r'FEC-FB: received peer loss_pct=(\d+)%', line)
            if m:
                feedbacks.append(int(m.group(1)))
    return decisions, feedbacks


# ─── Main ────────────────────────────────────────────────────────────────────
def run_test():
    print("=" * 60)
    print("  Adaptive FEC Gear-Shift Test")
    print("  Single transfer with mid-stream feedback injection")
    print("=" * 60)

    if not HAS_SCAPY:
        print("\n[ERROR] scapy not installed")
        return False
    if os.geteuid() != 0:
        print("\n[ERROR] Must run as root")
        return False

    result = subprocess.run(["ip", "link", "show", TAP_IFACE],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\n[ERROR] {TAP_IFACE} not found. Is lvl-ip running?")
        return False

    # Shared state
    stack_port = {"val": None}
    port_known = threading.Event()
    data_in_block = {"count": 0}
    block_count = {"total": 0}
    feedback_sent = {2: False, 3: False}

    def on_packet(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        raw = bytes(pkt[TCP])
        if len(raw) < 13:
            return

        # Learn port from SYN
        if ip.src == STACK_IP and (pkt[TCP].flags & 0x02):
            stack_port["val"] = pkt[TCP].sport
            port_known.set()
            return

        # Only count packets FROM level-ip
        if ip.src != STACK_IP:
            return

        byte12 = raw[12]
        fec_flag = byte12 & 0x01
        doff = (byte12 >> 4) & 0x0F
        hdr_len = doff * 4 if doff else 20
        has_payload = len(raw) > hdr_len

        if not fec_flag and has_payload:
            data_in_block["count"] += 1
            if data_in_block["count"] >= 5:
                data_in_block["count"] = 0
                block_count["total"] += 1
                bc = block_count["total"]

                if bc == PHASE2_BLOCK and not feedback_sent[2]:
                    feedback_sent[2] = True
                    sp = stack_port["val"]
                    if sp:
                        for _ in range(5):
                            inject_feedback(10, sp)
                            time.sleep(0.01)
                        print(f"\n    >>> Injected 10% loss at sniffer block {bc}")

                elif bc == PHASE3_BLOCK and not feedback_sent[3]:
                    feedback_sent[3] = True
                    sp = stack_port["val"]
                    if sp:
                        for _ in range(5):
                            inject_feedback(20, sp)
                            time.sleep(0.01)
                        print(f"\n    >>> Injected 20% loss at sniffer block {bc}")

    # Start sniffer
    sniff_done = threading.Event()
    def sniffer():
        sniff(iface=TAP_IFACE, filter="tcp", prn=on_packet,
              store=0, timeout=60, stop_filter=lambda p: sniff_done.is_set())
    sniff_thread = threading.Thread(target=sniffer, daemon=True)
    sniff_thread.start()
    time.sleep(0.5)

    # Start server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST_IP, TEST_PORT))
    srv.listen(1)
    srv.settimeout(45)

    # Launch sender
    sender_cmd = [
        os.path.join(REPO_ROOT, "tools", "level-ip"),
        os.path.join(REPO_ROOT, "apps", "fec_sender"),
        HOST_IP, str(TEST_PORT), str(PAYLOAD)
    ]
    print(f"\n  Launching sender ({PAYLOAD//1024}KB)...")
    sender_proc = subprocess.Popen(
        sender_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Receive all data
    total_rx = 0
    try:
        conn, addr = srv.accept()
        print(f"  Connected from {addr}")
        conn.settimeout(30)
        while True:
            try:
                chunk = conn.recv(16384)
                if not chunk:
                    break
                total_rx += len(chunk)
            except socket.timeout:
                break
        conn.sendall(b"OK")
        time.sleep(0.3)
        conn.close()
    except Exception as e:
        print(f"  Server error: {e}")
    srv.close()

    try:
        sender_proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        sender_proc.kill()

    time.sleep(2)
    sniff_done.set()
    sniff_thread.join(timeout=5)

    print(f"\n  Transfer complete: {total_rx} bytes received, "
          f"{block_count['total']} blocks observed by sniffer")

    # ── Parse log (ground truth) ──
    logfile = os.path.join(REPO_ROOT, "lvl-ip-test.log")
    if not os.path.exists(logfile):
        print("\n[ERROR] lvl-ip-test.log not found")
        return False

    decisions, feedbacks = parse_log(logfile)

    print(f"\n{'='*60}")
    print(f"  LVL-IP LOG SUMMARY")
    print(f"{'='*60}")
    print(f"  Total FEC-TX decisions: {len(decisions)}")
    print(f"  Total FEC-FB received:  {len(feedbacks)}")

    # Group by target parity
    by_target = {}
    for d in decisions:
        t = d['target']
        by_target.setdefault(t, []).append(d['block'])

    for t in sorted(by_target.keys()):
        blocks = by_target[t]
        print(f"  target_parity={t}: {len(blocks)} blocks "
              f"(first=block {blocks[0]}, last=block {blocks[-1]})")

    # Print a few transitions
    print(f"\n  First 3 decisions:")
    for d in decisions[:3]:
        print(f"    block={d['block']} loss={d['loss']}% target={d['target']}")
    if len(decisions) > 3:
        # Find first transition to target=1
        for d in decisions:
            if d['target'] == 1:
                print(f"  First target=1: block={d['block']} loss={d['loss']}%")
                break
        for d in decisions:
            if d['target'] == 2:
                print(f"  First target=2: block={d['block']} loss={d['loss']}%")
                break

    print(f"{'='*60}")

    # ── Assertions (based on log, not sniffer counts) ──
    print(f"\n{'='*60}")
    print("  TEST RESULTS")
    print(f"{'='*60}")

    passed = 0
    total = 3

    # Test 1: Some blocks should have target_parity=0 (before feedback)
    blocks_at_0 = by_target.get(0, [])
    if len(blocks_at_0) >= 3:
        print(f"  PASS TEST 1: {len(blocks_at_0)} blocks with target_parity=0 (expected >=3)")
        passed += 1
    else:
        print(f"  FAIL TEST 1: {len(blocks_at_0)} blocks with target_parity=0 (expected >=3)")

    # Test 2: Some blocks should have target_parity=1 (after 10% feedback)
    blocks_at_1 = by_target.get(1, [])
    if len(blocks_at_1) >= 2:
        print(f"  PASS TEST 2: {len(blocks_at_1)} blocks with target_parity=1 (expected >=2)")
        passed += 1
    else:
        print(f"  FAIL TEST 2: {len(blocks_at_1)} blocks with target_parity=1 (expected >=2)")

    # Test 3: Some blocks should have target_parity=2 (after 20% feedback)
    blocks_at_2 = by_target.get(2, [])
    if len(blocks_at_2) >= 2:
        print(f"  PASS TEST 3: {len(blocks_at_2)} blocks with target_parity=2 (expected >=2)")
        passed += 1
    else:
        print(f"  FAIL TEST 3: {len(blocks_at_2)} blocks with target_parity=2 (expected >=2)")

    # Bonus: verify ordering (0 appears before 1, 1 before 2)
    if blocks_at_0 and blocks_at_1 and blocks_at_2:
        if blocks_at_0[0] < blocks_at_1[0] < blocks_at_2[0]:
            print(f"  PASS BONUS: Correct ordering 0->{blocks_at_0[0]} "
                  f"1->{blocks_at_1[0]} 2->{blocks_at_2[0]}")
        else:
            print(f"  WARN BONUS: Unexpected ordering")

    print(f"\n  Result: {passed}/{total} tests passed")
    print(f"{'='*60}")
    return passed == total


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
