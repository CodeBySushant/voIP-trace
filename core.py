#!/usr/bin/env python3
import sys
import logging
import time
import threading
from datetime import datetime
from collections import deque
import geoip2.database
import json

from scapy.all import sniff, UDP, Raw, IP, get_if_list
from scapy.arch.windows import get_windows_if_list

# --- Setup Logging (Corrected and Robust) ---
# This setup prevents Flask/Werkzeug from hijacking the log handlers.

# 1. Setup the DEBUG logger (for voip_trace.log)
debug_logger = logging.getLogger('DebugLogger')
debug_logger.setLevel(logging.INFO)
debug_logger.propagate = False  # <-- PREVENTS INTERFERENCE
# Create file handler which logs even debug messages
fh_debug = logging.FileHandler('voip_trace.log', mode='w', encoding='utf-8')
# Create formatter and add it to the handler
formatter_debug = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh_debug.setFormatter(formatter_debug)
# Add the handler to the logger
if not debug_logger.handlers:
    debug_logger.addHandler(fh_debug)

# 2. Setup the DATA logger (for call_data.jsonl)
data_logger = logging.getLogger('DataLogger')
data_logger.setLevel(logging.INFO)
data_logger.propagate = False  # <-- PREVENTS INTERFERENCE
# Create file handler which logs JSON data
fh_data = logging.FileHandler('call_data.jsonl', mode='a', encoding='utf-8')
# No formatter needed for this one, as we log raw JSON strings
if not data_logger.handlers:
    data_logger.addHandler(fh_data)

# Suppress scapy's base logger to keep logs clean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# --- Global State & Callbacks ---
active_calls = {}
lock = threading.RLock()
on_new_flow = None
on_update_flow = None
on_remove_flow = None
on_new_alert = None

# --- Constants & GeoIP ---
CALL_INACTIVITY_TIMEOUT = 15
SHORT_CALL_THRESHOLD = 10
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
except FileNotFoundError:
    debug_logger.error("[ERROR] GeoLite2-City.mmdb not found. Please download it from MaxMind.")
    sys.exit(1)

# --- Protocol Heuristics ---
def is_stun(payload: bytes) -> bool:
    return len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42"

def stun_msg_type(payload: bytes) -> int:
    return int.from_bytes(payload[0:2], "big")

def is_dtls(payload: bytes) -> bool:
    return len(payload) >= 13 and (20 <= payload[0] <= 64) and payload[1:3] in [b"\xfe\xff", b"\xfe\xfd"]

def looks_like_rtp(payload: bytes) -> bool:
    return len(payload) >= 12 and (payload[0] >> 6) == 2 and 0 <= (payload[1] & 0x7F) <= 127

# --- STUN Parser ---
def parse_stun(payload: bytes):
    try:
        magic_cookie = payload[4:8]
        length = int.from_bytes(payload[2:4], "big")
        offset = 20
        attrs = {}
        while offset < 20 + length:
            atype = int.from_bytes(payload[offset:offset+2], "big")
            alen = int.from_bytes(payload[offset+2:offset+4], "big")
            aval = payload[offset+4:offset+4+alen]
            offset += 4 + alen
            if offset % 4:
                offset += 4 - (offset % 4)
            if atype == 0x0020:
                family = aval[1]
                port = int.from_bytes(aval[2:4], "big") ^ int.from_bytes(magic_cookie[:2], "big")
                if family == 0x01:
                    ip_raw = bytearray(aval[4:8])
                    for i in range(4):
                        ip_raw[i] ^= magic_cookie[i]
                    ip = ".".join(map(str, ip_raw))
                    attrs["XOR-MAPPED-ADDRESS"] = {"ip": ip, "port": port}
        return attrs
    except Exception:
        return None

# --- Helpers ---
def get_geoip_location(ip_address: str):
    if not geoip_reader:
        return "GeoIP N/A"
    try:
        response = geoip_reader.city(ip_address)
        city = response.city.name or "Unknown City"
        country = response.country.iso_code or "Unknown Country"
        return f"{city}, {country}"
    except geoip2.errors.AddressNotFoundError:
        return "Private/LAN"
    except Exception:
        return "Error"

def get_geoip_data(ip_address: str):
    """Looks up an IP and returns the full GeoIP city object or None."""
    if not geoip_reader:
        return None
    try:
        # Returns the City model object on success
        return geoip_reader.city(ip_address)
    except (geoip2.errors.AddressNotFoundError, Exception):
        # Returns None if the address is not found (e.g., private IP) or on error
        return None

def normalize_flow(ip, sport, dst, dport):
    return tuple(sorted([(ip, sport), (dst, dport)]))

# --- Packet Handler ---
def pkt_cb(pkt):
    if IP in pkt and UDP in pkt and Raw in pkt:
        ip, sport = pkt[IP].src, pkt[UDP].sport
        dst, dport = pkt[IP].dst, pkt[UDP].dport
        flow = normalize_flow(ip, sport, dst, dport)
        payload = bytes(pkt[Raw].load)

        proto, mapped, direction = None, None, None
        if is_stun(payload):
            msg_type = stun_msg_type(payload)
            proto = "STUN"
            if msg_type == 0x0001: direction = "REQ"
            elif msg_type == 0x0101:
                direction = "RESP"
                stun_info = parse_stun(payload)
                if stun_info and "XOR-MAPPED-ADDRESS" in stun_info:
                    mapped = stun_info["XOR-MAPPED-ADDRESS"]
        elif is_dtls(payload):
            proto = "DTLS"
        elif looks_like_rtp(payload):
            proto = "RTP/SRTP"

        if proto:
            now = time.time()
            with lock:
                if flow not in active_calls:
                    # Pre-fetch GeoIP data to make the core engine more robust
                    source_loc_obj = get_geoip_data(flow[0][0])
                    dest_loc_obj = get_geoip_data(flow[1][0])
                    
                    meta = {
                        "proto": proto, "first_seen": now, "last_seen": now,
                        "mapped": mapped, "direction": direction,
                        "source_loc_data": source_loc_obj,
                        "dest_loc_data": dest_loc_obj,
                        "has_seen_rtp": (proto == "RTP/SRTP") # Initialize the RTP flag
                    }
                    active_calls[flow] = meta
                    if on_new_flow:
                        on_new_flow({"flow": flow, "meta": meta})
                else:
                    f = active_calls[flow]
                    f["last_seen"] = now
                    f["proto"] = proto # <-- FIX: Always update the protocol
                    if mapped: f["mapped"] = mapped
                    if direction: f["direction"] = direction
                    
                    # If we see an RTP packet, set the flag to True permanently
                    if proto == "RTP/SRTP":
                        f["has_seen_rtp"] = True

                    if on_update_flow:
                        on_update_flow({"flow": flow, "meta": f})

# --- Anomaly Detection and Cleanup ---
def cleanup_and_detect_anomalies():
    now = time.time()
    inactive_flows = [flow for flow, meta in active_calls.items()
                      if now - meta['last_seen'] > CALL_INACTIVITY_TIMEOUT]

    with lock:
        for flow in inactive_flows:
            if flow in active_calls:
                meta = active_calls.pop(flow)
                duration = meta['last_seen'] - meta['first_seen']

                debug_logger.info(f"Inactive flow detected: {flow[0][0]} <-> {flow[1][0]}. Duration: {duration:.2f}s")
                
                is_short_call = duration < SHORT_CALL_THRESHOLD
                has_seen_rtp = meta.get("has_seen_rtp", False) # Get the flag

                # Only trigger an alert if the call was short AND it contained media (RTP)
                if is_short_call and has_seen_rtp:
                    debug_logger.warning(f">>> Condition Met: Short media call! Logging event for flow {flow[0][0]}.")
                    if on_new_alert:
                        details = { "flow": f"{flow[0][0]}:{flow[0][1]} <-> {flow[1][0]}:{flow[1][1]}", "duration": f"{duration:.2f}s" }
                        on_new_alert({"event": "SHORT CALL DETECTED", "details": details, "severity": "warning"})
                
                # FIX: Log the full, complete call record
                call_record = {
                    "start_time": datetime.fromtimestamp(meta['first_seen']).isoformat(),
                    "end_time": datetime.fromtimestamp(meta['last_seen']).isoformat(),
                    "duration_seconds": round(duration, 2),
                    "source_ip": flow[0][0],
                    "source_port": flow[0][1],
                    "source_location": get_geoip_location(flow[0][0]),
                    "destination_ip": flow[1][0],
                    "destination_port": flow[1][1],
                    "destination_location": get_geoip_location(flow[1][0]),
                    "mapped_address": meta.get("mapped"),
                    "is_short_call_anomaly": (is_short_call and has_seen_rtp)
                }
                data_logger.info(json.dumps(call_record))

                if on_remove_flow:
                    on_remove_flow({"flow": flow})

# --- Main Sniffer Control ---
def start_sniffer(iface, cleanup_callback):
    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={'iface': iface, 'filter': 'udp', 'prn': pkt_cb, 'store': False, 'promisc': True},
        daemon=True
    )
    sniffer_thread.start()
    debug_logger.info(f"Sniffer thread started on interface: {iface}")

    def run_cleanup():
        while True:
            time.sleep(1)
            cleanup_callback()
    
    cleanup_thread = threading.Thread(target=run_cleanup, daemon=True)
    cleanup_thread.start()
    debug_logger.info("Cleanup thread started.")

