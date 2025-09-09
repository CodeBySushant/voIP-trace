#!/usr/bin/env python3
import sys
import threading
from datetime import datetime

from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list

# Import the core sniffing and analysis logic
import core

# --- UI Specific Globals ---
console = Console()
recent_events = core.deque(maxlen=50)

# --- Define UI Callback Functions ---
def handle_new_or_update(data):
    # This function is not strictly needed for the TUI as it redraws everything,
    # but it's good practice to have placeholders.
    pass

def handle_remove(data):
    # The core logic handles removing from active_calls, the UI will just redraw.
    pass

def handle_new_alert(data):
    now = datetime.now().isoformat()
    evt = {"time": now, "event": data['event'], "details": data['details'], "severity": data['severity']}
    with core.lock:
        recent_events.append(evt)

def handle_stun_mapped(data):
    now = datetime.now().isoformat()
    evt = {"time": now, "event": "STUN-MAPPED", "details": data, "severity": "info"}
    with core.lock:
        recent_events.append(evt)

# --- Register Callbacks with the Core Engine ---
core.on_new_flow = handle_new_or_update
core.on_update_flow = handle_new_or_update
core.on_remove_flow = handle_remove
core.on_new_alert = handle_new_alert
core.on_stun_mapped = handle_stun_mapped

# --- UI Rendering (Largely Unchanged) ---
def render_ui():
    flows_table = Table(title="[bold cyan]Active VoIP Flows[/bold cyan]", expand=True)
    flows_table.add_column("Flow")
    flows_table.add_column("Location", max_width=35)
    flows_table.add_column("Proto")
    flows_table.add_column("Direction")
    flows_table.add_column("Mapped")
    flows_table.add_column("Age (s)", justify="right")

    now = core.time.time()
    with core.lock:
        # We now read from core.active_calls
        for flow, meta in core.active_calls.items():
            ip1, ip2 = flow[0][0], flow[1][0]
            loc1 = core.get_geoip_location(ip1)
            loc2 = core.get_geoip_location(ip2)
            location_str = f"[green]{loc1}[/green] <-> [yellow]{loc2}[/yellow]"
            flow_str = f"{ip1}:{flow[0][1]} <-> {ip2}:{flow[1][1]}"
            proto = meta.get("proto", "-")
            direction = meta.get("direction", "-")
            mapped = f"{meta['mapped']['ip']}:{meta['mapped']['port']}" if meta.get("mapped") else "-"
            age = int(now - meta.get("first_seen", now))
            flows_table.add_row(flow_str, location_str, proto, direction, mapped, str(age))

    ev_lines = []
    for e in list(recent_events)[-15:]:
        sev, line = e.get("severity", "info"), f"{e['time']} {e['event']} {e['details']}"
        style = {"warning": "yellow", "error": "red"}.get(sev, "cyan")
        ev_lines.append(Text(line, style=style))
    ev_panel = Panel(Text("\n").join(ev_lines) if ev_lines else Text("No events yet"),
                     title="Recent Events", border_style="magenta", height=12)

    layout = Table.grid(expand=True)
    layout.add_row(flows_table)
    layout.add_row(ev_panel)
    return layout

# --- Main UI Thread ---
def main():
    ifaces = get_windows_if_list()
    print("[*] Available interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"  {i}: {iface}")
    
    choice = input("\n[?] Enter interface index, name, or 'all': ").strip()
    iface = ifaces[int(choice)] if choice.isdigit() else choice
    iface = None if choice == "all" else iface

    console.print(f"[*] Starting VoIP Trace TUI on: {iface if iface else 'ALL INTERFACES'}")
    
    # The core sniffer now takes the cleanup function as an argument
    core.start_sniffer(iface, core.cleanup_and_detect_anomalies)

    try:
        with Live(render_ui(), refresh_per_second=1, screen=False, vertical_overflow="visible") as live:
            while True:
                core.time.sleep(1)
                live.update(render_ui())
    except KeyboardInterrupt:
        console.print("\n[red][!] Stopped by user[/red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
