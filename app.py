#!/usr/bin/env python3
import sys
import logging
import re
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import get_if_list

# Import the core sniffing and analysis logic
import core

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key' 
socketio = SocketIO(app, async_mode='threading')

# --- Helper Function ---
def create_safe_flow_id(flow):
    """Creates a CSS-selector-safe ID from a flow tuple."""
    return re.sub(r'[^a-zA-Z0-9]', '', str(flow))

# --- Define Web Callback Functions ---
def handle_new_flow(data):
    """Takes flow data from the core and emits it to the web client."""
    flow = data['flow']
    meta = data['meta']
    
    source_loc_data = meta.get('source_loc_data')
    dest_loc_data = meta.get('dest_loc_data')

    source_loc = {'lat': None, 'lon': None, 'city': 'Private/LAN', 'country': ''}
    if source_loc_data:
        source_loc = {
            'city': source_loc_data.city.name, 'country': source_loc_data.country.iso_code, 
            'lat': source_loc_data.location.latitude, 'lon': source_loc_data.location.longitude
        }

    dest_loc = {'lat': None, 'lon': None, 'city': 'Private/LAN', 'country': ''}
    if dest_loc_data:
        dest_loc = {
            'city': dest_loc_data.city.name, 'country': dest_loc_data.country.iso_code, 
            'lat': dest_loc_data.location.latitude, 'lon': dest_loc_data.location.longitude
        }
    

    socketio.emit('new_flow', {
        'flow_id': str(flow), # Original ID for map layer tracking
        'safe_flow_id': create_safe_flow_id(flow), # Safe ID for DOM elements
        'source_ip': flow[0][0], 'source_port': flow[0][1],
        'dest_ip': flow[1][0], 'dest_port': flow[1][1],
        'proto': meta.get('proto', '-'),
        'source_loc': source_loc,
        'dest_loc': dest_loc,
        'start_time': meta['first_seen']
    })

def handle_update_flow(data):
    """Handles protocol updates for an existing flow and sends them to the client."""
    flow = data['flow']
    meta = data['meta']
    socketio.emit('update_flow', {
        'safe_flow_id': create_safe_flow_id(flow),
        'proto': meta.get('proto', '-')
    })

def handle_remove_flow(data):
    """Tells the web client to remove a flow from the UI."""
    socketio.emit('remove_flow', {
        'flow_id': str(data['flow']),
        'safe_flow_id': create_safe_flow_id(data['flow'])
    })

def handle_new_alert(data):
    """Sends anomaly alerts to the web client."""
    alert_data = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'message': data['event'],
        'details': f"{data['details']['flow']} ({data['details']['duration']})"
    }
    socketio.emit('new_alert', alert_data)


# --- Register Callbacks with the Core Engine ---
core.on_new_flow = handle_new_flow
core.on_update_flow = handle_update_flow
core.on_remove_flow = handle_remove_flow
core.on_new_alert = handle_new_alert


# --- Flask Route ---
@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')


# --- Main Execution ---
if __name__ == '__main__':
    # --- Interface Selection ---
    ifaces = get_if_list()
    print("[*] Available network interfaces:")
    for i, iface_name in enumerate(ifaces):
        print(f"  {i}: {iface_name}")
    
    choice = input("\n[?] Enter the index, name, or 'all' to monitor: ").strip().lower()
    
    iface = None
    try:
        if choice == 'all':
            iface = None
        elif choice.isdigit():
            iface = ifaces[int(choice)]
        else:
            if choice in ifaces:
                iface = choice
            else:
                print(f"[ERROR] Invalid interface name '{choice}'.")
                sys.exit(1)
    except (IndexError, ValueError):
        print(f"[ERROR] Invalid choice '{choice}'. Please select a valid index or name.")
        sys.exit(1)

    display_iface = iface if iface is not None else "ALL INTERFACES"
    core.debug_logger.info(f"[*] Starting VoIP Trace Web Dashboard on interface: {display_iface}")
    
    core.start_sniffer(iface, core.cleanup_and_detect_anomalies)

    core.debug_logger.info(f"[*] Server is live at http://127.0.0.1:5000")
    # Use log_output=False to prevent Werkzeug from interfering with our logger
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True, log_output=False)

