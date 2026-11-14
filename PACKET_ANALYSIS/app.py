from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque
from threading import Thread, Lock
import psutil
import time

app = Flask(__name__)

# Store recent packets
packets = deque(maxlen=100)

# Thread synchronization
lock = Lock()

# Network statistics
stats = {
    "total": 0,
    "incoming": 0,
    "outgoing": 0,
    "local": 0,
    "bytes": 0
}

# Get local IP addresses
local_ips = set()

for interfaces in psutil.net_if_addrs().values():
    for address in interfaces:
        if address.family.name == "AF_INET":
            local_ips.add(address.address)


# Detect network protocol
def get_protocol(packet):

    if TCP in packet:
        return "TCP"

    elif UDP in packet:
        return "UDP"

    elif ICMP in packet:
        return "ICMP"

    return "OTHER"


# Capture network packets
def process_packet(packet):

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    size = len(packet)
    protocol = get_protocol(packet)

    if src in local_ips and dst not in local_ips:
        direction = "Outgoing"

    elif dst in local_ips and src not in local_ips:
        direction = "Incoming"

    else:
        direction = "Local"

    packet_data = {
        "time": time.strftime("%H:%M:%S"),
        "source": src,
        "destination": dst,
        "protocol": protocol,
        "size": size,
        "direction": direction
    }

    with lock:

        stats["total"] += 1
        stats["bytes"] += size

        if direction == "Incoming":
            stats["incoming"] += 1

        elif direction == "Outgoing":
            stats["outgoing"] += 1

        else:
            stats["local"] += 1

        packets.appendleft(packet_data)


# Start packet capture
def start_monitoring():

    sniff(
        filter="ip",
        prn=process_packet,
        store=False
    )


# Dashboard page
@app.route("/")
def index():
    return render_template("index.html")


# API for live statistics
@app.route("/api/stats")

def get_stats():

    with lock:

        return jsonify({
            "stats": stats.copy(),
            "packets": list(packets)
        })


# Start application
if __name__ == "__main__":

    Thread(
        target=start_monitoring,
        daemon=True
    ).start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )