import argparse
import re
import time
import json
import os
import sys
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, TCP, IP, Raw, conf
from signatures import (
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    TRAVERSAL_PATTERNS,
    SUSPICIOUS_USER_AGENTS,
    )

class config:
    INTERFACE = 'lo'
    PORT = 5000

    #Brute force detection
    BRUTE_FORCE_TIMEFRAME = 60 #seconds
    BRUTE_FORCE_QUANTITY = 5 

    #Port scanning detection
    PORT_SCAN_TIMEFRAME = 10 #seconds
    PORT_SCAN_QUANTITY = 15

    #Request flooding detection
    REQUEST_RATE_TIMEFRAME = 10  #seconds
    REQUEST_RATE_QUANTITY = 50

    LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'ids_alerts.log')
    VERBOSE = True

class severity:
    LOW = 'LOw'
    MEDIUM = 'Medium'
    HIGH = 'High'
    CRITICAL = 'CRITICAL'

class AlertManager:
    def __init__(self, log_file, verbose=True):
        self.log_file = log_file
        self.verbose = verbose
        self.alert_count = defaultdict(int)
        self.total_alerts = 0
    
    def alert(self, severity, category, description, source_ip="unknown", dest_ip="unknown", payload=""):
        self.total_alerts += 1
        self.alert_count[category] += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_data = {
            "timestemp": timestamp,
            "severity": severity,
            "category": category,
            "description": description,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "payload": payload[:200] if payload else ""
        }

        colors = {
            severity.LOW:      "\033[94m",   # Blue
            severity.MEDIUM:   "\033[93m",   # Yellow
            severity.HIGH:     "\033[91m",   # Red
            severity.CRITICAL: "\033[95m",   # Magenta
        }
        color = colors.get(severity, "\033[0m")
        reset = "\033[0m"

        if self.verbose:
            print(f"\n{color}{'='*70}")
            print(f"  ALERT [{severity}] — {category}")
            print(f"{'='*70}{reset}")
            print(f"  Time:     {timestamp}")
            print(f"  Source:   {source_ip} -> {dest_ip}")
            print(f"  Detail:   {description}")
            if payload:
                display = payload[:200].replace('\n', ' ').replace('\r', '')
                print(f"  Payload:  {display}")
            print(f"{color}{'='*70}{reset}\n")
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(alert_data) + "\n")
        
    def summary(self):
        print(f"\n\033[96m{'='*50}")
        print(f"  IDS Session Summary")
        print(f"{'='*50}\033[0m")
        print(f"  Total alerts fired: {self.total_alerts}")
        if self.alert_count:
            for category, count in sorted(self.alert_count.items()):
                print(f"    {category}: {count}")
        else:
            print("  No alerts detected.")
        print(f"\033[96m{'='*50}\033[0m\n")


#======================= CORE IDS Logic =======================#


class DetectionIDS:
    def __init__(self, alert_manager):
        self.alerts = alert_manager

        self.login_attempts = defaultdict(list)
        self.syn_tracker = defaultdict(dict)
        self.request_tracker = defaultdict(list)

    #scanning signature issues

    def scan_sql_injection(self, data, src_ip, dst_ip):
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                self.alerts.alert(
                    severity.CRITICAL,
                    "SQL_INJECTION",
                    f"SQL injection pattern detected: matched '{pattern}'",
                    src_ip, dst_ip, data
                )
            return True
        return False
    
    def scan_xss(self, data, src_ip, dst_ip):
        for pattern in XSS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                self.alerts.alert(
                    severity.HIGH,
                    "XSS_ATTACK",
                    f"Cross-site scripting pattern detected: matched '{pattern}'",
                    src_ip, dst_ip, data
                )
                return True
        return False

    def scan_command_injection(self, data, src_ip, dst_ip):
        for pattern in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                self.alerts.alert(
                    severity.CRITICAL,
                    "COMMAND_INJECTION",
                    f"Command injection pattern detected: matched '{pattern}'",
                    src_ip, dst_ip, data
                )
                return True
        return False

    def scan_traversal(self, data, src_ip, dst_ip):
        for pattern in TRAVERSAL_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                self.alerts.alert(
                    severity.HIGH,
                    "DIRECTORY_TRAVERSAL",
                    f"Directory traversal pattern detected: matched '{pattern}'",
                    src_ip, dst_ip, data
                )
                return True
        return False
    
    def scan_user_agent(self, data, src_ip, dst_ip):
        ua_match = re.search(r"User-Agent:\s*(.+?)(?:\r\n|\r|\n)", data, re.IGNORECASE)
        if ua_match:
            ua = ua_match.group(1)
            for pattern in SUSPICIOUS_USER_AGENTS:
                if re.search(pattern, ua, re.IGNORECASE):
                    self.alerts.alert(
                        severity.MEDIUM,
                        "SUSPICIOUS_USER_AGENT",
                        f"Known attack tool detected: '{ua.strip()}'",
                        src_ip, dst_ip, ua
                    )
                    return True
        return False

    # scanning behavioural issues

    def scan_brute_force(self, data, src_ip, dst_ip):
        if "POST" in data and "/login" in data:
            now = time.time()
            self.login_attempts[src_ip].append(now)
        
            self.login_attempts[src_ip] = [
                t for t in self.login_attempts[src_ip]
                if now - t < config.BRUTE_FORCE_TIMEFRAME
            ]

            count = len(self.login_attempts[src_ip])
            if count >= config.BRUTE_FORCE_QUANTITY:
                self.alerts.alert(
                    severity.HIGH,
                    "BRUTE_FORCE",
                    f"{count} login attempts in {config.BRUTE_FORCE_QUANTITY}s from {src_ip}",
                    src_ip, dst_ip, data
                )
                return True
        return False
    
    def scan_request_flood(self, src_ip, dst_ip):
        now = time.time()
        self.request_tracker[src_ip].append(now)

        self.request_tracker[src_ip] = [
            t for t in self.request_tracker[src_ip]
            if now - t < config. REQUEST_RATE_TIMEFRAME
        ]

        count = len(self.request_tracker[src_ip])
        if count >= config.REQUEST_RATE_QUANTITY:
            self.alerts.alert(
                severity.MEDIUM,
                "REQUEST_FLOOD",
                f"{count} requests in {config.REQUEST_RATE_TIMEFRAME}s from {src_ip}",
                src_ip, dst_ip
            )
            return True
        return False
    
    def scan_syn(self, src_ip, dst_port):
        now = time.time()
        self.syn_tracker[src_ip][dst_port] = now

        self.syn_tracker[src_ip] = {
            p: t for p, t in self.syn_tracker[src_ip].items()
            if now - t < config.PORT_SCAN_TIMEFRAME
        }

        unique_ports = len(self.syn_tracker[src_ip])
        if unique_ports >= config.PORT_SCAN_QUANTITY:
            self.alerts.alert(
                severity.HIGH,
                "PORT_SCAN",
                f"{unique_ports} unique ports probed in {config.PORT_SCAN_WINDOW}s from {src_ip}",
                src_ip, "N/A"
            )
            self.syn_tracker[src_ip] = {}
            return True
        return False
    
    def analyze_packets(self, payload, src_ip, dst_ip):
        self.scan_request_flood(src_ip, dst_ip)
        self.scan_sql_injection(payload, src_ip, dst_ip)
        self.scan_xss(payload, src_ip, dst_ip)
        self.scan_command_injection(payload, src_ip, dst_ip)
        self.scan_traversal(payload, src_ip, dst_ip)
        self.scan_user_agent(payload, src_ip, dst_ip)
        self.scan_brute_force(payload, src_ip, dst_ip)
    

class NetworkIDS:
    def __init__(self, interface, port, alert_manager):
        self.interface = interface
        self.port = port
        self.alert_manager = alert_manager
        self.ids = DetectionIDS(alert_manager)
        self.packet_count = 0

    def analyze_packet(self, packet):
        self.packet_count += 1

        # syn detection (TCP)
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp = packet[TCP]
            ip = packet[IP]

            if tcp.flags == 0x02:
                self.ids.scan_syn(ip.src, tcp.dport)
        
        # HTTP payload 
        if packet.haslayer(Raw) and packet.haslayer(TCP) and packet.haslayer(IP):
            tcp = packet[TCP]
            ip = packet[IP]

            if tcp.dport == self.port or tcp.sport == self.port:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                except Exception:
                    return
                
                http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
                if any(payload.startswith(method) for method in http_methods):
                    src_ip = ip.src
                    dst_ip = ip.dst

                    self.engine.analyze_packet(payload, src_ip, dst_ip)

                    if config.VERBOSE:
                        parts = payload.split(' ')
                        method = parts[0] if len(parts) > 0 else '?'
                        path = parts[1].split('?')[0] if len(parts) > 1 else '?'
                        print(f"  \033[90m[packet #{self.packet_count}] "
                              f"{src_ip} -> {method} {path}\033[0m")