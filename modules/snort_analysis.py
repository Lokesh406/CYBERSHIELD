"""Preserved Snort/pfSense normalization, classification, and report helpers."""

from datetime import datetime

import pandas as pd


def normalize_columns(df):
    lower = {str(c).strip().lower(): c for c in df.columns}
    aliases = {"timestamp": ["timestamp", "time", "date", "datetime", "event_time", "eventtime"], "protocol": ["protocol", "proto"], "source_ip": ["source ip", "src ip", "src_ip", "source", "src"], "source_port": ["source port", "src port", "src_port", "sport"], "destination_ip": ["destination ip", "dest ip", "dst ip", "destination", "dst_ip", "dst"], "destination_port": ["destination port", "dest port", "dst port", "dst_port", "dport"], "message": ["message", "alert", "description", "alert description", "msg"], "sid": ["sid", "signature id", "signature_id", "rule id", "rule_id"], "action": ["action", "status", "response", "disposition"]}
    rename = {}
    for standard, names in aliases.items():
        for name in names:
            if name in lower:
                rename[lower[name]] = standard
                break
    return df.rename(columns=rename)


def classify_attack(message, protocol=""):
    text = f"{message} {protocol}".lower()
    if any(x in text for x in ["arp spoof", "arpspoof", "arp cache", "ethernet arp"]): return "ARP Spoofing", "Critical"
    if any(x in text for x in ["port scan", "portscan", "nmap", "portsweep"]): return "Port Scan", "Medium"
    if any(x in text for x in ["icmp attack", "icmp flood", "ping flood", "icmp"]): return "ICMP Attack", "High"
    if any(x in text for x in ["http inspect", "http attack", "web attack", "http"]): return "HTTP Attack", "High"
    if any(x in text for x in ["dos", "denial of service", "flood"]): return "DoS", "High"
    if any(x in text for x in ["scan", "recon"]): return "Reconnaissance", "Medium"
    return "Other / Unknown", "Low"


def prepare_snort(frame):
    required = ["timestamp", "protocol", "source_ip", "source_port", "destination_ip", "destination_port", "message", "sid", "action"]
    frame = normalize_columns(frame.copy())
    for column in required:
        if column not in frame: frame[column] = ""
        frame[column] = frame[column].fillna("").astype(str)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame["timestamp_display"] = frame["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("Unknown")
    classified = frame.apply(lambda row: classify_attack(row["message"], row["protocol"]), axis=1)
    frame["attack_type"] = classified.map(lambda result: result[0])
    frame["severity"] = classified.map(lambda result: result[1])
    frame["action"] = frame["action"].replace("", "Detected").str.strip().str.title()
    return frame


def snort_report(frame):
    columns = ["timestamp_display", "attack_type", "severity", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "sid", "message", "action"]
    report = frame[columns].copy()
    report.columns = ["Timestamp", "Attack Type", "Severity", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "SID", "Message", "Action"]
    return report


def snort_html_report(frame):
    report = snort_report(frame)
    blocked = int(frame["action"].str.lower().str.contains("block|drop|deny", regex=True).sum())
    return f"<!doctype html><html><head><meta charset='utf-8'><title>CYBERSHIELD Snort Report</title><style>body{{font-family:Arial;margin:32px}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid #ddd;padding:6px}}th{{background:#e8f0f2}}</style></head><body><h1>CYBERSHIELD FORENSIC REPORT</h1><p>Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</p><p>Total alerts: {len(frame)} | Blocked/Dropped: {blocked}</p>{frame['attack_type'].value_counts().to_frame('Count').to_html()}<h2>Incident Details</h2>{report.to_html(index=False, escape=True)}</body></html>"