"""Explainable, rule-based CIC flow risk scoring."""

import math

SEVERITY_BASE = {"Low": 5, "Medium": 35, "High": 60, "Critical": 80}


def _number(row, column):
    try:
        value = float(row.get(column, 0))
        return value if math.isfinite(value) else 0.0
    except (TypeError, ValueError):
        return 0.0


def score_flow(row):
    attack = str(row.get("Attack_Type", "Other"))
    score = SEVERITY_BASE.get(str(row.get("Severity", "Medium")), 35)
    factors = []
    packet_rate = max(_number(row, "Flow Packets/s"), _number(row, "Fwd Packets/s"))
    if packet_rate > 1000:
        score += 10; factors.append("High packet rate")
    elif packet_rate > 100:
        score += 5; factors.append("Elevated packet rate")
    if _number(row, "Flow Bytes/s") > 1_000_000:
        score += 8; factors.append("High byte rate")
    port = _number(row, "Destination Port")
    if port in {21, 22, 23, 25, 80, 443, 3389} and attack != "Normal":
        score += 5; factors.append("Attack traffic targets a service port")
    syn, rst, fin = _number(row, "SYN Flag Count"), _number(row, "RST Flag Count"), _number(row, "FIN Flag Count")
    if syn > 0 and rst > 0:
        score += 7; factors.append("SYN and RST activity")
    if fin > 0 and syn > 0:
        score += 3; factors.append("TCP connection flag activity")
    if _number(row, "Total Fwd Packets") + _number(row, "Total Backward Packets") > 1000:
        score += 5; factors.append("Large flow packet count")
    if not factors and attack == "Normal":
        factors.append("No rule-based suspicious indicators")
    elif not factors:
        factors.append("Attack category contributes to score")
    return min(100, max(0, int(score))), factors