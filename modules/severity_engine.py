"""Transparent severity rules shared by CIC-IDS analysis and reports."""

SEVERITY_RULES = {
    "Normal": ("Low", "Benign flow label"),
    "Port Scan": ("Medium", "Reconnaissance activity"),
    "Brute Force": ("High", "Credential attack category"),
    "Web Attack": ("High", "Application-layer attack category"),
    "DoS": ("High", "Denial-of-service category"),
    "DDoS": ("Critical", "Distributed denial-of-service category"),
    "Infiltration": ("Critical", "Infiltration category"),
    "Botnet": ("Critical", "Botnet category"),
    "Heartbleed": ("Critical", "Heartbleed category"),
    "Other": ("Medium", "Unmapped dataset label"),
}


def severity_for_attack(attack_type):
    return SEVERITY_RULES.get(attack_type, SEVERITY_RULES["Other"])