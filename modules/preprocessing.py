"""CIC-IDS2017 cleaning and label normalization."""

import numpy as np
import pandas as pd

from .severity_engine import severity_for_attack

LABEL_MAP = {
    "BENIGN": "Normal", "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS", "DDoS": "DDoS",
    "PortScan": "Port Scan", "FTP-Patator": "Brute Force", "SSH-Patator": "Brute Force",
    "Web Attack - Brute Force": "Web Attack", "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack", "Infiltration": "Infiltration",
    "Bot": "Botnet", "Heartbleed": "Heartbleed",
}


def normalize_label(value):
    return LABEL_MAP.get(str(value).strip(), "Other")


def preprocess_cicids(frame):
    if frame is None or frame.empty:
        raise ValueError("The uploaded CSV is empty.")
    frame = frame.copy()
    frame.columns = [str(column).strip() for column in frame.columns]
    if "Label" not in frame.columns:
        raise ValueError("CIC-IDS2017 analysis requires a 'Label' column.")

    original_rows = len(frame)
    frame["Original_Label"] = frame["Label"].fillna("Unknown").astype(str).str.strip()
    frame["Attack_Type"] = frame["Original_Label"].map(normalize_label)
    duplicate_rows = int(frame.duplicated().sum())
    frame = frame.drop_duplicates().reset_index(drop=True)

    protected = {"Label", "Original_Label", "Attack_Type"}
    numeric_features = []
    for column in frame.columns:
        if column in protected:
            continue
        converted = pd.to_numeric(frame[column], errors="coerce")
        if converted.notna().any():
            frame[column] = converted.replace([np.inf, -np.inf], np.nan)
            numeric_features.append(column)

    missing_values = int(frame[numeric_features].isna().sum().sum()) if numeric_features else 0
    constant_features = [column for column in numeric_features if frame[column].nunique(dropna=True) <= 1]
    for column in numeric_features:
        median = frame[column].median()
        frame[column] = frame[column].fillna(0 if pd.isna(median) else median)

    frame["Severity"] = frame["Attack_Type"].map(lambda value: severity_for_attack(value)[0])
    frame["Severity_Reason"] = frame["Attack_Type"].map(lambda value: severity_for_attack(value)[1])
    usable_features = [column for column in numeric_features if column not in constant_features]
    return frame, {
        "original_rows": original_rows, "processed_rows": len(frame),
        "removed_duplicates": duplicate_rows, "missing_values_filled": missing_values,
        "features": len(usable_features), "attack_classes": int(frame["Attack_Type"].nunique()),
        "numeric_features": usable_features, "constant_features": constant_features,
    }