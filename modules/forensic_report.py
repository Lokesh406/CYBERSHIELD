"""Report builders for CIC and Snort analysis modes."""

from datetime import datetime


def cicids_html_report(frame, summary, dataset_name, ml_metrics=None, anomaly_count=None):
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attacks = frame["Attack_Type"].value_counts().to_frame("Count").to_html()
    severities = frame["Severity"].value_counts().to_frame("Count").to_html()
    incidents = frame.assign(**{"Event Count": 1}).groupby(["Attack_Type", "Severity"], as_index=False).agg({"Event Count": "sum", "Risk_Score": "max"}).to_html(index=False)
    ml_text = "Model training was not completed for this analysis."
    if ml_metrics:
        ml_text = f"Random Forest macro F1: {ml_metrics['macro_f1']:.3f}; accuracy: {ml_metrics['accuracy']:.3f}."
    anomaly_text = "Anomaly detection was not enabled."
    if anomaly_count is not None:
        anomaly_text = f"Anomalous flows: {anomaly_count}. Anomalies indicate unusual behavior, not proof of malicious activity."
    details = frame.head(100).to_html(index=False, escape=True)
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>CYBERSHIELD Forensic Report</title><style>body{{font-family:Arial,sans-serif;margin:32px;color:#17202a}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid #d8dee4;padding:6px;text-align:left}}th{{background:#e8f0f2}}.metric{{display:inline-block;margin:8px 20px 8px 0;padding:12px;border-left:4px solid #0e7490;background:#eef7f8}}</style></head><body><h1>CYBERSHIELD FORENSIC REPORT</h1><p>Generated: {generated} | Dataset: {dataset_name}</p><h2>Executive Summary</h2><div class='metric'>Rows analyzed<br><b>{len(frame)}</b></div><div class='metric'>Malicious flows<br><b>{int((frame['Attack_Type'] != 'Normal').sum())}</b></div><div class='metric'>Maximum risk<br><b>{int(frame['Risk_Score'].max())}</b></div><h2>Preprocessing Summary</h2><p>Original rows: {summary['original_rows']} | Processed rows: {summary['processed_rows']} | Removed duplicates: {summary['removed_duplicates']} | Missing numeric values filled: {summary['missing_values_filled']} | Features: {summary['features']}</p><h2>Attack Distribution</h2>{attacks}<h2>Severity Analysis</h2>{severities}<h2>Incident Summary</h2>{incidents}<h2>ML Results</h2><p>{ml_text}</p><h2>Anomaly Results</h2><p>{anomaly_text}</p><h2>Limitations</h2><p>Rule-based scores are transparent calculations and are not scientifically validated. CIC-IDS2017 is an offline benchmark dataset. Live monitoring requires separate deployment.</p><h2>Flow Details (first 100)</h2>{details}</body></html>"""