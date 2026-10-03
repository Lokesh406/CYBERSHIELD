"""CYBERSHIELD: Snort/pfSense and CIC-IDS2017 forensic analysis."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from modules.anomaly_detector import detect_anomalies
from modules.cicids_loader import load_cicids_csv
from modules.forensic_report import cicids_html_report
from modules.ml_detector import load_model, predict, train_random_forest
from modules.preprocessing import preprocess_cicids
from modules.risk_engine import score_flow
from modules.severity_engine import severity_for_attack
from modules.snort_analysis import prepare_snort, snort_html_report, snort_report

MODEL_PATH = Path(__file__).parent / "models" / "cicids_random_forest.joblib"

st.set_page_config(page_title="CYBERSHIELD", page_icon="Shield", layout="wide")
st.markdown("""
<style>
.block-container { padding-top: 2.5rem; padding-bottom: 3rem; }
body { background: #f4f8f8; color: #15343b; }
.brand { position: relative; overflow: hidden; border-left: 5px solid #087f8c; padding: 1.15rem 1.25rem; margin-bottom: 1.75rem; background: linear-gradient(105deg, #e1f3f2, #f7fbfb); box-shadow: 0 8px 24px rgba(33, 78, 84, .08); animation: brand-in .7s ease-out both; }
.brand::after { content: ""; position: absolute; inset: 0 auto 0 -35%; width: 28%; background: rgba(52, 211, 153, .16); transform: skewX(-18deg); animation: scan 4.5s ease-in-out infinite; }
.brand h1 { letter-spacing: .12em; margin: 0; color: #123d46; font-size: clamp(1.75rem, 4vw, 2.7rem); }
.brand p { color: #4b6f75; margin: .35rem 0 0; font-size: 1rem; }
[data-testid="stMetric"] { background: linear-gradient(145deg, #ffffff, #eef7f7); border: 1px solid #c9e2e3; padding: 1rem; border-radius: 8px; animation: rise-in .55s ease-out both; transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease; }
[data-testid="stMetric"]:hover { transform: translateY(-3px); border-color: #0e9aa6; box-shadow: 0 10px 24px rgba(33, 78, 84, .15); }
[data-testid="stMetricLabel"] { color: #52757a; }
[data-testid="stMetricValue"] { color: #123d46; }
button, [role="tab"] { transition: background-color .2s ease, color .2s ease, border-color .2s ease, transform .2s ease; }
button:hover { transform: translateY(-1px); }
[role="tab"][aria-selected="true"] { color: #5eead4; border-bottom-color: #18b6a4; }
.stAlert { animation: rise-in .45s ease-out both; }
@keyframes brand-in { from { opacity: 0; transform: translateY(-12px); } to { opacity: 1; transform: translateY(0); } }
@keyframes rise-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
@keyframes scan { 0%, 25% { left: -35%; } 65%, 100% { left: 125%; } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; } }
</style>
""", unsafe_allow_html=True)


def header():
    st.markdown("<div class='brand'><h1>CYBERSHIELD</h1><p>Automated Network Threat Detection &amp; Forensic Analysis</p></div>", unsafe_allow_html=True)


def metric_row(values):
    columns = st.columns(len(values))
    for column, (label, value) in zip(columns, values):
        column.metric(label, value)


@st.cache_data(show_spinner=False)
def load_and_prepare_cic(data, mode, sample_size, chunksize):
    raw, load_summary = load_cicids_csv(data, mode, sample_size, chunksize)
    prepared, summary = preprocess_cicids(raw)
    return prepared, summary, load_summary


def render_snort():
    st.caption("Snort / pfSense Alert Analysis")
    upload = st.file_uploader("Upload Snort/pfSense alert CSV", type=["csv"], key="snort_upload")
    use_sample = st.checkbox("Use included sample_alerts.csv", value=upload is None)
    source = upload
    is_sample = False
    if source is None and use_sample:
        sample_path = Path(__file__).parent / "sample_alerts.csv"
        if sample_path.exists():
            source = sample_path
            is_sample = True
    if source is None:
        st.info("Upload an alert CSV or select the included sample.")
        return
    try:
        frame = prepare_snort(pd.read_csv(source))
    except Exception as exc:
        st.error(f"Could not read Snort/pfSense CSV: {exc}")
        return

    blocked = int(frame["action"].str.lower().str.contains("block|drop|deny", regex=True).sum())
    high = int(frame["severity"].isin(["High", "Critical"]).sum())
    metric_row([("Total Alerts", len(frame)), ("Unique Source IPs", frame["source_ip"].replace("", pd.NA).dropna().nunique()), ("Blocked/Dropped", blocked), ("High/Critical", high)])
    st.info("Offline Dataset Analysis" if is_sample else "Uploaded alert analysis")
    left, right = st.columns(2)
    with left:
        st.subheader("Attack Distribution")
        counts = frame["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="count")
        st.plotly_chart(px.bar(counts, x="attack_type", y="count"), use_container_width=True)
    with right:
        st.subheader("Severity Distribution")
        counts = frame["severity"].value_counts().rename_axis("severity").reset_index(name="count")
        st.plotly_chart(px.bar(counts, x="severity", y="count"), use_container_width=True)
    st.subheader("Forensic Incident Table")
    filters = st.columns(3)
    attacks = sorted(frame["attack_type"].unique())
    attack_filter = filters[0].multiselect("Attack Type", attacks, default=attacks)
    severity_filter = filters[1].multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    protocols = sorted([value for value in frame["protocol"].unique() if value])
    protocol_filter = filters[2].multiselect("Protocol", protocols, default=protocols)
    filtered = frame[frame["attack_type"].isin(attack_filter) & frame["severity"].isin(severity_filter)]
    if protocol_filter:
        filtered = filtered[filtered["protocol"].isin(protocol_filter) | (filtered["protocol"] == "")]
    display = snort_report(filtered)
    st.dataframe(display, use_container_width=True, hide_index=True)
    if len(filtered):
        st.write(f"**Most frequent attack:** {filtered['attack_type'].value_counts().idxmax()}  \n**Incidents in current filter:** {len(filtered)}")
    st.download_button("Download CSV Forensic Report", display.to_csv(index=False), "snort_forensic_report.csv", "text/csv")
    st.download_button("Download HTML Forensic Report", snort_html_report(filtered), "snort_forensic_report.html", "text/html")


def apply_risk(frame):
    scored = frame.copy()
    results = scored.apply(score_flow, axis=1)
    scored["Risk_Score"] = results.map(lambda result: result[0])
    scored["Risk_Factors"] = results.map(lambda result: "; ".join(result[1]))
    return scored


def render_overview(frame, load_summary):
    total = len(frame)
    benign = int((frame["Attack_Type"] == "Normal").sum())
    malicious = total - benign
    high = int(frame["Severity"].isin(["High", "Critical"]).sum())
    metric_row([("Total Flows", total), ("Benign Flows", benign), ("Malicious Flows", malicious), ("Attack Classes", frame["Attack_Type"].nunique()), ("High/Critical", high), ("Maximum Risk", int(frame["Risk_Score"].max()))])
    st.caption(f"Offline Dataset Analysis | Loader: {load_summary['mode']} | Chunks processed: {load_summary['chunks']} | Rows read: {load_summary['rows_read']}")
    left, right = st.columns(2)
    with left:
        traffic = pd.DataFrame({"Traffic": ["Benign", "Malicious"], "Count": [benign, malicious]})
        st.plotly_chart(px.bar(traffic, x="Traffic", y="Count", color="Traffic"), use_container_width=True)
    with right:
        attacks = frame["Attack_Type"].value_counts().rename_axis("Attack Type").reset_index(name="Count")
        st.plotly_chart(px.bar(attacks, x="Attack Type", y="Count", color="Attack Type"), use_container_width=True)


def render_analytics(frame):
    st.subheader("Attack Analytics")
    tabs = st.tabs(["Severity", "Ports", "Flow Duration", "Packet Rates", "TCP Flags"])
    with tabs[0]:
        chart = frame.groupby(["Attack_Type", "Severity"]).size().reset_index(name="Count")
        st.plotly_chart(px.bar(chart, x="Attack_Type", y="Count", color="Severity"), use_container_width=True)
    with tabs[1]:
        if "Destination Port" in frame:
            ports = frame["Destination Port"].value_counts().head(20).rename_axis("Destination Port").reset_index(name="Count")
            st.plotly_chart(px.bar(ports, x="Destination Port", y="Count"), use_container_width=True)
        else:
            st.info("Destination Port is not present in this dataset.")
    with tabs[2]:
        if "Flow Duration" in frame:
            st.plotly_chart(px.histogram(frame, x="Flow Duration", color="Attack_Type"), use_container_width=True)
        else:
            st.info("Flow Duration is not present in this dataset.")
    with tabs[3]:
        available = [column for column in ["Flow Packets/s", "Flow Bytes/s"] if column in frame]
        if available:
            st.plotly_chart(px.histogram(frame, x=available[0], color="Attack_Type"), use_container_width=True)
        else:
            st.info("Packet-rate columns are not present in this dataset.")
    with tabs[4]:
        available = [column for column in ["SYN Flag Count", "RST Flag Count", "FIN Flag Count", "ACK Flag Count"] if column in frame]
        if available:
            flag_counts = frame[available].sum().rename_axis("Flag").reset_index(name="Count")
            st.plotly_chart(px.bar(flag_counts, x="Flag", y="Count"), use_container_width=True)
        else:
            st.info("TCP flag columns are not present in this dataset.")


def render_cicids():
    st.caption("CIC-IDS2017 Network Flow Analysis")
    upload = st.file_uploader("Upload one CIC-IDS2017 CSV", type=["csv"], key="cic_upload")
    settings = st.columns(3)
    mode = settings[0].selectbox("Analysis mode", ["Quick Analysis", "Full Analysis"])
    sample_size = settings[1].selectbox("Quick sample rows", [10000, 25000, 50000, 100000], index=1)
    chunksize = settings[2].number_input("Full-analysis chunk size", 10000, 250000, 50000, 10000)
    if upload is None:
        st.info("Upload one CIC-IDS2017 CSV. Large files are read in chunks; files are not loaded simultaneously.")
        return
    try:
        frame, summary, load_summary = load_and_prepare_cic(upload.getvalue(), mode, sample_size, chunksize)
        frame = apply_risk(frame)
    except MemoryError:
        st.error("The file exceeded available memory. Use Quick Analysis with a smaller sample.")
        return
    except Exception as exc:
        st.error(f"CIC-IDS2017 processing failed: {exc}")
        return

    st.sidebar.success(f"Processed {len(frame):,} rows")
    tabs = st.tabs(["Overview", "Threat Detection", "Attack Analytics", "Risk Analysis", "ML Detection", "Anomaly Detection", "Forensic Analysis", "Reports", "System Information"])
    with tabs[0]:
        render_overview(frame, load_summary)
    with tabs[1]:
        st.subheader("Threat Detection")
        st.dataframe(frame[["Original_Label", "Attack_Type", "Severity", "Severity_Reason", "Risk_Score", "Risk_Factors"]], use_container_width=True, hide_index=True)
    with tabs[2]:
        render_analytics(frame)
    with tabs[3]:
        st.subheader("Rule-Based Risk Analysis")
        st.caption("Risk scores are transparent prototype calculations and are not scientifically validated.")
        st.plotly_chart(px.histogram(frame, x="Risk_Score", color="Severity", nbins=20), use_container_width=True)
        st.dataframe(frame.sort_values("Risk_Score", ascending=False).head(100), use_container_width=True, hide_index=True)
    with tabs[4]:
        render_ml(frame, summary)
    with tabs[5]:
        render_anomaly(frame, summary)
    with tabs[6]:
        render_forensics(frame, summary)
    with tabs[7]:
        html = cicids_html_report(frame, summary, upload.name, st.session_state.get("ml_metrics"), st.session_state.get("anomaly_count"))
        st.download_button("Download CYBERSHIELD HTML Report", html, "cybershield_forensic_report.html", "text/html")
        st.download_button("Download Processed CSV", frame.to_csv(index=False), "cybershield_processed_flows.csv", "text/csv")
    with tabs[8]:
        st.write({"Dataset": upload.name, "Mode": mode, "Rows analyzed": len(frame), "Numeric features": summary["features"], "Attack classes": summary["attack_classes"], "Constant features removed from ML": len(summary["constant_features"])})


def render_ml(frame, summary):
    st.subheader("ML Detection")
    st.caption("Random Forest uses numeric flow features only. Label, Original_Label, Attack_Type, Severity, and Risk_Score are excluded to prevent leakage.")
    actions = st.columns(2)
    if actions[0].button("Train Model", type="primary"):
        try:
            payload = train_random_forest(frame, summary["numeric_features"], MODEL_PATH)
            st.session_state["model_payload"] = payload
            st.session_state["ml_metrics"] = payload["metrics"]
            st.success("Model trained and saved.")
        except Exception as exc:
            st.error(f"Training failed: {exc}")
    if actions[1].button("Load Existing Model"):
        payload = load_model(MODEL_PATH)
        if payload is None:
            st.warning("No saved model exists yet. Train a model first.")
        else:
            st.session_state["model_payload"] = payload
            st.session_state["ml_metrics"] = payload["metrics"]
            st.success("Saved model loaded.")
    payload = st.session_state.get("model_payload")
    if not payload:
        st.info("Model training is manual and does not run automatically.")
        return
    metrics = payload["metrics"]
    metric_row([("Model", metrics["model"]), ("Training Samples", metrics["training_samples"]), ("Testing Samples", metrics["testing_samples"]), ("Features", metrics["features"]), ("Classes", metrics["classes"])])
    metric_row([("Accuracy", f"{metrics['accuracy']:.3f}"), ("Macro Precision", f"{metrics['macro_precision']:.3f}"), ("Macro Recall", f"{metrics['macro_recall']:.3f}"), ("Macro F1", f"{metrics['macro_f1']:.3f}")])
    matrix = pd.DataFrame(metrics["confusion_matrix"], index=metrics["classes_list"], columns=metrics["classes_list"])
    st.plotly_chart(px.imshow(matrix, text_auto=True, labels=dict(x="Predicted", y="Actual", color="Count")), use_container_width=True)
    importance = pd.Series(metrics["feature_importance"]).sort_values(ascending=False).head(20).sort_values().rename_axis("Feature").reset_index(name="Importance")
    st.plotly_chart(px.bar(importance, x="Importance", y="Feature", orientation="h"), use_container_width=True)
    predictions, confidence = predict(frame, payload)
    prediction_frame = frame[["Original_Label"]].copy()
    prediction_frame["Predicted_Attack"] = predictions
    prediction_frame["Model_Confidence"] = confidence.round(4)
    prediction_frame["Severity"] = prediction_frame["Predicted_Attack"].map(lambda value: severity_for_attack(value)[0])
    risk_input = frame.copy()
    risk_input["Attack_Type"] = predictions
    risk_input["Severity"] = prediction_frame["Severity"]
    prediction_frame["Risk_Score"] = apply_risk(risk_input)["Risk_Score"]
    st.subheader("Predictions")
    st.dataframe(prediction_frame.head(1000), use_container_width=True, hide_index=True)


def render_anomaly(frame, summary):
    st.subheader("Anomaly Detection")
    st.info("Anomaly detection identifies unusual flow behavior and does not independently prove malicious activity.")
    if st.button("Run Isolation Forest"):
        try:
            result = detect_anomalies(frame, summary["numeric_features"])
            anomaly_frame = frame[["Original_Label", "Attack_Type", "Severity", "Risk_Score"]].copy()
            anomaly_frame["Anomaly"] = result
            st.session_state["anomaly_count"] = result.count("Anomalous")
            st.session_state["anomaly_frame"] = anomaly_frame
        except Exception as exc:
            st.error(f"Anomaly detection failed: {exc}")
    anomaly_frame = st.session_state.get("anomaly_frame")
    if anomaly_frame is not None:
        metric_row([("Anomalous", int((anomaly_frame["Anomaly"] == "Anomalous").sum())), ("Normal-like", int((anomaly_frame["Anomaly"] == "Normal-like").sum()))])
        st.dataframe(anomaly_frame, use_container_width=True, hide_index=True)


def render_forensics(frame, summary):
    st.subheader("Forensic Analysis")
    malicious = int((frame["Attack_Type"] != "Normal").sum())
    most_common = frame["Attack_Type"].value_counts().idxmax()
    st.write(f"**Dataset:** CIC-IDS2017 offline CSV  \n**Rows analyzed:** {len(frame)}  \n**Benign traffic:** {len(frame) - malicious}  \n**Malicious traffic:** {malicious}  \n**Most common attack:** {most_common}  \n**High/Critical events:** {int(frame['Severity'].isin(['High', 'Critical']).sum())}  \n**Maximum risk score:** {int(frame['Risk_Score'].max())}")
    if "Source IP" not in frame.columns and "source_ip" not in frame.columns:
        st.info("IP investigation unavailable because Source IP is not present.")
    if "Timestamp" not in frame.columns and "timestamp" not in frame.columns:
        st.info("Timeline analysis unavailable because Timestamp is not present.")
    groups = frame.groupby(["Attack_Type", "Severity"]).agg(Event_Count=("Attack_Type", "size"), Risk_Score=("Risk_Score", "max")).reset_index()
    groups.insert(0, "Incident_ID", [f"INC-{index:04d}" for index in range(1, len(groups) + 1)])
    st.dataframe(groups, use_container_width=True, hide_index=True)


header()
st.sidebar.title("CYBERSHIELD")
mode = st.sidebar.radio("Data Source", ["Snort / pfSense", "CIC-IDS2017"])
if mode == "Snort / pfSense":
    render_snort()
else:
    render_cicids()
