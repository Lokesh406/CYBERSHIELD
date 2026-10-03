# CYBERSHIELD

**Automated Network Threat Detection & Forensic Analysis**

CYBERSHIELD is an academic/prototype forensic analytics platform with two separate analysis modes in one Streamlit application:

- **Snort / pfSense Alert Analysis** for normalized CSV alert exports.
- **CIC-IDS2017 Network Flow Analysis** for offline benchmark flow data.

It does not claim live monitoring. Live Snort/pfSense monitoring requires a separate authorized network deployment.

## Features

### Snort / pfSense

- CSV upload and common-column normalization.
- Rule-based ICMP, port scan, HTTP, ARP spoofing, DoS, and reconnaissance classification.
- Low/Medium/High/Critical severity.
- Metrics, Plotly charts, filters, forensic summaries, CSV reports, and HTML reports.

### CIC-IDS2017

- Quick sampling at 10,000, 25,000, 50,000, or 100,000 rows.
- Full analysis with bounded `chunksize` CSV reads.
- Label preservation in `Original_Label` and normalized `Attack_Type` classification.
- Numeric conversion, infinity replacement, missing-value filling, duplicate removal, and constant-feature detection.
- Transparent rule-based risk score from 0 to 100 with calculated factors.
- Random Forest training, saved models, evaluation metrics, confusion matrix, feature importance, and predictions.
- Optional Isolation Forest anomaly detection.
- Attack, severity, port, duration, packet-rate, TCP-flag, risk, and forensic analysis views.
- Dynamic HTML and processed CSV reports.
- Explicit unavailability messages when IP or timestamp columns are absent.

## Architecture

```text
app.py
  -> modules/cicids_loader.py
  -> modules/preprocessing.py
  -> modules/severity_engine.py
  -> modules/risk_engine.py
  -> modules/ml_detector.py
  -> modules/anomaly_detector.py
  -> modules/forensic_report.py
  -> modules/snort_analysis.py
```

ML excludes `Label`, `Original_Label`, `Attack_Type`, `Severity`, and `Risk_Score` from its features to avoid target leakage. Model evaluation values are calculated from the selected data split and are never hard-coded.

## Technology Stack

Python, Streamlit, pandas, NumPy, scikit-learn, joblib, and Plotly.

## Installation

PowerShell:

```powershell
C:/Users/<user>/AppData/Local/Microsoft/WindowsApps/python3.11.exe -m pip install -r requirements.txt
```

Or use an activated virtual environment:

```powershell
python -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt
```

## Run

```powershell
python -m streamlit run app.py
```

Open `http://localhost:8501`.

## CIC-IDS2017 Usage

1. Select **CIC-IDS2017** in the sidebar.
2. Upload one CSV containing the required `Label` column.
3. Choose **Quick Analysis** for a bounded sample or **Full Analysis** for chunk processing.
4. Review Overview, Threat Detection, Analytics, Risk, and Forensic tabs.
5. In **ML Detection**, click **Train Model** when the selected data contains enough examples in at least two classes.
6. The model is saved to `models/cicids_random_forest.joblib`; use **Load Existing Model** on a later run.
7. Use **Run Isolation Forest** in Anomaly Detection when at least ten rows and numeric features are available.

The application dynamically inspects columns. CIC-IDS2017 does not necessarily contain IP addresses, timestamps, or protocol fields, so those values are never fabricated.

## Reports

The Reports tab provides a processed CSV and a dynamic CYBERSHIELD HTML forensic report containing executive statistics, preprocessing information, attack and severity distributions, risk results, available ML results, anomaly status, incidents, and limitations.

## Project Structure

```text
app.py
modules/
  anomaly_detector.py
  cicids_loader.py
  forensic_report.py
  ml_detector.py
  preprocessing.py
  risk_engine.py
  severity_engine.py
  snort_analysis.py
models/
sample_alerts.csv
snort_csv_template.csv
requirements.txt
README.md
```

## Limitations and Future Enhancements

This is an academic/prototype forensic analytics platform. Rule-based risk scores are explainable calculations, not scientifically validated threat probabilities. CIC-IDS2017 is an offline benchmark dataset. Future work could add a durable incident database, authenticated access, PDF export, and a separately deployed live ingestion service.

Run attack simulations only in a private lab or VM network that you own or are authorized to test.
