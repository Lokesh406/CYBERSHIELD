"""Optional unsupervised anomaly detection for numeric network flows."""

from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


def detect_anomalies(frame, feature_columns):
    if len(frame) < 10 or not feature_columns:
        raise ValueError("Anomaly detection requires at least 10 rows and one numeric feature.")
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("detector", IsolationForest(random_state=42, contamination="auto", n_jobs=-1)),
    ])
    values = pipeline.fit_predict(frame[feature_columns])
    return ["Anomalous" if value == -1 else "Normal-like" for value in values]