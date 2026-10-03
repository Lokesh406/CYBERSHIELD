"""Leakage-safe Random Forest training, evaluation, persistence, and prediction."""

from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

EXCLUDED = {"Label", "Original_Label", "Attack_Type", "Severity", "Severity_Reason", "Risk_Score", "Risk_Factors"}


def train_random_forest(frame, feature_columns, model_path):
    features = [c for c in feature_columns if c in frame.columns and c not in EXCLUDED]
    labels = frame["Attack_Type"]
    if not features:
        raise ValueError("At least one numeric flow feature is required for training.")
    if labels.nunique() < 2 or labels.value_counts().min() < 2:
        raise ValueError("Training requires at least two attack classes with two rows each.")
    x_train, x_test, y_train, y_test = train_test_split(
        frame[features], labels, test_size=0.2, random_state=42, stratify=labels
    )
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced_subsample", n_jobs=-1)),
    ])
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    classes = list(pipeline.named_steps["classifier"].classes_)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predictions, average="macro", zero_division=0)
    metrics = {
        "model": "Random Forest", "training_samples": len(x_train), "testing_samples": len(x_test),
        "features": len(features), "classes": len(classes), "accuracy": accuracy_score(y_test, predictions),
        "macro_precision": precision, "macro_recall": recall, "macro_f1": f1,
        "classification_report": classification_report(y_test, predictions, zero_division=0, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=classes).tolist(),
        "classes_list": classes,
        "feature_importance": dict(zip(features, pipeline.named_steps["classifier"].feature_importances_)),
    }
    payload = {"pipeline": pipeline, "features": features, "metrics": metrics}
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, model_path)
    return payload


def load_model(model_path):
    path = Path(model_path)
    return joblib.load(path) if path.exists() else None


def predict(frame, payload):
    usable = frame.reindex(columns=payload["features"], fill_value=0)
    pipeline = payload["pipeline"]
    predictions = pipeline.predict(usable)
    probabilities = pipeline.predict_proba(usable)
    return predictions, probabilities.max(axis=1)