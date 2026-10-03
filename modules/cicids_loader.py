"""Memory-aware loading helpers for CIC-IDS2017 CSV files."""

from io import BytesIO

import pandas as pd


def _reader_source(source):
    if isinstance(source, bytes):
        return BytesIO(source)
    if hasattr(source, "seek"):
        source.seek(0)
    return source


def normalize_columns(columns):
    """Trim whitespace and make duplicate headers unique."""
    seen = {}
    normalized = []
    for value in columns:
        name = str(value).replace("\ufeff", "").strip()
        count = seen.get(name, 0)
        normalized.append(name if count == 0 else f"{name}_{count}")
        seen[name] = count + 1
    return normalized


def load_cicids_csv(source, analysis_mode="Quick Analysis", sample_size=25000, chunksize=50000):
    """Load one file, reading quick samples or full data in bounded chunks."""
    source = _reader_source(source)
    if analysis_mode == "Quick Analysis":
        frame = pd.read_csv(source, nrows=int(sample_size), low_memory=False)
        frame.columns = normalize_columns(frame.columns)
        return frame, {"mode": analysis_mode, "chunks": 1, "rows_read": len(frame)}

    chunks = []
    rows_read = 0
    for chunk in pd.read_csv(source, chunksize=int(chunksize), low_memory=False):
        chunk.columns = normalize_columns(chunk.columns)
        chunks.append(chunk)
        rows_read += len(chunk)
    if not chunks:
        return pd.DataFrame(), {"mode": analysis_mode, "chunks": 0, "rows_read": 0}
    return pd.concat(chunks, ignore_index=True), {
        "mode": analysis_mode,
        "chunks": len(chunks),
        "rows_read": rows_read,
    }