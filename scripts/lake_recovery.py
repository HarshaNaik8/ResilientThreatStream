#!/usr/bin/env python3
"""
lake_recovery.py — rebuild the MongoDB hot tier from the Parquet data lake (Lambda "master dataset").

If MongoDB *and* its backups are lost, every event is still in the immutable lake.  Alert documents are
re-created with the same deterministic _id (topic:partition:offset) the streaming sink uses, so the rebuild is
idempotent and byte-for-byte joins with anything that survived.

Recovered: threat_alerts and batch_metrics (re-aggregated per micro-batch from the lake's verdicts + ground truth).
Approximations: the per-rule reason breakdown (the lake keeps the rule/ML verdicts, not each rule flag), the original
batch timestamps, and malformed-record counts (only valid events are stored) cannot be recovered.  Rollups are
recomputed with batch_analytics.py.
Usage: python -m scripts.lake_recovery --lake-dir data/lake [--run-id demo-run] --mongo-uri mongodb://127.0.0.1:27019
"""
import argparse
import os
from typing import Dict, Iterator, List, Optional

import pyarrow.dataset as ds
from pymongo import MongoClient, ReplaceOne

from mongo_sink import build_alert_document, build_batch_metric_document

COLUMNS = ["run_id", "protocol", "topic", "kafka_partition", "kafka_offset", "event_time", "ttl", "total_len",
           "t_delta", "label", "rule_attack", "ml_attack", "predicted_attack"]


def reason_from_flags(rule_attack, ml_attack) -> str:
    """The lake stores the verdicts, so the reason is the verdict source."""
    parts = []
    if rule_attack:
        parts.append("RULE_ALERT")
    if ml_attack:
        parts.append("ML_PAYLOAD_ANOMALY")
    return ";".join(parts) or "HEURISTIC_ALERT"


def lake_alert_docs(lake_dir: str, run_id: Optional[str] = None, batch_rows: int = 20000) -> Iterator[List[Dict]]:
    """Yield lists of alert documents (predicted_attack == 1) read straight from Parquet."""
    dataset = ds.dataset(os.path.join(lake_dir, "events"), format="parquet", partitioning="hive")
    flt = ds.field("predicted_attack") == 1
    if run_id:
        flt = flt & (ds.field("run_id") == run_id)
    for batch in dataset.to_batches(columns=COLUMNS, filter=flt, batch_size=batch_rows):
        docs = []
        for r in batch.to_pylist():
            label = r["label"]
            docs.append(build_alert_document(
                topic=r["topic"], kafka_partition=r["kafka_partition"], kafka_offset=r["kafka_offset"],
                protocol=r["protocol"], ttl=r["ttl"], total_len=r["total_len"], t_delta=r["t_delta"],
                predicted_attack=1, alert_reason=reason_from_flags(r["rule_attack"], r["ml_attack"]),
                event_timestamp=r["event_time"], ground_truth_label=label,
                ground_truth_is_attack=(None if label is None else int(str(label).strip().upper() != "BENIGN")),
                detector_version="recovered-from-lake", run_id=r["run_id"]))
        yield docs


def rebuild_batch_metrics(lake_dir: str, run_id: Optional[str] = None) -> List[Dict]:
    """Re-aggregate one batch_metrics document per (run_id, batch_id) from the lake."""
    import pandas as pd
    dataset = ds.dataset(os.path.join(lake_dir, "events"), format="parquet", partitioning="hive")
    flt = (ds.field("run_id") == run_id) if run_id else None
    df = dataset.to_table(columns=["run_id", "batch_id", "label", "predicted_attack", "rule_attack"],
                          filter=flt).to_pandas()
    if df.empty:
        return []
    norm = df["label"].fillna("").str.strip().str.upper()
    df["valid"] = (norm != "") & (norm != "UNKNOWN")
    df["truth"] = (df["valid"] & (norm != "BENIGN")).astype(int)
    docs = []
    for (rid, bid), g in df.groupby(["run_id", "batch_id"]):
        e = g[g["valid"]]
        pred = e["predicted_attack"].fillna(0).astype(int)
        tp = int(((pred == 1) & (e["truth"] == 1)).sum()); fp = int(((pred == 1) & (e["truth"] == 0)).sum())
        tn = int(((pred == 0) & (e["truth"] == 0)).sum()); fn = int(((pred == 0) & (e["truth"] == 1)).sum())
        alerts = int((g["predicted_attack"] == 1).sum())
        doc = build_batch_metric_document(
            run_id=rid, batch_id=int(bid), total_records=len(g), valid_records=len(g), malformed_records=0,
            alert_count=alerts, normal_count=len(g) - alerts,
            actual_attacks=(tp + fn) if len(e) else None, actual_benign=(tn + fp) if len(e) else None,
            tp=tp if len(e) else None, fp=fp if len(e) else None, tn=tn if len(e) else None, fn=fn if len(e) else None)
        doc["recovered_from_lake"] = True
        docs.append(doc)
    return docs


def recover_batch_metrics(lake_dir: str, mongo_uri: str, db_name: str, run_id: Optional[str] = None) -> int:
    docs = rebuild_batch_metrics(lake_dir, run_id)
    if docs:
        client = MongoClient(mongo_uri)
        try:
            client[db_name]["batch_metrics"].bulk_write(
                [ReplaceOne({"_id": d["_id"]}, d, upsert=True) for d in docs], ordered=False)
        finally:
            client.close()
    return len(docs)


def recover_alerts(lake_dir: str, mongo_uri: str, db_name: str, run_id: Optional[str] = None) -> int:
    client = MongoClient(mongo_uri)
    n = 0
    try:
        coll = client[db_name]["threat_alerts"]
        for docs in lake_alert_docs(lake_dir, run_id):
            if docs:
                coll.bulk_write([ReplaceOne({"_id": d["_id"]}, d, upsert=True) for d in docs], ordered=False)
                n += len(docs)
    finally:
        client.close()
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lake-dir", default="data/lake")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", default=os.getenv("MONGODB_DATABASE", "network_threat_analytics"))
    a = ap.parse_args()
    print(f"[Recovery] re-created {recover_alerts(a.lake_dir, a.mongo_uri, a.mongo_db, a.run_id):,} alerts and "
          f"{recover_batch_metrics(a.lake_dir, a.mongo_uri, a.mongo_db, a.run_id)} batch-metric docs from {a.lake_dir}")
