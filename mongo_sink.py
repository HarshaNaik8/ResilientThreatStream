"""
mongo_sink.py — MongoDB Persistence Layer for Network Threat Analytics.

Handles idempotent bulk upserts of predicted threat alerts and micro-batch metrics.
Supports MONGODB_URI environment variable and connection reuse.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pymongo
from pymongo import MongoClient, ReplaceOne, IndexModel, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError


_mongo_client_instance: Optional[MongoClient] = None


def get_mongo_client(uri: Optional[str] = None) -> MongoClient:
    """
    Returns a shared, pooled MongoClient instance.
    Uses MONGODB_URI environment variable or defaults to mongodb://localhost:27017.
    """
    global _mongo_client_instance
    if _mongo_client_instance is None:
        target_uri = uri or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        _mongo_client_instance = MongoClient(
            target_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", "10000")),
            maxPoolSize=20,
        )
    return _mongo_client_instance


def close_mongo_client():
    """Cleanly closes the shared MongoClient instance."""
    global _mongo_client_instance
    if _mongo_client_instance is not None:
        try:
            _mongo_client_instance.close()
        finally:
            _mongo_client_instance = None


def init_mongo_collections(client: MongoClient, db_name: str = "network_threat_analytics"):
    """
    Initializes collections and creates performance/lookup indexes idempotently.
    """
    db = client[db_name]

    # Collection A: threat_alerts indexes
    alerts_col = db["threat_alerts"]
    alert_indexes = [
        IndexModel([("kafka_offset", ASCENDING)], name="idx_kafka_offset"),
        IndexModel([("topic", ASCENDING), ("kafka_partition", ASCENDING), ("kafka_offset", ASCENDING)], name="idx_kafka_source"),
        IndexModel([("stored_at", DESCENDING)], name="idx_stored_at"),
        IndexModel([("protocol", ASCENDING)], name="idx_protocol"),
        IndexModel([("predicted_attack", ASCENDING)], name="idx_predicted_attack"),
        IndexModel([("run_id", ASCENDING)], name="idx_run_id"),
    ]
    alerts_col.create_indexes(alert_indexes)

    # Collection B: batch_metrics indexes
    metrics_col = db["batch_metrics"]
    metric_indexes = [
        IndexModel([("batch_id", ASCENDING)], name="idx_batch_id"),
        IndexModel([("run_id", ASCENDING), ("batch_id", ASCENDING)], name="idx_run_batch"),
        IndexModel([("timestamp", DESCENDING)], name="idx_timestamp"),
    ]
    metrics_col.create_indexes(metric_indexes)

    return db


def build_alert_document(
    topic: str,
    kafka_partition: int,
    kafka_offset: int,
    protocol: Optional[str],
    ttl: Optional[int],
    total_len: Optional[int],
    t_delta: Optional[float],
    predicted_attack: int,
    alert_reason: str,
    event_timestamp: Optional[datetime] = None,
    ground_truth_label: Optional[str] = None,
    ground_truth_is_attack: Optional[int] = None,
    detector_version: str = "1.0-rules",
    run_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs a deterministic document for predicted_attack == 1 alerts.
    _id is deterministically formatted: {topic}:{partition}:{offset}.
    Optionally stores run_id for precise multi-run dashboard isolation.
    """
    doc_id = f"{topic}:{kafka_partition}:{kafka_offset}"
    now_utc = datetime.now(timezone.utc)

    doc = {
        "_id": doc_id,
        "topic": topic,
        "kafka_partition": int(kafka_partition),
        "kafka_offset": int(kafka_offset),
        "event_timestamp": event_timestamp,
        "stored_at": now_utc,
        "protocol": protocol if protocol else "unknown",
        "ttl": ttl,
        "total_len": total_len,
        "t_delta": t_delta,
        "predicted_attack": int(predicted_attack),
        "alert_reason": alert_reason,
        "ground_truth_label": ground_truth_label,
        "ground_truth_is_attack": ground_truth_is_attack,
        "detector_version": detector_version,
    }
    if run_id is not None:
        doc["run_id"] = str(run_id)
    return doc


def build_batch_metric_document(
    run_id: str,
    batch_id: int,
    total_records: int,
    valid_records: int,
    malformed_records: int,
    alert_count: int,
    normal_count: int,
    actual_attacks: Optional[int],
    actual_benign: Optional[int],
    tp: Optional[int],
    fp: Optional[int],
    tn: Optional[int],
    fn: Optional[int],
    timestamp: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Constructs a deterministic document for a micro-batch execution summary.
    Handles undefined zero-division metrics explicitly by setting them to None.
    """
    doc_id = f"{run_id}:{batch_id}"
    batch_time = timestamp or datetime.now(timezone.utc)

    # Safe metric calculations — undefined metrics remain None (null in MongoDB)
    precision = None
    if tp is not None and fp is not None and (tp + fp) > 0:
        precision = round(float(tp) / float(tp + fp), 4)

    recall = None
    if tp is not None and fn is not None and (tp + fn) > 0:
        recall = round(float(tp) / float(tp + fn), 4)

    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = round(2.0 * precision * recall / (precision + recall), 4)

    fpr = None
    if fp is not None and tn is not None and (fp + tn) > 0:
        fpr = round(float(fp) / float(fp + tn), 4)

    return {
        "_id": doc_id,
        "run_id": str(run_id),
        "batch_id": int(batch_id),
        "timestamp": batch_time,
        "total_records": int(total_records),
        "valid_records": int(valid_records),
        "malformed_records": int(malformed_records),
        "alert_count": int(alert_count),
        "normal_count": int(normal_count),
        "actual_attacks": actual_attacks,
        "actual_benign": actual_benign,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def persist_micro_batch(
    client: MongoClient,
    db_name: str,
    alert_docs: List[Dict[str, Any]],
    metric_doc: Optional[Dict[str, Any]]
) -> Dict[str, int]:
    """
    Persists alert documents and micro-batch metric summaries idempotently.
    Uses ReplaceOne with upsert=True.
    Propagates PyMongoError if persistence fails.
    
    Returns:
        dict: {"alerts_upserted": int, "metrics_upserted": int}
    """
    db = client[db_name]
    alerts_upserted = 0
    metrics_upserted = 0

    try:
        # 1. Bulk upsert alerts if any are present
        if alert_docs:
            ops = [
                ReplaceOne({"_id": doc["_id"]}, doc, upsert=True)
                for doc in alert_docs
            ]
            bulk_res = db["threat_alerts"].bulk_write(ops, ordered=False)
            alerts_upserted = (bulk_res.upserted_count or 0) + (bulk_res.matched_count or 0)

        # 2. Upsert batch metric summary document
        if metric_doc:
            db["batch_metrics"].replace_one(
                {"_id": metric_doc["_id"]},
                metric_doc,
                upsert=True
            )
            metrics_upserted = 1

    except PyMongoError as exc:
        # Re-raise to ensure Spark streaming query detects write failure
        raise RuntimeError(f"MongoDB persistence failed for batch: {exc}") from exc

    return {
        "alerts_upserted": alerts_upserted,
        "metrics_upserted": metrics_upserted
    }


def row_to_alert_document(
    row: Any,
    detector_version: str = "1.0-rules",
    run_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Transforms a Spark Row (or dict) representing a predicted threat alert
    into a standardized, deterministic MongoDB document.
    """
    def _get(field, default=None):
        if hasattr(row, field):
            val = getattr(row, field)
            return default if val is None else val
        elif isinstance(row, dict):
            val = row.get(field)
            return default if val is None else val
        return default

    is_invalid = _get("is_invalid_metadata", 0)
    burst_delta = _get("rule_burst_delta", 0)
    susp_ttl = _get("rule_suspicious_ttl", 0)
    anom_len = _get("rule_anomalous_len", 0)

    reasons = []
    if is_invalid:
        reasons.append("INVALID_METADATA")
    if burst_delta:
        reasons.append("RAPID_BURST_DELTA")
    if susp_ttl:
        reasons.append("KNOWN_ATTACK_ORIGIN_TTL")
    if anom_len:
        reasons.append("ANOMALOUS_LEN")
    ml_attack = _get("ml_attack", 0)
    if ml_attack:
        reasons.append("ML_PAYLOAD_ANOMALY")
    alert_reason = ";".join(reasons) if reasons else "HEURISTIC_ALERT"

    has_gt = _get("has_valid_ground_truth", 0)
    gt_is_attack = _get("is_ground_truth_attack", None) if has_gt else None
    target_run_id = _get("run_id", run_id)

    return build_alert_document(
        topic=_get("topic", "network-records"),
        kafka_partition=int(_get("kafka_partition", 0)),
        kafka_offset=int(_get("kafka_offset", 0)),
        protocol=_get("protocol", "unknown"),
        ttl=_get("ttl"),
        total_len=_get("total_len"),
        t_delta=_get("t_delta"),
        predicted_attack=int(_get("predicted_attack", 1)),
        alert_reason=alert_reason,
        event_timestamp=_get("event_timestamp"),
        ground_truth_label=_get("label"),
        ground_truth_is_attack=gt_is_attack,
        detector_version=("2.0-hybrid" if _get("ml_attack_prob") is not None else detector_version),
        run_id=target_run_id,
    )


def persist_alerts_partition(
    iterator,
    mongo_uri: str,
    db_name: str,
    batch_size: int = 1000,
    run_id: Optional[str] = None
) -> int:
    """
    Persists a partition of predicted alert Rows to MongoDB in bounded bulk chunks.
    Avoids driver-side collect() by executing directly on Spark executor workers.
    Ensures MongoClient is closed cleanly in a finally block.
    Propagates PyMongoError if persistence fails.
    
    Returns:
        int: Total number of alert operations executed in this partition.
    """
    client = None
    total_written = 0
    try:
        ops = []
        for row in iterator:
            if client is None:
                client = MongoClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", "10000")),
                    maxPoolSize=10,
                )
            doc = row_to_alert_document(row, run_id=run_id)
            ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))
            if len(ops) >= batch_size:
                client[db_name]["threat_alerts"].bulk_write(ops, ordered=False)
                total_written += len(ops)
                ops.clear()

        if ops and client is not None:
            client[db_name]["threat_alerts"].bulk_write(ops, ordered=False)
            total_written += len(ops)
            ops.clear()

    except PyMongoError as exc:
        raise RuntimeError(f"MongoDB alert partition persistence failed: {exc}") from exc
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    return total_written


def persist_batch_metric(
    client: MongoClient,
    db_name: str,
    metric_doc: Dict[str, Any]
) -> int:
    """
    Persists a single micro-batch metric document to batch_metrics.
    Uses ReplaceOne with upsert=True for idempotency.
    Propagates PyMongoError if persistence fails.
    
    Returns:
        int: 1 on success.
    """
    try:
        db = client[db_name]
        db["batch_metrics"].replace_one(
            {"_id": metric_doc["_id"]},
            metric_doc,
            upsert=True
        )
        return 1
    except PyMongoError as exc:
        raise RuntimeError(f"MongoDB batch metric persistence failed: {exc}") from exc

