"""
dashboard_utils.py — Data Access and Aggregation Helpers for Streamlit Dashboard.

Provides read-only queries, safe classification metric aggregations, bounded
pagination, and connection health checks for MongoDB collections `threat_alerts`
and `batch_metrics`.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError


def get_secret_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Safely resolves configuration keys with strict fallback priority:
    1. Streamlit secrets (st.secrets) if running under Streamlit and key exists.
    2. Environment variable (os.getenv).
    3. Provided default fallback.

    Gracefully catches StreamlitSecretNotFoundError or KeyError when secrets.toml
    is not configured.
    """
    try:
        import streamlit as st
        if hasattr(st, "secrets"):
            val = st.secrets.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    except Exception:
        pass

    env_val = os.getenv(key)
    if env_val is not None and str(env_val).strip():
        return str(env_val).strip()

    return default


def get_mongo_connection(
    uri: Optional[str] = None,
    server_timeout_ms: int = 4000
) -> MongoClient:
    """
    Initializes a read-only MongoClient with bounded timeouts.
    Resolves URI from explicit parameter -> st.secrets -> os.getenv -> localhost default.
    """
    target_uri = uri or get_secret_setting("MONGODB_URI", "mongodb://localhost:27017")
    return MongoClient(
        target_uri,
        serverSelectionTimeoutMS=server_timeout_ms,
        connectTimeoutMS=server_timeout_ms,
        socketTimeoutMS=5000,
        maxPoolSize=10,
    )


def test_mongo_connection(client: MongoClient) -> Tuple[bool, Optional[str]]:
    """
    Validates MongoDB connectivity with a quick ping command.
    Returns (is_connected, error_message).
    """
    try:
        client.admin.command("ping")
        return True, None
    except Exception as exc:
        return False, str(exc)


def calculate_aggregate_confusion_matrix(batch_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes aggregated confusion-matrix and classification metrics across batches.
    
    IMPORTANT: Aggregated metrics are calculated from SUMMED counts (TP, FP, TN, FN),
    NEVER from an unweighted average of individual batch precision or recall.
    Zero-division cases return None safely.
    """
    tp_sum = 0
    fp_sum = 0
    tn_sum = 0
    fn_sum = 0
    eval_batch_count = 0

    for doc in batch_docs:
        tp = doc.get("tp")
        fp = doc.get("fp")
        tn = doc.get("tn")
        fn = doc.get("fn")
        if tp is not None and fp is not None and tn is not None and fn is not None:
            tp_sum += int(tp)
            fp_sum += int(fp)
            tn_sum += int(tn)
            fn_sum += int(fn)
            eval_batch_count += 1

    if eval_batch_count == 0:
        return {
            "has_eval_data": False,
            "eval_batch_count": 0,
            "tp": None,
            "fp": None,
            "tn": None,
            "fn": None,
            "actual_attacks": None,
            "actual_benign": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "fpr": None,
            "accuracy": None,
        }

    actual_attacks = tp_sum + fn_sum
    actual_benign = tn_sum + fp_sum
    total_eval = tp_sum + fp_sum + tn_sum + fn_sum

    precision = round(float(tp_sum) / float(tp_sum + fp_sum), 4) if (tp_sum + fp_sum) > 0 else None
    recall = round(float(tp_sum) / float(tp_sum + fn_sum), 4) if (tp_sum + fn_sum) > 0 else None
    
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = round(2.0 * precision * recall / (precision + recall), 4)

    fpr = round(float(fp_sum) / float(fp_sum + tn_sum), 4) if (fp_sum + tn_sum) > 0 else None
    accuracy = round(float(tp_sum + tn_sum) / float(total_eval), 4) if total_eval > 0 else None

    return {
        "has_eval_data": True,
        "eval_batch_count": eval_batch_count,
        "tp": tp_sum,
        "fp": fp_sum,
        "tn": tn_sum,
        "fn": fn_sum,
        "actual_attacks": actual_attacks,
        "actual_benign": actual_benign,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "accuracy": accuracy,
    }


def get_available_runs(db) -> List[str]:
    """
    Returns list of distinct run_ids present in batch_metrics and threat_alerts collections.
    Includes 'Legacy / Unassigned' if documents exist without a run_id.
    """
    try:
        metric_runs = set(db["batch_metrics"].distinct("run_id"))
        alert_runs = set(db["threat_alerts"].distinct("run_id"))
        distinct_runs = sorted(list((metric_runs | alert_runs) - {None, ""}))

        has_legacy = (
            db["threat_alerts"].count_documents({"$or": [{"run_id": {"$exists": False}}, {"run_id": None}]}) > 0
            or db["batch_metrics"].count_documents({"$or": [{"run_id": {"$exists": False}}, {"run_id": None}]}) > 0
        )
        if has_legacy:
            distinct_runs.append("Legacy / Unassigned")

        return distinct_runs
    except Exception:
        return []


def get_overview_metrics(
    db,
    run_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Aggregates high-level streaming counters from batch_metrics and threat_alerts.
    Clearly distinguishes accumulated micro-batch metrics from alert document count.
    """
    batch_filter: Dict[str, Any] = {}
    if run_id and run_id != "All Runs":
        if run_id == "Legacy / Unassigned":
            batch_filter["$or"] = [{"run_id": {"$exists": False}}, {"run_id": None}]
        else:
            batch_filter["run_id"] = run_id

    if start_time or end_time:
        ts_cond: Dict[str, Any] = {}
        if start_time:
            ts_cond["$gte"] = start_time
        if end_time:
            ts_cond["$lte"] = end_time
        batch_filter["timestamp"] = ts_cond

    batches = list(db["batch_metrics"].find(
        batch_filter,
        {
            "total_records": 1,
            "valid_records": 1,
            "malformed_records": 1,
            "alert_count": 1,
            "normal_count": 1,
            "timestamp": 1,
            "run_id": 1,
            "batch_id": 1
        }
    ).sort([("timestamp", ASCENDING), ("batch_id", ASCENDING)]))

    total_records = sum(b.get("total_records", 0) for b in batches)
    valid_records = sum(b.get("valid_records", 0) for b in batches)
    malformed_records = sum(b.get("malformed_records", 0) for b in batches)
    accumulated_alerts = sum(b.get("alert_count", 0) for b in batches)
    accumulated_normal = sum(b.get("normal_count", 0) for b in batches)
    total_batches = len(batches)

    overall_alert_rate = (
        round(accumulated_alerts / total_records, 4)
        if total_records > 0 else None
    )

    most_recent_batch_time = None
    if batches:
        timestamps = [b["timestamp"] for b in batches if b.get("timestamp")]
        if timestamps:
            most_recent_batch_time = max(timestamps)

    # Count actual stored threat alert documents in threat_alerts (filtered by run_id)
    alert_filter: Dict[str, Any] = {}
    if run_id and run_id != "All Runs":
        if run_id == "Legacy / Unassigned":
            alert_filter["$or"] = [{"run_id": {"$exists": False}}, {"run_id": None}]
        else:
            alert_filter["run_id"] = run_id

    if start_time or end_time:
        alert_ts_cond: Dict[str, Any] = {}
        if start_time:
            alert_ts_cond["$gte"] = start_time
        if end_time:
            alert_ts_cond["$lte"] = end_time
        alert_filter["stored_at"] = alert_ts_cond

    stored_alerts_count = db["threat_alerts"].count_documents(alert_filter)

    return {
        "total_records": total_records,
        "valid_records": valid_records,
        "malformed_records": malformed_records,
        "accumulated_alerts": accumulated_alerts,
        "accumulated_normal": accumulated_normal,
        "overall_alert_rate": overall_alert_rate,
        "total_batches": total_batches,
        "most_recent_batch_time": most_recent_batch_time,
        "stored_alerts_count": stored_alerts_count,
        "batch_count": len(batches),
    }


def get_traffic_summary(
    db,
    run_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Computes traffic and alert distributions:
    - Protocol breakdown (TCP vs UDP)
    - Primary alert reasons
    - Individual heuristic rule frequencies across unique alert records
    - Temporal alert activity
    """
    alert_filter: Dict[str, Any] = {}
    if start_time or end_time:
        ts_cond: Dict[str, Any] = {}
        if start_time:
            ts_cond["$gte"] = start_time
        if end_time:
            ts_cond["$lte"] = end_time
        alert_filter["stored_at"] = ts_cond

    # 1. Protocol counts
    proto_pipeline = [
        {"$match": alert_filter},
        {"$group": {"_id": {"$ifNull": ["$protocol", "unknown"]}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    proto_res = list(db["threat_alerts"].aggregate(proto_pipeline))
    protocol_counts = {item["_id"]: item["count"] for item in proto_res}

    # 2. Alert Reason Breakdown & Individual Rule Triggers
    alerts_cursor = db["threat_alerts"].find(
        alert_filter,
        {"alert_reason": 1, "protocol": 1, "stored_at": 1, "event_timestamp": 1}
    ).limit(5000)

    unique_reason_counts: Dict[str, int] = {}
    rule_frequency: Dict[str, int] = {}
    temporal_buckets: Dict[str, int] = {}
    total_alerts_analyzed = 0

    for doc in alerts_cursor:
        total_alerts_analyzed += 1
        raw_reason = doc.get("alert_reason") or "UNKNOWN"
        unique_reason_counts[raw_reason] = unique_reason_counts.get(raw_reason, 0) + 1

        # Break down individual heuristic rules without double-counting the record itself
        rules = [r.strip() for r in raw_reason.split(";") if r.strip()]
        for rule in set(rules):  # set prevents counting same rule twice within 1 record
            rule_frequency[rule] = rule_frequency.get(rule, 0) + 1

        # Temporal binning by minute or 10-second window
        ts = doc.get("event_timestamp") or doc.get("stored_at")
        if isinstance(ts, datetime):
            time_key = ts.strftime("%H:%M:%S")
            temporal_buckets[time_key] = temporal_buckets.get(time_key, 0) + 1

    return {
        "total_alerts": total_alerts_analyzed,
        "protocol_counts": protocol_counts,
        "unique_reason_counts": unique_reason_counts,
        "rule_frequency": rule_frequency,
        "temporal_buckets": temporal_buckets,
    }


def get_filtered_alerts(
    db,
    run_id: Optional[str] = None,
    protocol: Optional[str] = None,
    alert_reason: Optional[str] = None,
    ground_truth: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    sort_field: str = "stored_at",
    sort_direction: int = -1,
    limit: int = 50,
    skip: int = 0
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Retrieves a paginated list of threat alert documents with safe projections.
    Optionally filters by run_id (supporting 'Legacy / Unassigned' for historical docs).
    Returns (records, total_matching_count).
    """
    filter_dict: Dict[str, Any] = {}

    if run_id and run_id != "All Runs":
        if run_id == "Legacy / Unassigned":
            filter_dict["$or"] = [{"run_id": {"$exists": False}}, {"run_id": None}]
        else:
            filter_dict["run_id"] = run_id

    if protocol and protocol != "All":
        filter_dict["protocol"] = protocol.lower()

    if alert_reason and alert_reason != "All":
        # Match alerts that contain this rule or composite reason
        filter_dict["alert_reason"] = {"$regex": alert_reason, "$options": "i"}

    if ground_truth and ground_truth != "All":
        if ground_truth == "ATTACK (All attacks)":
            filter_dict["ground_truth_is_attack"] = 1
        elif ground_truth == "BENIGN":
            filter_dict["ground_truth_label"] = "BENIGN"
        else:
            filter_dict["ground_truth_label"] = ground_truth

    if start_time or end_time:
        ts_cond: Dict[str, Any] = {}
        if start_time:
            ts_cond["$gte"] = start_time
        if end_time:
            ts_cond["$lte"] = end_time
        filter_dict["stored_at"] = ts_cond

    total_matching = db["threat_alerts"].count_documents(filter_dict)

    projection = {
        "_id": 1,
        "run_id": 1,
        "topic": 1,
        "kafka_partition": 1,
        "kafka_offset": 1,
        "event_timestamp": 1,
        "stored_at": 1,
        "protocol": 1,
        "ttl": 1,
        "total_len": 1,
        "t_delta": 1,
        "predicted_attack": 1,
        "alert_reason": 1,
        "ground_truth_label": 1,
        "ground_truth_is_attack": 1,
        "detector_version": 1,
    }

    # Validate sort field
    valid_sorts = ["stored_at", "event_timestamp", "kafka_offset", "ttl", "total_len", "t_delta"]
    actual_sort_field = sort_field if sort_field in valid_sorts else "stored_at"

    cursor = (
        db["threat_alerts"]
        .find(filter_dict, projection)
        .sort([(actual_sort_field, sort_direction)])
        .skip(max(0, skip))
        .limit(max(1, min(limit, 500)))  # Cap max limit to 500
    )

    return list(cursor), total_matching


def get_historical_batches(
    db,
    run_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Returns ordered micro-batch metrics sorted by timestamp and batch_id.
    Includes cumulative counters and alert rates.
    """
    batch_filter: Dict[str, Any] = {}
    if run_id and run_id != "All Runs":
        batch_filter["run_id"] = run_id

    if start_time or end_time:
        ts_cond: Dict[str, Any] = {}
        if start_time:
            ts_cond["$gte"] = start_time
        if end_time:
            ts_cond["$lte"] = end_time
        batch_filter["timestamp"] = ts_cond

    cursor = db["batch_metrics"].find(batch_filter).sort([
        ("timestamp", ASCENDING),
        ("batch_id", ASCENDING)
    ])

    batches = list(cursor)
    cumulative_records = 0
    cumulative_alerts = 0

    for b in batches:
        rec = b.get("total_records", 0)
        alr = b.get("alert_count", 0)
        cumulative_records += rec
        cumulative_alerts += alr
        b["cumulative_records"] = cumulative_records
        b["cumulative_alerts"] = cumulative_alerts
        b["alert_rate"] = round(alr / rec, 4) if rec > 0 else 0.0

    return batches


# -----------------------------------------------------------------------------
# Lambda-architecture additions: batch rollups, data-lake stats, DR status, lag
# -----------------------------------------------------------------------------
ROLLUP_COLLECTION = "historical_threat_rollups"


def get_historical_rollups(db, rollup_type: str, run_id: Optional[str] = None,
                           limit: int = 5000) -> List[Dict[str, Any]]:
    """
    Read pre-computed batch views from `historical_threat_rollups` (serving layer).
    Returns each rollup's `data` payload; [] if the collection/run is absent.
    """
    try:
        query: Dict[str, Any] = {"rollup_type": rollup_type}
        if run_id and run_id != "All Runs":
            query["run_id"] = run_id
        cursor = db[ROLLUP_COLLECTION].find(query).sort("key", ASCENDING).limit(max(1, min(int(limit), 20000)))
        out = []
        for doc in cursor:
            row = dict(doc.get("data") or {})
            row["run_id"] = doc.get("run_id")
            row["generated_at"] = doc.get("generated_at")
            out.append(row)
        return out
    except PyMongoError:
        return []


def get_rollup_runs(db) -> List[str]:
    """Run IDs that have batch rollups."""
    try:
        return sorted(r for r in db[ROLLUP_COLLECTION].distinct("run_id") if r)
    except PyMongoError:
        return []


def get_lake_stats(lake_dir: str) -> Dict[str, Any]:
    """Parquet lake size/file count; available=False when the lake is not on this host (e.g. Streamlit Cloud)."""
    if not lake_dir or not os.path.isdir(lake_dir):
        return {"available": False, "bytes": 0, "files": 0}
    total, files = 0, 0
    for root, _d, names in os.walk(lake_dir):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(root, n))
            except OSError:
                continue
            if n.endswith(".parquet"):
                files += 1
    return {"available": True, "bytes": total, "files": files}


def get_backup_status(backup_dir: str) -> Dict[str, Any]:
    """Latest backup snapshot info (timestamp, verification, sizes) for the DR card."""
    try:
        from scripts.backup_manager import backup_status
        st = backup_status(backup_dir)
        st["available"] = st["count"] > 0
        return st
    except Exception:
        return {"available": False, "count": 0, "latest_time": None, "latest_verified": None,
                "total_bytes": 0, "latest_bytes": 0}


def read_checkpoint_offsets(checkpoint_dir: str) -> Dict[str, Dict[str, int]]:
    """
    Latest committed source offsets from a Spark Structured Streaming checkpoint:
    {topic: {partition: offset}}.  Reads the newest file in `<ckpt>/offsets/`.
    """
    import json
    off_dir = os.path.join(checkpoint_dir, "offsets")
    if not os.path.isdir(off_dir):
        return {}
    ids = sorted((int(n) for n in os.listdir(off_dir) if n.isdigit()))
    if not ids:
        return {}
    try:
        with open(os.path.join(off_dir, str(ids[-1]))) as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        return json.loads(lines[-1])
    except (OSError, ValueError, IndexError):
        return {}


def compute_lag(end_offsets: Dict[int, int], committed: Dict[str, int]) -> Dict[str, Any]:
    """Pure helper: per-partition and total lag = log-end offset - committed offset."""
    per = {}
    for part, end in end_offsets.items():
        per[int(part)] = max(0, int(end) - int(committed.get(str(part), 0)))
    return {"per_partition": per, "total": sum(per.values()), "partitions": len(per)}


def get_kafka_consumer_lag(bootstrap: str, topic: str, checkpoint_dir: str,
                           timeout_ms: int = 3000) -> Dict[str, Any]:
    """
    Consumer lag of the Spark streaming query = Kafka log-end offsets minus the
    offsets recorded in its checkpoint (Spark does not commit to consumer groups).
    Returns {"available": False, ...} gracefully when Kafka is unreachable.
    """
    try:
        import socket
        host, _, port = bootstrap.split(",")[0].partition(":")
        # Fast reachability pre-check so an absent broker (e.g. Streamlit Cloud) fails in ~1s, not 30s.
        socket.create_connection((host or "localhost", int(port or 9092)), timeout=1.0).close()
        from kafka import KafkaConsumer, TopicPartition
        consumer = KafkaConsumer(bootstrap_servers=bootstrap.split(","),
                                 request_timeout_ms=max(timeout_ms, 11000), session_timeout_ms=10000,
                                 heartbeat_interval_ms=3000, group_id=None)
        try:
            parts = consumer.partitions_for_topic(topic)
            if not parts:
                return {"available": False, "reason": f"topic '{topic}' not found"}
            tps = [TopicPartition(topic, p) for p in sorted(parts)]
            ends = {tp.partition: off for tp, off in consumer.end_offsets(tps).items()}
        finally:
            consumer.close()
        committed = read_checkpoint_offsets(checkpoint_dir).get(topic, {})
        res = compute_lag(ends, committed)
        res.update({"available": True, "has_checkpoint": bool(committed)})
        return res
    except Exception as exc:
        return {"available": False, "reason": str(exc)[:120]}


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def get_replica_set_status(uri: str, timeout_ms: int = 1500) -> Dict[str, Any]:
    """
    Replica-set member states for the DR card.  Gracefully reports available=False for
    standalone servers / Atlas users without replSetGetStatus rights.
    """
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        try:
            st = client.admin.command("replSetGetStatus")
        finally:
            client.close()
        members = [{"name": m["name"], "state": m["stateStr"], "healthy": bool(m.get("health"))}
                   for m in st.get("members", [])]
        return {"available": True, "set": st.get("set"), "members": members,
                "healthy_count": sum(1 for m in members if m["healthy"]),
                "has_primary": any(m["state"] == "PRIMARY" for m in members)}
    except Exception as exc:
        return {"available": False, "reason": str(exc)[:100]}


def get_cluster_status(uri: str, timeout_ms: int = 1500) -> Dict[str, Any]:
    """
    Data-tier health for the DR card.  Through a mongos router: every shard's replica-set members
    and roles.  Against a plain replica set: that one set.  Standalone/unreachable: available=False.
    """
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        try:
            shards = client.admin.command("listShards")["shards"]
        finally:
            client.close()
    except Exception:
        rs = get_replica_set_status(uri, timeout_ms)
        if rs.get("available"):
            return {"available": True, "sharded": False, "shards": {rs["set"]: rs}}
        return {"available": False, "reason": rs.get("reason", "")}
    out = {}
    for sh in shards:
        rs_name, _, hosts = sh["host"].partition("/")
        out[sh["_id"]] = get_replica_set_status(f"mongodb://{hosts}/?replicaSet={rs_name}", timeout_ms)
    return {"available": True, "sharded": True, "shards": out}
