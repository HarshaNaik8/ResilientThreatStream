"""
batch_analytics.py — Batch layer of the Lambda Architecture.

Runs Spark SQL (HiveQL-style) over the immutable Parquet data lake and writes
pre-computed views ("batch views") into MongoDB ``historical_threat_rollups``,
which the dashboard's serving layer reads with a single cheap query.

Rollup types (``rollup_type``):
  * tumbling_window   - non-overlapping time windows (alerts, volume, entropy)
  * sliding_window    - overlapping windows (smoothed trend; window > slide)
  * protocol_summary  - top attacked protocols
  * attack_family     - volume + detection rate per ground-truth family (post-hoc)
  * entropy_hist      - payload-entropy distribution, benign vs attack
  * hop_heatmap       - protocol x TTL-bucket threat heatmap (network-distance
                        proxy; the CIC payload dataset has no IP addresses, so
                        a true subnet heatmap is not derivable)
  * storage_format    - Parquet vs CSV size/scan benchmark (storage-choice study)

Time axis: ``event_time`` is the Kafka ingestion timestamp.  In a historical
replay it spans replay wall-clock, so windows are configurable (default 1 min).

Usage::

    python batch_analytics.py --lake-dir data/lake --run-id <run> [--window "1 minute"]
"""

import os as _os
import sys as _sys
# Python UDF workers must use the same interpreter as the driver (venv), not system python.
_os.environ.setdefault("PYSPARK_PYTHON", _sys.executable)
_os.environ.setdefault("PYSPARK_DRIVER_PYTHON", _sys.executable)

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pyspark.sql import DataFrame, SparkSession

from lake_sink import EVENTS_SUBDIR, lake_file_count, lake_size_bytes

ROLLUP_COLLECTION = "historical_threat_rollups"
EVENTS_VIEW = "lake_events"


def get_spark(app: str = "BatchLakeAnalytics", shuffle_partitions: int = 8) -> SparkSession:
    return (SparkSession.builder.appName(app)
            .config("spark.sql.shuffle.partitions", str(shuffle_partitions))
            .config("spark.ui.showConsoleProgress", "false")
            .getOrCreate())


def register_lake(spark: SparkSession, lake_dir: str, run_id: Optional[str] = None) -> DataFrame:
    """Read the lake (partition discovery on run_id/protocol) and expose it as a SQL view."""
    path = os.path.join(lake_dir, EVENTS_SUBDIR)
    df = spark.read.parquet(path)          # partition pruning on run_id/protocol
    if run_id:
        df = df.filter(df.run_id == run_id)
    df.createOrReplaceTempView(EVENTS_VIEW)
    return df


# ----------------------------------------------------------------------------
# Queries (Spark SQL)
# ----------------------------------------------------------------------------
def q_tumbling(spark, window: str) -> List[Dict[str, Any]]:
    rows = spark.sql(f"""
        SELECT window.start AS window_start, window.end AS window_end,
               COUNT(*) AS events,
               SUM(predicted_attack) AS alerts,
               ROUND(SUM(predicted_attack) / COUNT(*), 4) AS alert_rate,
               ROUND(AVG(payload_entropy), 4) AS avg_entropy,
               SUM(CASE WHEN label <> 'BENIGN' THEN 1 ELSE 0 END) AS true_attacks
        FROM {EVENTS_VIEW}
        GROUP BY window(event_time, '{window}')
        ORDER BY window_start
    """).collect()
    return [r.asDict() for r in rows]


def q_sliding(spark, window: str, slide: str) -> List[Dict[str, Any]]:
    rows = spark.sql(f"""
        SELECT window.start AS window_start, window.end AS window_end,
               COUNT(*) AS events, SUM(predicted_attack) AS alerts,
               ROUND(SUM(predicted_attack) / COUNT(*), 4) AS alert_rate
        FROM {EVENTS_VIEW}
        GROUP BY window(event_time, '{window}', '{slide}')
        ORDER BY window_start
    """).collect()
    return [r.asDict() for r in rows]


def q_protocols(spark) -> List[Dict[str, Any]]:
    rows = spark.sql(f"""
        SELECT protocol, COUNT(*) AS events, SUM(predicted_attack) AS alerts,
               ROUND(SUM(predicted_attack) / COUNT(*), 4) AS alert_rate,
               ROUND(AVG(total_len), 2) AS avg_len, ROUND(AVG(ttl), 2) AS avg_ttl
        FROM {EVENTS_VIEW}
        GROUP BY protocol ORDER BY alerts DESC
    """).collect()
    return [r.asDict() for r in rows]


def q_attack_families(spark) -> List[Dict[str, Any]]:
    rows = spark.sql(f"""
        SELECT label, COUNT(*) AS events, SUM(predicted_attack) AS detected,
               ROUND(SUM(predicted_attack) / COUNT(*), 4) AS detection_rate,
               SUM(COALESCE(rule_attack, 0)) AS rule_detected,
               ROUND(SUM(COALESCE(rule_attack, 0)) / COUNT(*), 4) AS rule_detection_rate
        FROM {EVENTS_VIEW}
        GROUP BY label ORDER BY events DESC
    """).collect()
    return [r.asDict() for r in rows]


def q_entropy_hist(spark, bins: int = 16) -> List[Dict[str, Any]]:
    """Payload entropy (0..8 bits) bucketed, split benign vs attack."""
    width = 8.0 / bins
    rows = spark.sql(f"""
        SELECT CAST(FLOOR(LEAST(payload_entropy, 7.9999) / {width}) AS INT) AS bin,
               SUM(CASE WHEN label = 'BENIGN' THEN 1 ELSE 0 END) AS benign,
               SUM(CASE WHEN label <> 'BENIGN' THEN 1 ELSE 0 END) AS attack
        FROM {EVENTS_VIEW} WHERE payload_entropy IS NOT NULL
        GROUP BY 1 ORDER BY 1
    """).collect()
    out = []
    for r in rows:
        d = r.asDict()
        d["bin_low"] = round(d["bin"] * width, 4)
        d["bin_high"] = round((d["bin"] + 1) * width, 4)
        out.append(d)
    return out


def q_hop_heatmap(spark) -> List[Dict[str, Any]]:
    """Protocol x TTL-bucket (hop-distance proxy) -> events & alert rate."""
    rows = spark.sql(f"""
        SELECT protocol,
               CASE WHEN ttl < 32 THEN '<32' WHEN ttl < 64 THEN '32-63'
                    WHEN ttl < 128 THEN '64-127' ELSE '128+' END AS ttl_bucket,
               COUNT(*) AS events, SUM(predicted_attack) AS alerts,
               ROUND(SUM(predicted_attack) / COUNT(*), 4) AS alert_rate
        FROM {EVENTS_VIEW} WHERE ttl IS NOT NULL
        GROUP BY protocol, 2 ORDER BY protocol, 2
    """).collect()
    return [r.asDict() for r in rows]


def storage_format_benchmark(spark: SparkSession, lake_df: DataFrame, scratch_dir: str) -> Dict[str, Any]:
    """
    Compare row-oriented CSV with columnar Parquet(snappy) for the same data:
    on-disk size and the time of a single-column aggregate scan (column pruning).
    """
    import shutil
    csv_dir = os.path.join(scratch_dir, "bench_csv")
    pq_dir = os.path.join(scratch_dir, "bench_parquet")
    for d in (csv_dir, pq_dir):
        shutil.rmtree(d, ignore_errors=True)
    sample = lake_df.drop("run_id", "protocol").coalesce(4)
    sample.write.mode("overwrite").option("header", True).csv(csv_dir)
    sample.write.mode("overwrite").option("compression", "snappy").parquet(pq_dir)

    def timed(reader):
        t = time.time()
        reader().selectExpr("AVG(payload_entropy)").collect()
        return round(time.time() - t, 3)

    csv_t = timed(lambda: spark.read.option("header", True).option("inferSchema", True).csv(csv_dir))
    pq_t = timed(lambda: spark.read.parquet(pq_dir))
    csv_b, pq_b = lake_size_bytes(csv_dir), lake_size_bytes(pq_dir)
    shutil.rmtree(csv_dir, ignore_errors=True)
    shutil.rmtree(pq_dir, ignore_errors=True)
    return {
        "csv_bytes": csv_b, "parquet_bytes": pq_b,
        "compression_ratio": round(csv_b / pq_b, 2) if pq_b else None,
        "csv_scan_seconds": csv_t, "parquet_scan_seconds": pq_t,
    }


# ----------------------------------------------------------------------------
# Rollup assembly + persistence
# ----------------------------------------------------------------------------
def make_rollup_doc(run_id: str, rollup_type: str, key: str, data: Dict[str, Any],
                    generated_at: Optional[datetime] = None) -> Dict[str, Any]:
    """Deterministic _id => re-running the batch job overwrites (idempotent batch view)."""
    return {
        "_id": f"{run_id}:{rollup_type}:{key}",
        "run_id": run_id,
        "rollup_type": rollup_type,
        "key": key,
        "data": data,
        "generated_at": generated_at or datetime.now(timezone.utc),
    }


def build_rollups(spark: SparkSession, run_id: str, window: str = "1 minute",
                  sliding_window: str = "5 minutes", sliding_slide: str = "1 minute",
                  scratch_dir: Optional[str] = None, lake_df: Optional[DataFrame] = None
                  ) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    docs: List[Dict[str, Any]] = []

    for r in q_tumbling(spark, window):
        key = r["window_start"].strftime("%Y%m%dT%H%M%S")
        docs.append(make_rollup_doc(run_id, "tumbling_window", f"{window}:{key}", r, now))
    for r in q_sliding(spark, sliding_window, sliding_slide):
        key = r["window_start"].strftime("%Y%m%dT%H%M%S")
        docs.append(make_rollup_doc(run_id, "sliding_window", f"{sliding_window}/{sliding_slide}:{key}", r, now))
    for r in q_protocols(spark):
        docs.append(make_rollup_doc(run_id, "protocol_summary", r["protocol"], r, now))
    for r in q_attack_families(spark):
        docs.append(make_rollup_doc(run_id, "attack_family", r["label"], r, now))
    for r in q_entropy_hist(spark):
        docs.append(make_rollup_doc(run_id, "entropy_hist", f"{r['bin']:02d}", r, now))
    for r in q_hop_heatmap(spark):
        docs.append(make_rollup_doc(run_id, "hop_heatmap", f"{r['protocol']}:{r['ttl_bucket']}", r, now))
    if scratch_dir and lake_df is not None:
        docs.append(make_rollup_doc(run_id, "storage_format", "csv_vs_parquet",
                                    storage_format_benchmark(spark, lake_df, scratch_dir), now))
    return docs


def persist_rollups(docs: List[Dict[str, Any]], mongo_uri: str, db_name: str) -> int:
    from pymongo import MongoClient, ReplaceOne, ASCENDING
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    try:
        col = client[db_name][ROLLUP_COLLECTION]
        col.create_index([("run_id", ASCENDING), ("rollup_type", ASCENDING)])   # default name == the shard-key index
        if docs:
            col.bulk_write([ReplaceOne({"_id": d["_id"]}, d, upsert=True) for d in docs], ordered=False)
        return len(docs)
    finally:
        client.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Spark batch analytics over the Parquet data lake.")
    ap.add_argument("--lake-dir", default="data/lake")
    ap.add_argument("--run-id", default=None, help="Restrict to one run (default: every run found, one rollup set each)")
    ap.add_argument("--window", default="1 minute", help="Tumbling window (default '1 minute')")
    ap.add_argument("--sliding-window", default="5 minutes")
    ap.add_argument("--sliding-slide", default="1 minute")
    ap.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", default=os.getenv("MONGODB_DATABASE", "network_threat_analytics"))
    ap.add_argument("--scratch-dir", default="data/tmp_bench", help="Where the CSV-vs-Parquet benchmark writes (deleted after)")
    ap.add_argument("--skip-storage-benchmark", action="store_true")
    ap.add_argument("--shuffle-partitions", type=int, default=8)
    args = ap.parse_args(argv)

    spark = get_spark(shuffle_partitions=args.shuffle_partitions)
    spark.sparkContext.setLogLevel("ERROR")
    base = spark.read.parquet(os.path.join(args.lake_dir, EVENTS_SUBDIR))
    run_ids = [args.run_id] if args.run_id else [r.run_id for r in base.select("run_id").distinct().collect()]
    print(f"[Batch] Lake: {args.lake_dir} | {lake_file_count(args.lake_dir)} parquet files | "
          f"{lake_size_bytes(args.lake_dir)/1e6:.1f} MB | runs: {run_ids}")
    total = 0
    for rid in run_ids:
        lake_df = register_lake(spark, args.lake_dir, rid)
        n = lake_df.count()
        t0 = time.time()
        docs = build_rollups(spark, rid, args.window, args.sliding_window, args.sliding_slide,
                             scratch_dir=None if args.skip_storage_benchmark else args.scratch_dir,
                             lake_df=lake_df)
        written = persist_rollups(docs, args.mongo_uri, args.mongo_db)
        total += written
        print(f"[Batch] run_id={rid}: {n:,} lake events -> {written} rollup docs in "
              f"'{ROLLUP_COLLECTION}' ({time.time()-t0:.1f}s)")
    spark.stop()
    return total


if __name__ == "__main__":
    sys.exit(0 if main() >= 0 else 1)
