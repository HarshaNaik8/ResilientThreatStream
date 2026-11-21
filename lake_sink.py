"""
lake_sink.py — Tiered-storage cold tier: append-only Apache Parquet Data Lake.

Lambda Architecture role
------------------------
MongoDB is the *hot* (speed-layer) store: only alerts + batch metrics, optimised
for low-latency dashboard reads.  The Parquet lake is the *cold* (batch-layer)
master dataset: **every valid event**, immutable, columnar, Snappy-compressed and
partitioned by ``run_id`` / ``protocol`` so batch SQL can prune partitions.

Layout::

    <lake_dir>/events/run_id=<run_id>/protocol=<protocol>/part-*.snappy.parquet

Zero data leakage: ``label`` is stored for post-hoc evaluation only; nothing in
this module feeds it back into detection.
"""

import os as _os
import sys as _sys
# Python UDF workers must use the same interpreter as the driver (venv), not system python.
_os.environ.setdefault("PYSPARK_PYTHON", _sys.executable)
_os.environ.setdefault("PYSPARK_DRIVER_PYTHON", _sys.executable)

import math
import os
from typing import Iterable, Optional, Sequence, Tuple

from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DoubleType, IntegerType, StructField, StructType,
)

EVENTS_SUBDIR = "events"
PARTITION_COLUMNS = ("run_id", "protocol")

# Columns written to the lake (partition columns included; Spark moves them to the path).
LAKE_COLUMNS = [
    "run_id", "protocol", "batch_id", "topic", "kafka_partition", "kafka_offset",
    "event_time", "ttl", "total_len", "t_delta", "label",
    "rule_attack", "ml_attack_prob", "ml_attack", "predicted_attack",
    "payload_entropy", "payload_mean", "payload_nonzero",
]

_PAYLOAD_STATS_SCHEMA = StructType([
    StructField("entropy", DoubleType(), True),
    StructField("mean", DoubleType(), True),
    StructField("nonzero", IntegerType(), True),
])


def payload_stats(payload: Optional[Sequence[int]]) -> Tuple[Optional[float], Optional[float], Optional[int]]:
    """
    Shannon entropy (bits, over the byte-value histogram), mean byte value and
    count of non-zero bytes for one payload.  Pure python so it is unit-testable;
    returns (None, None, None) for a missing/empty payload.
    """
    if not payload:
        return (None, None, None)
    n = len(payload)
    hist = {}
    total = 0
    nonzero = 0
    for b in payload:
        if b is None:
            continue
        hist[b] = hist.get(b, 0) + 1
        total += b
        if b != 0:
            nonzero += 1
    valid = sum(hist.values())
    if valid == 0:
        return (None, None, None)
    entropy = -sum((c / valid) * math.log2(c / valid) for c in hist.values())
    return (round(entropy, 6), round(total / valid, 6), nonzero)


_payload_stats_udf = F.udf(lambda p: payload_stats(p), _PAYLOAD_STATS_SCHEMA)


def add_payload_stats(df: DataFrame, drop_payload: bool = True) -> DataFrame:
    """
    Derive ``payload_entropy`` / ``payload_mean`` / ``payload_nonzero`` from the
    ``payload`` array (if present) so the 1,500-element array need not be cached,
    shipped to Mongo workers, or stored in the lake.  No-op if already derived.
    """
    if "payload" not in df.columns or "payload_entropy" in df.columns:
        return df
    out = df.withColumn("_ps", _payload_stats_udf(F.col("payload")))
    out = (out.withColumn("payload_entropy", F.col("_ps.entropy"))
              .withColumn("payload_mean", F.col("_ps.mean"))
              .withColumn("payload_nonzero", F.col("_ps.nonzero"))
              .drop("_ps"))
    return out.drop("payload") if drop_payload else out


def build_lake_dataframe(df: DataFrame, run_id: str, batch_id: int) -> DataFrame:
    """
    Project a scored micro-batch (valid rows only) onto the lake schema.

    Optional input columns (``payload``, ``rule_attack``, ``ml_attack_prob``,
    ``ml_attack``) are filled with NULL when absent, so the lake schema is stable
    regardless of whether the run used payloads / ML.
    """
    out = add_payload_stats(df)
    cols = set(out.columns)
    if "payload_entropy" not in cols:
        out = (out.withColumn("payload_entropy", F.lit(None).cast("double"))
                  .withColumn("payload_mean", F.lit(None).cast("double"))
                  .withColumn("payload_nonzero", F.lit(None).cast("int")))

    if "rule_attack" not in cols:
        base = "rule_predicted_attack" if "rule_predicted_attack" in cols else "predicted_attack"
        out = out.withColumn("rule_attack", F.col(base).cast("int"))
    if "ml_attack_prob" not in cols:
        out = out.withColumn("ml_attack_prob", F.lit(None).cast("double"))
    if "ml_attack" not in cols:
        out = out.withColumn("ml_attack", F.lit(None).cast("int"))

    out = (out
           .withColumn("run_id", F.lit(str(run_id)))
           .withColumn("batch_id", F.lit(int(batch_id)).cast("long"))
           .withColumn("event_time", F.col("event_timestamp"))
           .withColumn("protocol", F.lower(F.coalesce(F.trim(F.col("protocol")), F.lit("unknown"))))
           .withColumn("protocol", F.when(F.col("protocol") == "", "unknown").otherwise(F.col("protocol"))))
    return out.select(*LAKE_COLUMNS)


def write_batch_to_lake(df: DataFrame, lake_dir: str, run_id: str, batch_id: int) -> int:
    """
    Append one micro-batch to the Parquet lake (Snappy, partitioned).
    Returns the number of rows written.  Exceptions propagate so Spark's
    checkpoint is not advanced past a batch that failed to reach cold storage.
    """
    lake_df = build_lake_dataframe(df, run_id, batch_id)
    n = lake_df.count()
    if n == 0:
        return 0
    (lake_df.write
        .mode("append")
        .option("compression", "snappy")
        .partitionBy(*PARTITION_COLUMNS)
        .parquet(os.path.join(lake_dir, EVENTS_SUBDIR)))
    return n


def lake_size_bytes(lake_dir: str) -> int:
    """Total size in bytes of all files under the lake directory (0 if absent)."""
    total = 0
    for root, _dirs, files in os.walk(lake_dir):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def lake_file_count(lake_dir: str) -> int:
    """Number of Parquet part-files in the lake."""
    count = 0
    for _root, _dirs, files in os.walk(lake_dir):
        count += sum(1 for f in files if f.endswith(".parquet"))
    return count
