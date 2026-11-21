import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, when, trim, upper, count, sum as spark_sum, lit
)
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, DoubleType, ArrayType
)

from mongo_sink import (
    get_mongo_client,
    close_mongo_client,
    init_mongo_collections,
    build_alert_document,
    build_batch_metric_document,
    persist_micro_batch,
    persist_alerts_partition,
    persist_batch_metric,
    row_to_alert_document
)
from lake_sink import write_batch_to_lake, add_payload_stats
from ml_payload_detector import (
    load_model, score_dataframe, apply_hybrid, with_features_from_payload_array
)


def create_schema():
    """Define the expected JSON schema for network records, including corrupt record capture."""
    return StructType([
        StructField("ttl", IntegerType(), True),
        StructField("total_len", IntegerType(), True),
        StructField("protocol", StringType(), True),
        StructField("t_delta", DoubleType(), True),
        StructField("label", StringType(), True),
        StructField("payload", ArrayType(IntegerType()), True),
        StructField("_corrupt_record", StringType(), True),
    ])


def create_micro_batch_processor(run_id: str, mongo_uri: str, mongo_db: str,
                                 lake_dir=None, ml_model=None, ml_threshold: float = 0.5):
    """
    Factory creating a micro-batch handler with dual-write persistence
    (Lambda architecture): MongoDB hot store + optional Parquet cold lake.
    Optionally applies the Spark MLlib payload model for a hybrid verdict.
    """
    client = get_mongo_client(mongo_uri)
    init_mongo_collections(client, mongo_db)

    def process_micro_batch(batch_df, batch_id):
        batch_count = batch_df.count()
        if batch_count == 0:
            return

        batch_time = datetime.now(timezone.utc)
        print("\n" + "=" * 78)
        print(f"  SPARK STREAMING MICRO-BATCH {batch_id}  |  Total Received: {batch_count:,} records")
        print("=" * 78)

        # 1. Ingestion Quality Breakdown
        malformed_df = batch_df.filter(col("is_malformed") == 1)
        malformed_count = malformed_df.count()
        valid_df = batch_df.filter(col("is_malformed") == 0)
        valid_count = valid_df.count()

        print(f"Ingestion Status: Valid records = {valid_count:,} | Malformed records = {malformed_count:,}")

        if malformed_count > 0:
            print("\n[Alert] Malformed JSON records detected in this micro-batch:")
            malformed_df.select("kafka_offset", "raw_value").show(truncate=False)

        alert_docs = []
        metric_doc = None
        predicted_alerts = 0
        predicted_normal = 0
        actual_attacks = None
        actual_benign = None
        tp = fp = tn = fn = None

        rule_metrics = None
        if valid_count > 0:
            valid_df = add_payload_stats(valid_df, drop_payload=(ml_model is None))
            if ml_model is not None:
                # Hybrid detector: rules (metadata) OR ML (payload). Label never touched.
                scored = score_dataframe(ml_model, with_features_from_payload_array(valid_df), ml_threshold)
                valid_df = apply_hybrid(scored)
            valid_df.cache()

            # -----------------------------------------------------------------
            # 2. Heuristic Detector Predictions (Metadata Only - NO label used)
            # -----------------------------------------------------------------
            alerts_df = valid_df.filter(col("predicted_attack") == 1)
            predicted_alerts = alerts_df.count()
            predicted_normal = valid_df.filter(col("predicted_attack") == 0).count()

            burst_triggers = valid_df.filter(col("rule_burst_delta") == 1).count()
            ttl_triggers = valid_df.filter(col("rule_suspicious_ttl") == 1).count()
            len_triggers = valid_df.filter(col("rule_anomalous_len") == 1).count()
            invalid_meta_triggers = valid_df.filter(col("is_invalid_metadata") == 1).count()

            print("-" * 78)
            print("STREAMING RULE-BASED DETECTOR OUTPUT (Evaluated on packet metadata only):")
            print(f"  Predicted Threat Alerts: {predicted_alerts:,} ({predicted_alerts/valid_count*100:.1f}%)")
            print(f"  Predicted Normal:        {predicted_normal:,} ({predicted_normal/valid_count*100:.1f}%)")
            print(f"  Heuristic Rule Triggers: Burst Delta={burst_triggers:,} | Suspicious TTL={ttl_triggers:,} | Anomalous Len={len_triggers:,} | Invalid Meta={invalid_meta_triggers:,}")

            # -----------------------------------------------------------------
            # 3. Protocol-Level Aggregation
            # -----------------------------------------------------------------
            print("-" * 78)
            print("PROTOCOL-LEVEL PREDICTION SUMMARY:")
            protocol_summary = (
                valid_df
                .groupBy(when(col("protocol").isNull(), "unknown").otherwise(col("protocol")).alias("protocol"))
                .agg(
                    count("*").alias("total_records"),
                    spark_sum("predicted_attack").alias("predicted_alerts"),
                    spark_sum(when(col("predicted_attack") == 0, 1).otherwise(0)).alias("predicted_normal"),
                )
                .orderBy(col("total_records").desc())
            )
            protocol_summary.show(truncate=False)

            # -----------------------------------------------------------------
            # 4. Offline Evaluation Layer (Comparing Predictions vs Ground Truth)
            # -----------------------------------------------------------------
            eval_df = valid_df.filter(col("has_valid_ground_truth") == 1)
            eval_count = eval_df.count()

            if eval_count > 0:
                tp = eval_df.filter((col("predicted_attack") == 1) & (col("is_ground_truth_attack") == 1)).count()
                fp = eval_df.filter((col("predicted_attack") == 1) & (col("is_ground_truth_attack") == 0)).count()
                tn = eval_df.filter((col("predicted_attack") == 0) & (col("is_ground_truth_attack") == 0)).count()
                fn = eval_df.filter((col("predicted_attack") == 0) & (col("is_ground_truth_attack") == 1)).count()

                actual_attacks = tp + fn
                actual_benign = tn + fp
                if ml_model is not None:
                    rtp = eval_df.filter((col("rule_attack") == 1) & (col("is_ground_truth_attack") == 1)).count()
                    rfp = eval_df.filter((col("rule_attack") == 1) & (col("is_ground_truth_attack") == 0)).count()
                    rule_metrics = {"rule_tp": rtp, "rule_fp": rfp,
                                    "rule_tn": actual_benign - rfp, "rule_fn": actual_attacks - rtp}
                    print(f"  Rules-only baseline on same batch: TP={rtp} FP={rfp} TN={actual_benign - rfp} FN={actual_attacks - rtp}")

                prec_val = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
                rec_val = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
                f1_val = (2 * prec_val * rec_val / (prec_val + rec_val)) if (prec_val + rec_val) > 0 else 0.0
                fpr_val = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                print("-" * 78)
                print("OFFLINE GROUND-TRUTH EVALUATION (Batch Metrics):")
                print(f"  Ground Truth: Actual Attacks = {actual_attacks:,} | Actual Benign = {actual_benign:,}")
                print(f"  Confusion Matrix: TP={tp} | FP={fp} | TN={tn} | FN={fn}")
                print(f"  Metrics: Precision={prec_val:.4f} | Recall={rec_val:.4f} | F1={f1_val:.4f} | FPR={fpr_val:.4f}")

            # -----------------------------------------------------------------
            # 5. Persist Predicted Alerts via Partition Workers (Zero Driver Collect)
            # -----------------------------------------------------------------
            if predicted_alerts > 0:
                print(f"[MongoDB] Persisting {predicted_alerts:,} alert(s) across partitions to 'threat_alerts' (run_id: {run_id})...")
                alerts_df.foreachPartition(
                    lambda iter_rows: persist_alerts_partition(iter_rows, mongo_uri, mongo_db, batch_size=1000, run_id=run_id)
                )

            # -----------------------------------------------------------------
            # 5b. Cold tier: append every valid event to the Parquet Data Lake
            # -----------------------------------------------------------------
            if lake_dir:
                lake_rows = write_batch_to_lake(valid_df, lake_dir, run_id, batch_id)
                print(f"[Lake] Appended {lake_rows:,} events to Parquet lake '{lake_dir}' "
                      f"(run_id={run_id}, partitioned by protocol, snappy)")

            valid_df.unpersist()

        # Construct micro-batch summary document
        metric_doc = build_batch_metric_document(
            run_id=run_id,
            batch_id=batch_id,
            total_records=batch_count,
            valid_records=valid_count,
            malformed_records=malformed_count,
            alert_count=predicted_alerts,
            normal_count=predicted_normal,
            actual_attacks=actual_attacks,
            actual_benign=actual_benign,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            timestamp=batch_time
        )
        metric_doc["detector"] = "hybrid-rules+ml" if ml_model is not None else "rules"
        metric_doc["lake_enabled"] = bool(lake_dir)
        if rule_metrics:
            metric_doc.update(rule_metrics)

        # -----------------------------------------------------------------
        # 6. Execute MongoDB Idempotent Micro-Batch Summary Persistence
        # -----------------------------------------------------------------
        print("-" * 78)
        try:
            persist_batch_metric(client, mongo_db, metric_doc)
            print(f"[MongoDB] Successfully persisted to database '{mongo_db}':")
            print(f"  - Collection 'threat_alerts': {predicted_alerts:,} alert(s) persisted via partition workers")
            print(f"  - Collection 'batch_metrics': Batch summary (ID: {run_id}:{batch_id})")
        except Exception as exc:
            print(f"[Error] MongoDB persistence failed for batch {batch_id}: {exc}", file=sys.stderr)
            raise

        print("=" * 78 + "\n")

    return process_micro_batch


def main():
    parser = argparse.ArgumentParser(
        description="Spark Structured Streaming consumer with rule-based threat detection and MongoDB persistence."
    )
    parser.add_argument(
        "--bootstrap",
        default="localhost:9092",
        help="Kafka bootstrap servers (default: localhost:9092)",
    )
    parser.add_argument(
        "--topic",
        default="network-records",
        help="Kafka topic to consume (default: network-records)",
    )
    parser.add_argument(
        "--starting-offsets",
        default="latest",
        choices=["latest", "earliest"],
        help="Starting offsets for Kafka ingestion: latest (default) or earliest",
    )
    parser.add_argument(
        "--trigger-interval",
        default="5 seconds",
        help="Micro-batch processing time trigger interval (default: 5 seconds)",
    )
    parser.add_argument(
        "--checkpoint-dir",
        default="checkpoints/stage5_mongodb",
        help="Directory to store streaming checkpoints (default: checkpoints/stage5_mongodb)",
    )
    parser.add_argument(
        "--burst-delta",
        type=float,
        default=0.00005,
        help="Burst delta threshold in seconds (default: 0.00005)",
    )
    parser.add_argument(
        "--mongo-uri",
        default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
        help="MongoDB connection URI (default: env MONGODB_URI or mongodb://localhost:27017)",
    )
    parser.add_argument(
        "--mongo-db",
        default=os.getenv("MONGODB_DATABASE", "network_threat_analytics"),
        help="MongoDB database name (default: env MONGODB_DATABASE or network_threat_analytics)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional unique run identifier (default: generated UUID)",
    )
    parser.add_argument(
        "--max-offsets-per-trigger",
        type=int,
        default=50000,
        help="Maximum offsets per micro-batch trigger for Kafka ingestion (default: 50000)",
    )
    parser.add_argument(
        "--await-termination-timeout",
        type=int,
        default=None,
        help="Optional timeout in seconds for query.awaitTermination (default: None, wait indefinitely)",
    )
    parser.add_argument("--lake-dir", default="data/lake",
                        help="Parquet data-lake root (cold tier). Default: data/lake")
    parser.add_argument("--no-lake", action="store_true", help="Disable Parquet lake dual-write")
    parser.add_argument("--shuffle-partitions", type=int, default=8,
                        help="spark.sql.shuffle.partitions (default: 8)")
    parser.add_argument("--ml-model", default=None,
                        help="Path to a PipelineModel saved by ml_payload_detector.py (enables hybrid detector; "
                             "producer must use --include-payload)")
    parser.add_argument("--ml-threshold", type=float, default=0.5,
                        help="P(attack) threshold for the ML stage (default: 0.5)")
    args = parser.parse_args()

    if args.max_offsets_per_trigger <= 0:
        raise ValueError(
            f"--max-offsets-per-trigger must be a positive integer, got: {args.max_offsets_per_trigger}"
        )

    run_id = args.run_id or f"run-{uuid.uuid4().hex[:8]}"

    # Ensure checkpoint directory exists
    os.makedirs(args.checkpoint_dir, exist_ok=True)

    print("[SparkConsumer] Initializing SparkSession...")
    spark = (
        SparkSession.builder
        .appName("NetworkThreatAnalyticsDetectorAndSink")
        .config("spark.sql.shuffle.partitions", str(args.shuffle_partitions))
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    schema = create_schema()

    print(f"[SparkConsumer] Ingesting from Kafka topic '{args.topic}' at '{args.bootstrap}'...")
    print(f"[SparkConsumer] Starting offsets: '{args.starting_offsets}' | Trigger: '{args.trigger_interval}' | Max offsets/trigger: {args.max_offsets_per_trigger:,}")
    print(f"[SparkConsumer] Checkpoint path: '{args.checkpoint_dir}'")
    print(f"[SparkConsumer] MongoDB URI: '{args.mongo_uri}' | Database: '{args.mongo_db}'")
    print(f"[SparkConsumer] Run ID: '{run_id}'")

    raw_stream = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", args.bootstrap)
        .option("subscribe", args.topic)
        .option("startingOffsets", args.starting_offsets)
        .option("maxOffsetsPerTrigger", args.max_offsets_per_trigger)
        .option("failOnDataLoss", "false")
        .load()
    )

    # Cast Kafka binary payload to string, preserve Kafka metadata
    raw_str = raw_stream.select(
        col("topic"),
        col("partition").alias("kafka_partition"),
        col("offset").alias("kafka_offset"),
        col("timestamp").alias("event_timestamp"),
        col("value").cast("string").alias("raw_value")
    )

    # Parse JSON with corrupt record capture
    parsed = raw_str.select(
        col("topic"),
        col("kafka_partition"),
        col("kafka_offset"),
        col("event_timestamp"),
        col("raw_value"),
        from_json(col("raw_value"), schema, {"columnNameOfCorruptRecord": "_corrupt_record"}).alias("r")
    )

    # Unpack fields and flag malformed records
    unpacked = (
        parsed
        .withColumn(
            "is_malformed",
            when(col("r._corrupt_record").isNotNull() | col("r").isNull(), 1).otherwise(0)
        )
        .select(
            col("topic"),
            col("kafka_partition"),
            col("kafka_offset"),
            col("event_timestamp"),
            col("raw_value"),
            col("is_malformed"),
            col("r.ttl").alias("ttl"),
            col("r.total_len").alias("total_len"),
            col("r.protocol").alias("protocol"),
            col("r.t_delta").alias("t_delta"),
            col("r.label").alias("label"),  # Isolated ground truth for evaluation only
            col("r.payload").alias("payload")
        )
    )

    # -----------------------------------------------------------------
    # DETECTOR LAYER: ZERO DATA LEAKAGE (Uses ONLY ttl, total_len, protocol, t_delta)
    # -----------------------------------------------------------------
    # Rule 1: Burst delta heuristic (< 50 microseconds)
    rule_burst_delta = when(
        col("t_delta").isNotNull() & (col("t_delta") >= 0.0) & (col("t_delta") <= lit(args.burst_delta)),
        1
    ).otherwise(0)

    # Rule 2: Suspicious TTL heuristic (hop counts 61, 62 or < 32; invalid < 1 or > 255)
    rule_ttl_invalid = when(col("ttl").isNotNull() & ((col("ttl") < 1) | (col("ttl") > 255)), 1).otherwise(0)
    rule_ttl_suspicious = when(
        col("ttl").isNotNull() & ((col("ttl").isin(61, 62)) | ((col("ttl") > 0) & (col("ttl") < 32))),
        1
    ).otherwise(0)

    # Rule 3: Anomalous packet length (invalid < 28; header-only TCP 40,48,52,60; oversized > 1500)
    rule_len_invalid = when(col("total_len").isNotNull() & (col("total_len") < 28), 1).otherwise(0)
    rule_len_suspicious = when(
        col("total_len").isNotNull() & ((col("total_len") > 1500) | col("total_len").isin(40, 48, 52, 60)),
        1
    ).otherwise(0)

    # Data quality check
    is_invalid_metadata = when((rule_ttl_invalid == 1) | (rule_len_invalid == 1), 1).otherwise(0)

    # Rule 4: Combined Decision Policy (Alert if invalid metadata or burst delta + suspicious ttl/len)
    predicted_attack = when(
        (is_invalid_metadata == 1) |
        ((rule_burst_delta == 1) & (rule_ttl_suspicious == 1)) |
        ((rule_burst_delta == 1) & (rule_len_suspicious == 1)),
        1
    ).otherwise(0)

    # -----------------------------------------------------------------
    # EVALUATION METADATA LAYER (Ground Truth Isolation)
    # -----------------------------------------------------------------
    norm_label = upper(trim(col("label")))
    has_valid_ground_truth = when(
        (col("is_malformed") == 0) & col("label").isNotNull() & (norm_label != "") & (norm_label != "UNKNOWN"),
        1
    ).otherwise(0)
    is_ground_truth_attack = when(has_valid_ground_truth == 1, when(norm_label != "BENIGN", 1).otherwise(0)).otherwise(0)

    # Attach predictions and evaluation fields to stream
    enriched_stream = (
        unpacked
        .withColumn("rule_burst_delta", rule_burst_delta)
        .withColumn("rule_suspicious_ttl", rule_ttl_suspicious)
        .withColumn("rule_anomalous_len", rule_len_suspicious)
        .withColumn("is_invalid_metadata", is_invalid_metadata)
        .withColumn("predicted_attack", predicted_attack)
        .withColumn("has_valid_ground_truth", has_valid_ground_truth)
        .withColumn("is_ground_truth_attack", is_ground_truth_attack)
    )

    lake_dir = None if args.no_lake else args.lake_dir
    ml_model = load_model(args.ml_model) if args.ml_model else None
    print(f"[SparkConsumer] Lake dir: {lake_dir} | Shuffle partitions: {args.shuffle_partitions} | "
          f"ML model: {args.ml_model or 'disabled (rules only)'}")
    processor = create_micro_batch_processor(
        run_id, args.mongo_uri, args.mongo_db,
        lake_dir=lake_dir, ml_model=ml_model, ml_threshold=args.ml_threshold,
    )

    print("[SparkConsumer] Starting Structured Streaming query with foreachBatch & MongoDB Sink...")
    query = (
        enriched_stream.writeStream
        .trigger(processingTime=args.trigger_interval)
        .option("checkpointLocation", args.checkpoint_dir)
        .foreachBatch(processor)
        .start()
    )

    print(f"[SparkConsumer] Query started. Query ID: {query.id} | Run ID: {query.runId}")
    print("[SparkConsumer] Awaiting streaming batches. Press Ctrl+C to terminate cleanly.\n")

    try:
        if args.await_termination_timeout is not None:
            query.awaitTermination(timeout=args.await_termination_timeout)
        else:
            query.awaitTermination()
    except KeyboardInterrupt:
        print("\n[SparkConsumer] Termination requested by user. Stopping streaming query...")
    finally:
        query.stop()
        spark.stop()
        close_mongo_client()
        print("[SparkConsumer] Streaming query and SparkSession stopped cleanly.")


if __name__ == "__main__":
    main()
