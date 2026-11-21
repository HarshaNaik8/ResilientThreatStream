#!/usr/bin/env bash
# Non-interactive end-to-end run into the sharded cluster (the guided version is docs/DEMO_GUIDE.md):
#   producer -> Kafka(4 partitions) -> Spark(rules + MLlib) -> sharded MongoDB + Parquet lake -> batch rollups -> snapshot
# Usage: scripts/run_lambda_demo.sh [csv] [records]
set -euo pipefail
source "$(dirname "$0")/demo_env.sh"
CSV="${1:-data/eval_sample_30k.csv}"; N="${2:-12000}"
[ -d models/payload_rf ] || python ml_payload_detector.py train --input data/stream_sample_10k.csv
"$SPARK_HOME/bin/spark-submit" --driver-memory 2g \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.6 spark_consumer.py \
  --topic "$KAFKA_TOPIC" --starting-offsets earliest --checkpoint-dir "$CHECKPOINT_DIR" --run-id demo-run \
  --ml-model models/payload_rf --max-offsets-per-trigger 10000 --trigger-interval "2 seconds" \
  --await-termination-timeout 120 > /dev/null 2>&1 &
sleep 25                                              # let Spark attach before data arrives
python producer.py --input "$CSV" --limit "$N" --topic "$KAFKA_TOPIC" --delay 0 --key-by flow --include-payload
wait
python batch_analytics.py --lake-dir data/lake --run-id demo-run --window "10 seconds"
python scripts/backup_manager.py run --lake-dir data/lake --checkpoint-dir "$CHECKPOINT_DIR" --backup-dir "$BACKUP_DIR"
