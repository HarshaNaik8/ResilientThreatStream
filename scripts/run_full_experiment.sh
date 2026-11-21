#!/usr/bin/env bash
# Full-scale hybrid experiment: 1,410,255 records with payloads through 4-partition Kafka.
set -uo pipefail
cd "$(dirname "$0")/.."
RUN=full-hybrid-cicids2017; TOPIC=network-records-full-hybrid; CSV="../Payload_data_CICIDS2017.csv"; TOTAL=1410255
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 PATH="$PWD/.venv311/bin:$PATH" PYSPARK_PYTHON="$PWD/.venv311/bin/python"
export SPARK_HOME="$PWD/.venv311/lib/python3.11/site-packages/pyspark"
K=~/bigdata-tools/kafka_2.13-4.3.1/bin/kafka-topics.sh
$K --bootstrap-server localhost:9092 --create --topic $TOPIC --partitions 4 --replication-factor 1 --if-not-exists
date; python producer.py --input "$CSV" --topic $TOPIC --delay 0 --key-by flow --include-payload > /tmp/full_producer.log 2>&1
date; rm -rf checkpoints/$RUN data/lake_full
"$SPARK_HOME/bin/spark-submit" --driver-memory 3g --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.6 spark_consumer.py \
  --topic $TOPIC --starting-offsets earliest --checkpoint-dir checkpoints/$RUN --run-id $RUN --lake-dir data/lake_full \
  --ml-model models/payload_rf --max-offsets-per-trigger 20000 --trigger-interval "1 second" > /tmp/full_consumer.log 2>&1 &
CPID=$!
while kill -0 $CPID 2>/dev/null; do
  N=$(python - <<'P'
from pymongo import MongoClient
print(sum(d['total_records'] for d in MongoClient()['network_threat_analytics']['batch_metrics'].find({'run_id':'full-hybrid-cicids2017'},{'total_records':1})))
P
)
  [ "${N:-0}" -ge $TOTAL ] && { sleep 5; pkill -P $CPID; kill $CPID 2>/dev/null; break; }
  sleep 30
done
date
python -W ignore batch_analytics.py --lake-dir data/lake_full --run-id $RUN --window "1 minute" --skip-storage-benchmark > /tmp/full_batch.log 2>&1
python scripts/backup_manager.py run --checkpoint-dir checkpoints/$RUN > /tmp/full_backup.log 2>&1
echo FULL_DONE; date
