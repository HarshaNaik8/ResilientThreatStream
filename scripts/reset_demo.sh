#!/usr/bin/env bash
# Clean slate for a repeatable demo. Touches ONLY demo artefacts: topic network-records-demo, database bda_demo,
# checkpoints/demo-run, lake run_id=demo-run and backups/demo.  Your other data is never modified.
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}" MONGODB_DATABASE=bda_demo
K="$HOME/bigdata-tools/kafka_2.13-4.3.1/bin/kafka-topics.sh"
"$K" --bootstrap-server localhost:9092 --delete --topic network-records-demo 2>/dev/null || true
sleep 3
"$K" --bootstrap-server localhost:9092 --create --topic network-records-demo --partitions 4 --replication-factor 1 --if-not-exists
.venv311/bin/python -c "
from pymongo import MongoClient; from scripts import shard_setup as ss
MongoClient('127.0.0.1', ss.MONGOS_PORT).drop_database('bda_demo'); ss.init_cluster()"
rm -rf checkpoints/demo-run "data/lake/events/run_id=demo-run" backups/demo
echo "demo reset done"
