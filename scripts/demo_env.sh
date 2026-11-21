# Source this in EVERY terminal you use for the demo:   source scripts/demo_env.sh
# Points the whole pipeline (producer, Spark, dashboard, backup tools) at the sharded cluster and demo-only names.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$ROOT/.venv311/bin:$PATH"
export PYSPARK_PYTHON="$ROOT/.venv311/bin/python"
export SPARK_HOME="$ROOT/.venv311/lib/python3.11/site-packages/pyspark"   # explicit: find-spark-home breaks on paths with spaces
export MONGODB_URI="mongodb://127.0.0.1:27019"        # mongos router of the sharded + replicated cluster
export MONGODB_DATABASE="bda_demo"                    # demo-only database (your real data is never touched)
export KAFKA_TOPIC="network-records-demo"
export CHECKPOINT_DIR="checkpoints/demo-run"
export BACKUP_DIR="backups/demo"
cd "$ROOT"
echo "demo environment ready: DB=$MONGODB_DATABASE via $MONGODB_URI | topic=$KAFKA_TOPIC"
