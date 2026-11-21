#!/usr/bin/env bash
# One-time setup on Ubuntu 22.04+ (tested on 26.04): Java 17, Python 3.11 venv, Kafka 4.3.1, MongoDB 8.0.4 + tools.
# Everything except apt packages is installed user-space under ~/bigdata-tools (no systemd needed).
# Usage: scripts/install_services.sh        (asks for sudo only for the apt step)
set -euo pipefail
cd "$(dirname "$0")/.."
T="$HOME/bigdata-tools"; mkdir -p "$T"; cd "$T"

sudo apt-get update && sudo apt-get install -y openjdk-17-jdk-headless curl wget net-tools

[ -d kafka_2.13-4.3.1 ] || { wget -q https://archive.apache.org/dist/kafka/4.3.1/kafka_2.13-4.3.1.tgz && tar -xzf kafka_2.13-4.3.1.tgz && rm kafka_2.13-4.3.1.tgz; }
sed -i "s|^log.dirs=.*|log.dirs=$T/kraft-logs|" kafka_2.13-4.3.1/config/server.properties
if [ ! -f "$T/kraft-logs/meta.properties" ]; then
  export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
  kafka_2.13-4.3.1/bin/kafka-storage.sh format --standalone -t "$(kafka_2.13-4.3.1/bin/kafka-storage.sh random-uuid | tail -1)" -c kafka_2.13-4.3.1/config/server.properties
fi

ls -d mongodb-linux-*/ >/dev/null 2>&1 || { wget -q -O m.tgz https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2404-8.0.4.tgz && tar -xzf m.tgz && rm m.tgz; }
ls -d mongodb-database-tools-*/ >/dev/null 2>&1 || { wget -q -O t.tgz https://fastdl.mongodb.org/tools/db/mongodb-database-tools-ubuntu2404-x86_64-100.10.0.tgz && tar -xzf t.tgz && rm t.tgz; }
mkdir -p mongo-data mongo-logs

cd - >/dev/null
PY=$(command -v python3.11 || true); [ -n "$PY" ] || { echo "Python 3.11 not found (PySpark 3.5.6 needs <= 3.12). Install it, e.g. 'uv python install 3.11'."; exit 1; }
[ -d .venv311 ] || "$PY" -m venv .venv311
.venv311/bin/pip install -q --upgrade pip
.venv311/bin/pip install -q -r requirements-pipeline.txt pyarrow numpy
echo "Done. Next: scripts/start_services.sh"
