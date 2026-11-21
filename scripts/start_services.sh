#!/usr/bin/env bash
# Start everything the pipeline needs (all installed user-space under ~/bigdata-tools; Ubuntu 26.04 has no
# mongodb-org apt repo):  standalone mongod :27017 (legacy), sharded+replicated cluster (mongos :27019),
# Kafka KRaft :9092 and the 4-partition topic.
set -euo pipefail
T="$HOME/bigdata-tools"
HERE="$(cd "$(dirname "$0")" && pwd)"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
KAFKA="$T/kafka_2.13-4.3.1"
MONGOD=$(ls -d "$T"/mongodb-linux-*/bin/mongod | head -1)
up() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

up 27017 || "$MONGOD" --dbpath "$T/mongo-data" --logpath "$T/mongo-logs/mongod.log" --bind_ip 127.0.0.1 --fork >/dev/null
"$HERE/sharded_cluster.sh" start
if ! up 9092; then
  setsid "$KAFKA/bin/kafka-server-start.sh" "$KAFKA/config/server.properties" > "$KAFKA/logs/kafkaServer.out" 2>&1 &
fi
for _ in $(seq 1 30); do up 9092 && break; sleep 1; done
"$KAFKA/bin/kafka-topics.sh" --bootstrap-server localhost:9092 --create --topic network-records-multi \
    --partitions 4 --replication-factor 1 --if-not-exists
"$KAFKA/bin/kafka-topics.sh" --bootstrap-server localhost:9092 --create --topic network-records-demo \
    --partitions 4 --replication-factor 1 --if-not-exists
"$HERE/sharded_cluster.sh" status
