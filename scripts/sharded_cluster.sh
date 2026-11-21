#!/usr/bin/env bash
# Local sharded + replicated MongoDB cluster (Lesson Plan U1.2: sharding, replication, and both combined).
#
#   config server RS  cfg      : 27100                      (1 node)
#   shard1 RS         shard1   : 27111 27112 27113  (3 data-bearing replicas)
#   shard2 RS         shard2   : 27121 27122 27123  (3 data-bearing replicas)
#   router            mongos   : 27019   <- point MONGODB_URI here
#
# Each shard is a 3-member replica set (Primary + 2 Secondaries): any single node can die with no data loss and
# the remaining two elect a primary.  (An arbiter variant was tried and rejected: with a data node down it stalls reads.)  The standalone mongod on :27017 is NOT touched.
#
# Usage: scripts/sharded_cluster.sh start|stop|status|clean
set -euo pipefail
T="$HOME/bigdata-tools"
BIN=$(ls -d "$T"/mongodb-linux-*/bin | head -1)
BASE="$T/shard-cluster"
CACHE_GB=0.25

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }   # pgrep -f is unreliable (matches wrappers)

node() {  # node <name> <port> <replset> <role: shardsvr|configsvr>
  local name=$1 port=$2 rs=$3 role=$4
  mkdir -p "$BASE/$name/db"
  if ! listening "$port"; then
    "$BIN/mongod" --$role --replSet "$rs" --port "$port" --bind_ip 127.0.0.1 --dbpath "$BASE/$name/db" \
      --logpath "$BASE/$name/mongod.log" --wiredTigerCacheSizeGB "$CACHE_GB" --fork >/dev/null
  fi
}

start() {
  node cfg 27100 cfg configsvr
  for p in 27111 27112 27113; do node "s1_$p" "$p" shard1 shardsvr; done
  for p in 27121 27122 27123; do node "s2_$p" "$p" shard2 shardsvr; done
  sleep 3
  "$(dirname "$0")/../.venv311/bin/python" "$(dirname "$0")/shard_setup.py" init-replsets
  if ! listening 27019; then
    "$BIN/mongos" --configdb cfg/127.0.0.1:27100 --port 27019 --bind_ip 127.0.0.1 \
      --logpath "$BASE/mongos.log" --fork >/dev/null
  fi
  sleep 3
  "$(dirname "$0")/../.venv311/bin/python" "$(dirname "$0")/shard_setup.py" init-cluster
}

stop() {
  for pid in $(ps -eo pid,comm | awk '$2=="mongos"||$2=="mongod"{print $1}'); do
    if tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | grep -q -e "$BASE" -e "--port 27019"; then kill "$pid"; fi
  done
  echo stopped
}
status() { "$(dirname "$0")/../.venv311/bin/python" "$(dirname "$0")/shard_setup.py" status; }

case "${1:-}" in
  start) start ;; stop) stop ;; status) status ;;
  clean) stop; sleep 2; rm -rf "$BASE"; echo "removed $BASE" ;;
  *) echo "usage: $0 start|stop|status|clean"; exit 1 ;;
esac
