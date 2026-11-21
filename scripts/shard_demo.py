#!/usr/bin/env python3
"""
shard_demo.py — (run: python -m scripts.shard_demo) evidence for the sharding/replication design (read-only on the source, writes to the cluster).

1. Copies up to --limit alert documents from the standalone MongoDB into the sharded cluster using the
   pipeline's own idempotent upsert semantics (ReplaceOne by _id) through mongos.
2. Reports documents per shard (hash-key balance).
3. Shows query routing with explain(): _id lookup (targeted, 1 shard) vs run_id filter (scatter-gather).
4. --failover: steps down shard1's primary and proves reads + writes continue (replication + election).
"""
import argparse
import json
import time

from pymongo import MongoClient, ReplaceOne

from scripts.shard_setup import DB_NAME, HOST, MONGOS_PORT, balance_ratio, distribution


def shards_touched(explain: dict) -> int:
    qp = explain.get("queryPlanner", {}).get("winningPlan", {})
    return len(qp.get("shards", [])) if "shards" in qp else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="mongodb://localhost:27017")
    ap.add_argument("--limit", type=int, default=200_000)
    ap.add_argument("--failover", action="store_true")
    a = ap.parse_args()

    src = MongoClient(a.source)[DB_NAME]["threat_alerts"]
    mongos = MongoClient(HOST, MONGOS_PORT)
    dst = mongos[DB_NAME]["threat_alerts"]

    t0, n, ops = time.time(), 0, []
    for doc in src.find().limit(a.limit):
        ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))
        if len(ops) == 2000:
            dst.bulk_write(ops, ordered=False); n += len(ops); ops = []
    if ops:
        dst.bulk_write(ops, ordered=False); n += len(ops)
    secs = time.time() - t0
    print(f"[load] upserted {n:,} alerts via mongos in {secs:.1f}s ({n/secs:,.0f} docs/s)")

    dist = distribution(mongos)["threat_alerts"]
    print(f"[distribution] {dist}  balance(max/min)={balance_ratio(dist)}")

    sample = dst.find_one()
    e1 = mongos[DB_NAME].command("explain", {"find": "threat_alerts", "filter": {"_id": sample["_id"]}}, verbosity="queryPlanner")
    e2 = mongos[DB_NAME].command("explain", {"find": "threat_alerts", "filter": {"run_id": sample.get("run_id")}}, verbosity="queryPlanner")
    print(f"[routing] _id equality -> shards contacted: {shards_touched(e1)} (targeted)")
    print(f"[routing] run_id filter -> shards contacted: {shards_touched(e2)} (scatter-gather)")

    if a.failover:
        p = MongoClient(HOST, 27111, directConnection=True)
        try:
            p.admin.command("replSetStepDown", 20, force=True)
        except Exception:
            pass                                   # connection drops on stepdown - expected
        t1 = time.time()
        worst, failures, i = 0.0, 0, 0
        while time.time() - t1 < 25:               # probe writes hit both shards (hashed _id)
            i += 1
            t = time.time()
            try:
                dst.replace_one({"_id": f"failover-probe-{i}"}, {"_id": f"failover-probe-{i}", "run_id": "probe"}, upsert=True)
            except Exception:
                failures += 1
                time.sleep(0.25)
            worst = max(worst, time.time() - t)
        print(f"[failover] shard1 primary stepped down; {i} probe writes in 25s, {failures} transient errors, "
              f"worst single-write stall {worst:.1f}s; docs readable: {dst.count_documents({}):,}")
        dst.delete_many({"_id": {"$regex": "^failover-probe"}})


if __name__ == "__main__":
    main()
