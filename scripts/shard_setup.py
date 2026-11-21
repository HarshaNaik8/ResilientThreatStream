#!/usr/bin/env python3
"""
shard_setup.py — configure and inspect the local sharded MongoDB cluster.

Shard-key design (see docs/SHARDING_AND_BACKUP_ARCHITECTURE.md):
  threat_alerts              {_id: "hashed"}                 write-heavy, idempotent upserts by _id are
                                                             single-shard targeted; hashing spreads evenly
  historical_threat_rollups  {run_id: 1, rollup_type: 1}     read by run/type -> targeted range queries
  batch_metrics              unsharded (tiny; lives on primary shard)

Commands: init-replsets | init-cluster | status | distribution
"""
import argparse
import os
import sys
import time
from typing import Any, Dict, List

from pymongo import MongoClient
from pymongo.errors import CollectionInvalid, OperationFailure

HOST = "127.0.0.1"
MONGOS_PORT = 27019
DB_NAME = os.getenv("MONGODB_DATABASE", "network_threat_analytics")

REPLSETS = {
    "cfg": {"configsvr": True, "members": [(27100, "data")]},
    "shard1": {"members": [(27111, "data"), (27112, "data"), (27113, "data")]},
    "shard2": {"members": [(27121, "data"), (27122, "data"), (27123, "data")]},
}

SHARDED_COLLECTIONS = [
    ("threat_alerts", {"_id": "hashed"}),
    ("historical_threat_rollups", {"run_id": 1, "rollup_type": 1}),
]


def replset_config(name: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Pure builder (unit-tested) for replSetInitiate."""
    members = []
    for i, (port, kind) in enumerate(spec["members"]):
        m = {"_id": i, "host": f"{HOST}:{port}"}
        if kind == "arbiter":
            m["arbiterOnly"] = True
        members.append(m)
    cfg = {"_id": name, "members": members}
    if spec.get("configsvr"):
        cfg["configsvr"] = True
    return cfg


def init_replsets() -> None:
    for name, spec in REPLSETS.items():
        port = spec["members"][0][0]
        c = MongoClient(HOST, port, directConnection=True, serverSelectionTimeoutMS=8000)
        try:
            try:
                c.admin.command("replSetInitiate", replset_config(name, spec))
                print(f"[init] replica set {name} initiated")
            except OperationFailure as exc:
                if exc.code in (23, 48) or "already initialized" in str(exc):
                    print(f"[init] replica set {name} already initialised")
                else:
                    raise
            for _ in range(60):                       # wait until *some* member is primary
                if c.admin.command("hello").get("primary"):
                    break
                time.sleep(1)
        finally:
            c.close()


def init_cluster() -> None:
    c = MongoClient(HOST, MONGOS_PORT, serverSelectionTimeoutMS=15000)
    admin = c.admin
    # Fast default write concern (acknowledged by the primary); the pipeline's alerts are idempotent upserts and the
    # Parquet lake + snapshots are the durability backstop.  Each shard still holds 3 replicas.
    admin.command("setDefaultRWConcern", defaultWriteConcern={"w": 1}, defaultReadConcern={"level": "local"})
    existing = {s["_id"] for s in admin.command("listShards")["shards"]}
    for name in ("shard1", "shard2"):
        if name not in existing:
            seed = ",".join(f"{HOST}:{p}" for p, k in REPLSETS[name]["members"] if k == "data")
            admin.command("addShard", f"{name}/{seed}")
            print(f"[init] added shard {name}")
    try:
        admin.command("enableSharding", DB_NAME)
    except OperationFailure:
        pass
    for coll, key in SHARDED_COLLECTIONS:
        ns = f"{DB_NAME}.{coll}"
        try:
            c[DB_NAME].create_collection(coll)
        except (CollectionInvalid, OperationFailure):
            pass                                  # already exists: start is idempotent
        try:
            admin.command("shardCollection", ns, key=key)
            print(f"[init] sharded {ns} on {key}")
        except OperationFailure as exc:
            if "already sharded" in str(exc):
                print(f"[init] {ns} already sharded")
            else:
                raise
    c.close()


def distribution(client: MongoClient) -> Dict[str, Dict[str, int]]:
    """Per-collection documents per shard (from collStats)."""
    out: Dict[str, Dict[str, int]] = {}
    db = client[DB_NAME]
    for coll, _key in SHARDED_COLLECTIONS:
        try:
            st = db.command("collStats", coll)
            out[coll] = {s: v.get("count", 0) for s, v in st.get("shards", {}).items()}
        except OperationFailure:
            out[coll] = {}
    return out


def balance_ratio(counts: Dict[str, int]) -> float:
    """max/min documents per shard (1.0 = perfect); inf if a shard is empty."""
    vals = list(counts.values())
    if len(vals) < 2:
        return 1.0
    return float("inf") if min(vals) == 0 else round(max(vals) / min(vals), 3)


def status() -> None:
    c = MongoClient(HOST, MONGOS_PORT, serverSelectionTimeoutMS=4000)
    try:
        shards = c.admin.command("listShards")["shards"]
    except Exception as exc:
        print(f"mongos on :{MONGOS_PORT} unreachable: {exc}")
        sys.exit(1)
    print("Shards:")
    for s in shards:
        print(f"  {s['_id']}: {s['host']}")
    for name, spec in REPLSETS.items():
        for port, kind in spec["members"]:
            try:
                n = MongoClient(HOST, port, directConnection=True, serverSelectionTimeoutMS=1500)
                h = n.admin.command("hello")
                role = "PRIMARY" if h.get("isWritablePrimary") else ("ARBITER" if h.get("arbiterOnly") else "SECONDARY")
                print(f"  {name} :{port} {role}")
                n.close()
            except Exception:
                print(f"  {name} :{port} DOWN")
    for coll, d in distribution(c).items():
        print(f"{coll}: {d}  balance(max/min)={balance_ratio(d)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["init-replsets", "init-cluster", "status"])
    a = ap.parse_args()
    {"init-replsets": init_replsets, "init-cluster": init_cluster, "status": status}[a.command]()
