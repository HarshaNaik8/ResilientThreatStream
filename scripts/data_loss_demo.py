#!/usr/bin/env python3
"""
data_loss_demo.py — simulate real data-loss events and show how each layer recovers.

  A  NODE CRASH       kill a shard's primary mongod        -> REPLICATION: automatic election, no data lost
  B  DATABASE DROPPED delete the whole database ("rm -rf")  -> BACKUP: verified snapshot restore (RPO/RTO measured)
  C  BACKUP ALSO LOST delete DB *and* all snapshots         -> LAMBDA MASTER DATASET: rebuild from the Parquet lake

Run after the pipeline has loaded data:  python -m scripts.data_loss_demo [--pause] [--only A|B|C]
--pause waits for Enter between steps (for a live demo).
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

from pymongo import MongoClient

from scripts import backup_manager as bm
from scripts import lake_recovery
from scripts import shard_setup as ss

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAUSE = False


def step(msg):
    print(f"\n\033[1;36m>>> {msg}\033[0m")
    if PAUSE:
        input("    [Enter to run] ")


def counts(uri, db):
    c = MongoClient(uri)
    try:
        return {n: c[db][n].count_documents({}) for n in c[db].list_collection_names()
                if n in ("threat_alerts", "batch_metrics", "historical_threat_rollups")}
    finally:
        c.close()


def pid_of_port(port):
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            cmd = open(f"/proc/{pid}/cmdline").read().split("\0")
        except OSError:
            continue
        if cmd and cmd[0].endswith("mongod") and "--port" in cmd and cmd[cmd.index("--port") + 1] == str(port):
            return int(pid)
    return None


def scenario_a(uri, db):
    print("\n" + "=" * 78 + "\nSCENARIO A - a database server crashes (hardware failure)\n" + "=" * 78)
    primary = None
    for port, _kind in ss.REPLSETS["shard1"]["members"]:           # whichever node is shard1's primary right now
        n = MongoClient(ss.HOST, port, directConnection=True, serverSelectionTimeoutMS=2000)
        try:
            if n.admin.command("hello").get("isWritablePrimary"):
                primary = port
        except Exception:
            pass
        n.close()
        if primary:
            break
    before = counts(uri, db)
    print(f"documents before crash: {before}")
    step(f"kill -9 the PRIMARY of its shard (mongod on port {primary})")
    os.kill(pid_of_port(primary), 9)
    t0 = time.time()
    client = MongoClient(uri, serverSelectionTimeoutMS=20000)
    coll = client[db]["threat_alerts"]
    stalls, ok = 0.0, 0
    for i in range(60):                                   # writes hit both shards (hashed _id)
        t = time.time()
        try:
            coll.replace_one({"_id": f"crash-probe-{i}"}, {"_id": f"crash-probe-{i}", "run_id": "probe"}, upsert=True)
            ok += 1
        except Exception:
            time.sleep(0.5)
        stalls = max(stalls, time.time() - t)
    coll.delete_many({"_id": {"$regex": "^crash-probe"}})
    after = counts(uri, db)
    print(f"cluster kept serving: {ok}/60 probe writes accepted, longest stall {stalls:.1f}s (election)")
    print(f"documents after crash:  {after}  -> {'NO DATA LOST' if after == before else 'MISMATCH!'}")
    step(f"restart the dead node (it re-syncs from the new primary)")
    subprocess.run([os.path.join(HERE, "sharded_cluster.sh"), "start"], check=True, capture_output=True)
    subprocess.run([os.path.join(HERE, "sharded_cluster.sh"), "status"], check=True)
    client.close()
    return after == before


def scenario_b(uri, db, backup_dir, ckpt, lake):
    print("\n" + "=" * 78 + "\nSCENARIO B - the whole database is deleted (operator error / corruption)\n" + "=" * 78)
    step("take a verified snapshot (mongodump.gz + checkpoints + Parquet lake)")
    snap = bm.create_backup(backup_dir, uri, db, ckpt, lake_dir=lake, read_preference="primary")
    print("snapshot:", snap, "| verify:", "OK" if bm.verify_snapshot(snap)["ok"] else "FAILED")
    before = counts(uri, db)
    print("documents in snapshot:", before)
    step("DISASTER: drop the database through mongos")
    c = MongoClient(uri)
    c.drop_database(db)
    print("documents now:", counts(uri, db), "<- everything is gone")
    step("RECOVER: re-create the sharded layout, then mongorestore the snapshot")
    t = time.time()
    ss.init_cluster()
    bm.restore_snapshot(snap, uri, db)
    secs = time.time() - t
    after = counts(uri, db)
    print(f"documents restored: {after}  in {secs:.1f}s (RTO)  -> {'IDENTICAL' if after == before else 'MISMATCH!'}")
    c.close()
    return after == before


def scenario_c(uri, db, backup_dir, lake, run_id):
    print("\n" + "=" * 78 + "\nSCENARIO C - database AND every backup are lost (worst case)\n" + "=" * 78)
    c = MongoClient(uri)
    before_ids = set(d["_id"] for d in c[db]["threat_alerts"].find({"run_id": run_id}, {"_id": 1}))
    print(f"alerts of run '{run_id}' before disaster: {len(before_ids):,}")
    step("DISASTER: drop the database and delete all snapshots")
    c.drop_database(db)
    shutil.rmtree(backup_dir, ignore_errors=True)
    print("documents now:", counts(uri, db), "| snapshots:", len(bm.list_snapshots(backup_dir)))
    step("RECOVER: rebuild alerts from the immutable Parquet lake (the master dataset)")
    t = time.time()
    ss.init_cluster()
    n = lake_recovery.recover_alerts(lake, uri, db, run_id)
    m = lake_recovery.recover_batch_metrics(lake, uri, db, run_id)
    print(f"re-aggregated {m} batch-metric documents (evaluation counts) from the same lake rows")
    after_ids = set(d["_id"] for d in c[db]["threat_alerts"].find({"run_id": run_id}, {"_id": 1}))
    print(f"re-created {n:,} alerts in {time.time() - t:.1f}s; "
          f"same _ids as before: {after_ids == before_ids}  ({len(after_ids):,} of {len(before_ids):,})")
    print("batch rollups can be recomputed with:  python batch_analytics.py --lake-dir data/lake --run-id", run_id)
    c.close()
    return after_ids == before_ids


def main():
    global PAUSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", f"mongodb://{ss.HOST}:{ss.MONGOS_PORT}"))
    ap.add_argument("--mongo-db", default=ss.DB_NAME)
    ap.add_argument("--run-id", default="demo-run")
    ap.add_argument("--lake-dir", default="data/lake")
    ap.add_argument("--backup-dir", default="backups/demo")
    ap.add_argument("--checkpoint-dir", default="checkpoints/demo-run")
    ap.add_argument("--only", choices=["A", "B", "C"])
    ap.add_argument("--pause", action="store_true")
    a = ap.parse_args()
    PAUSE = a.pause
    os.chdir(ROOT)
    results = {}
    if a.only in (None, "A"):
        results["A node crash -> replication"] = scenario_a(a.mongo_uri, a.mongo_db)
    if a.only in (None, "B"):
        results["B database dropped -> snapshot restore"] = scenario_b(
            a.mongo_uri, a.mongo_db, a.backup_dir, a.checkpoint_dir, a.lake_dir)
    if a.only in (None, "C"):
        results["C backups lost too -> lake rebuild"] = scenario_c(
            a.mongo_uri, a.mongo_db, a.backup_dir, a.lake_dir, a.run_id)
    print("\n" + "=" * 78)
    for k, v in results.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
