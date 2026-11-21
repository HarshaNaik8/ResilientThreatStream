#!/usr/bin/env python3
"""
dr_drill.py — Disaster-recovery drill: backup -> verify -> restore into a scratch database -> compare.

Measures the quantities a DR plan is judged on:
  RPO  = age of newest snapshot at the moment of failure (bounded by backup schedule)
  RTO  = wall-clock time to restore (reported here: backup, verify, restore seconds)
  Integrity = per-collection document counts identical after restore.
Usage: python -m scripts.dr_drill [--mongo-uri ...] [--lake-dir data/lake]
"""
import argparse
import json
import os
import shutil
import tempfile
import time

from pymongo import MongoClient

from scripts import backup_manager as bm


def run_drill(mongo_uri, db_name, checkpoint_dir, lake_dir=None):
    work = tempfile.mkdtemp(prefix="dr_drill_")
    restored_db = f"{db_name}_drill_restore"
    client = MongoClient(mongo_uri)
    res = {"database": db_name}
    try:
        t = time.time()
        snap = bm.create_backup(os.path.join(work, "bk"), mongo_uri, db_name, checkpoint_dir, lake_dir=lake_dir,
                              read_preference="primary")   # drill compares exact counts: avoid replication lag
        res["backup_seconds"] = round(time.time() - t, 2)
        res["snapshot_bytes"] = json.load(open(os.path.join(snap, "manifest.json")))["total_bytes"]
        t = time.time()
        res["verify_ok"] = bm.verify_snapshot(snap)["ok"]
        res["verify_seconds"] = round(time.time() - t, 2)
        client.drop_database(restored_db)
        t = time.time()
        bm.restore_snapshot(snap, mongo_uri, restored_db, restore_checkpoints_to=os.path.join(work, "ckpt"),
                            restore_lake_to=os.path.join(work, "lake") if lake_dir else None)
        res["restore_seconds"] = round(time.time() - t, 2)
        src = {n: client[db_name][n].estimated_document_count() for n in client[db_name].list_collection_names()}
        dst = {n: client[restored_db][n].estimated_document_count() for n in client[restored_db].list_collection_names()}
        res["collections"] = {n: {"source": src[n], "restored": dst.get(n, 0), "match": src[n] == dst.get(n, 0)} for n in src}
        res["integrity_ok"] = all(v["match"] for v in res["collections"].values())
        res["rto_seconds"] = round(res["verify_seconds"] + res["restore_seconds"], 2)
    finally:
        client.drop_database(restored_db)
        client.close()
        shutil.rmtree(work, ignore_errors=True)
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", default=os.getenv("MONGODB_DATABASE", "network_threat_analytics"))
    ap.add_argument("--checkpoint-dir", default="checkpoints/stage8_lambda")
    ap.add_argument("--lake-dir", default=None)
    a = ap.parse_args()
    print(json.dumps(run_drill(a.mongo_uri, a.mongo_db, a.checkpoint_dir, a.lake_dir), indent=2))
