#!/usr/bin/env python3
"""
backup_manager.py — Disaster-recovery automation (Bottleneck E).

Each run creates one timestamped snapshot directory::

    backups/20261120T230000Z/
        mongo.archive.gz     gzip `mongodump --archive` of the whole database
                             (pure-python mongo.jsonl.gz fallback if mongodump is absent)
        checkpoints.tar.gz   Spark Structured-Streaming checkpoint directory
        lake.tar.gz          Parquet data lake (optional, --lake-dir)
        manifest.json        sizes, SHA-256 digests, per-collection doc counts

Commands:  backup | verify | rotate | restore | status | run (= backup+verify+rotate)

* Retention: snapshots older than --retention-days (default 7) are deleted;
  the newest snapshot is always kept.
* Verification: SHA-256 match, gzip/tar integrity, and `mongorestore --dryRun`
  (or JSONL decode) of the archive.  A snapshot that fails verification is
  flagged in its manifest (`"verified": false`).
* Cron example (daily 02:00)::
      0 2 * * * cd /path/to/project && .venv311/bin/python scripts/backup_manager.py run

Note: the Parquet data lake is the master dataset; if MongoDB *and* every snapshot are lost it is
rebuilt from the lake with scripts/lake_recovery.py (see scripts/data_loss_demo.py, scenario C).
"""

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

TS_FORMAT = "%Y%m%dT%H%M%SZ"
MANIFEST = "manifest.json"


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def find_tool(name: str) -> Optional[str]:
    """Locate mongodump/mongorestore: $MONGO_TOOLS_DIR, PATH, ~/bigdata-tools/*."""
    env_dir = os.getenv("MONGO_TOOLS_DIR")
    if env_dir and os.path.isfile(os.path.join(env_dir, name)):
        return os.path.join(env_dir, name)
    found = shutil.which(name)
    if found:
        return found
    base = os.path.expanduser("~/bigdata-tools")
    if os.path.isdir(base):
        for entry in sorted(os.listdir(base)):
            cand = os.path.join(base, entry, "bin", name)
            if os.path.isfile(cand):
                return cand
    return None


def parse_snapshot_time(name: str) -> Optional[datetime]:
    try:
        return datetime.strptime(name, TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def list_snapshots(backup_dir: str) -> List[str]:
    """Snapshot directory names, oldest -> newest."""
    if not os.path.isdir(backup_dir):
        return []
    names = [n for n in os.listdir(backup_dir)
             if os.path.isdir(os.path.join(backup_dir, n)) and parse_snapshot_time(n)]
    return sorted(names)


# ----------------------------------------------------------------------------
# backup pieces
# ----------------------------------------------------------------------------
def dump_mongo(mongo_uri: str, db_name: str, out_dir: str, use_mongodump: bool = True,
               read_preference: str = "secondaryPreferred") -> Dict[str, Any]:
    """Dump the database. Returns {file, method, collections:{name:count}}."""
    from pymongo import MongoClient
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000, readPreference=read_preference)
    try:
        db = client[db_name]
        counts = {n: db[n].estimated_document_count() for n in db.list_collection_names()}
        tool = find_tool("mongodump") if use_mongodump else None
        if tool:
            path = os.path.join(out_dir, "mongo.archive.gz")
            subprocess.run([tool, f"--uri={mongo_uri}", f"--db={db_name}",
                            f"--archive={path}", "--gzip", "--quiet",
                            f"--readPreference={read_preference}"],      # default: dump from a secondary, no load on the primary
                           check=True, capture_output=True, text=True)
            return {"file": os.path.basename(path), "method": "mongodump", "collections": counts}
        from bson import json_util
        path = os.path.join(out_dir, "mongo.jsonl.gz")
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            for coll in counts:
                for doc in db[coll].find():
                    fh.write(json.dumps({"_collection": coll, "doc": json.loads(json_util.dumps(doc))}) + "\n")
        return {"file": os.path.basename(path), "method": "python-jsonl", "collections": counts}
    finally:
        client.close()


def archive_checkpoints(checkpoint_dir: str, out_dir: str) -> Optional[Dict[str, Any]]:
    if not os.path.isdir(checkpoint_dir):
        return None
    path = os.path.join(out_dir, "checkpoints.tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        tar.add(checkpoint_dir, arcname=os.path.basename(os.path.normpath(checkpoint_dir)))
    return {"file": os.path.basename(path), "source": checkpoint_dir}


def archive_lake(lake_dir: Optional[str], out_dir: str) -> Optional[Dict[str, Any]]:
    """Tar+gzip the Parquet lake (already columnar/compressed, so this is mainly packaging + integrity)."""
    if not lake_dir or not os.path.isdir(lake_dir):
        return None
    path = os.path.join(out_dir, "lake.tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        tar.add(lake_dir, arcname=os.path.basename(os.path.normpath(lake_dir)))
    return {"file": os.path.basename(path), "source": lake_dir}


def create_backup(backup_dir: str, mongo_uri: str, db_name: str, checkpoint_dir: str,
                  use_mongodump: bool = True, now: Optional[datetime] = None,
                  lake_dir: Optional[str] = None, read_preference: str = "secondaryPreferred") -> str:
    now = now or datetime.now(timezone.utc)
    snap = os.path.join(backup_dir, now.strftime(TS_FORMAT))
    os.makedirs(snap, exist_ok=False)
    manifest: Dict[str, Any] = {
        "created_at": now.isoformat(), "database": db_name, "verified": None, "files": {},
    }
    try:
        mongo = dump_mongo(mongo_uri, db_name, snap, use_mongodump, read_preference)
        manifest["mongo"] = {k: v for k, v in mongo.items() if k != "file"}
        files = [mongo["file"]]
        ckpt = archive_checkpoints(checkpoint_dir, snap)
        manifest["checkpoints_source"] = checkpoint_dir if ckpt else None
        if ckpt:
            files.append(ckpt["file"])
        lake = archive_lake(lake_dir, snap)
        manifest["lake_source"] = lake_dir if lake else None
        if lake:
            files.append(lake["file"])
        for f in files:
            p = os.path.join(snap, f)
            manifest["files"][f] = {"bytes": os.path.getsize(p), "sha256": sha256_file(p)}
    except Exception:
        shutil.rmtree(snap, ignore_errors=True)      # never leave a half-written snapshot
        raise
    manifest["total_bytes"] = sum(v["bytes"] for v in manifest["files"].values())
    with open(os.path.join(snap, MANIFEST), "w") as fh:
        json.dump(manifest, fh, indent=2)
    return snap


# ----------------------------------------------------------------------------
# verification / rotation / restore
# ----------------------------------------------------------------------------
def verify_snapshot(snap: str, deep: bool = True) -> Dict[str, Any]:
    """Check digests + archive integrity; records result in the manifest."""
    problems: List[str] = []
    mpath = os.path.join(snap, MANIFEST)
    if not os.path.isfile(mpath):
        return {"ok": False, "problems": ["manifest.json missing"]}
    with open(mpath) as fh:
        manifest = json.load(fh)
    for name, meta in manifest.get("files", {}).items():
        p = os.path.join(snap, name)
        if not os.path.isfile(p):
            problems.append(f"{name}: missing")
            continue
        if sha256_file(p) != meta["sha256"]:
            problems.append(f"{name}: sha256 mismatch")
            continue
        if not deep:
            continue
        try:
            if name.endswith(".tar.gz"):
                with tarfile.open(p, "r:gz") as tar:
                    tar.getmembers()
            elif name.endswith(".jsonl.gz"):
                with gzip.open(p, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        json.loads(line)
            elif name.endswith(".archive.gz"):
                tool = find_tool("mongorestore")
                if tool:
                    r = subprocess.run([tool, f"--archive={p}", "--gzip", "--dryRun", "--quiet"],
                                       capture_output=True, text=True)
                    if r.returncode != 0:
                        problems.append(f"{name}: mongorestore --dryRun failed: {r.stderr.strip()[:200]}")
                else:
                    with gzip.open(p, "rb") as fh:
                        while fh.read(1 << 20):
                            pass
        except Exception as exc:
            problems.append(f"{name}: integrity error: {exc}")
    ok = not problems
    manifest["verified"] = ok
    manifest["verified_at"] = datetime.now(timezone.utc).isoformat()
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=2)
    return {"ok": ok, "problems": problems}


def rotate_snapshots(backup_dir: str, retention_days: int = 7,
                     now: Optional[datetime] = None) -> List[str]:
    """Delete snapshots older than retention_days; the newest one is always kept."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    snaps = list_snapshots(backup_dir)
    removed = []
    for name in snaps[:-1]:                           # never delete the newest
        ts = parse_snapshot_time(name)
        if ts and ts < cutoff:
            shutil.rmtree(os.path.join(backup_dir, name))
            removed.append(name)
    return removed


def restore_snapshot(snap: str, mongo_uri: str, db_name: str, restore_checkpoints_to: Optional[str] = None,
                     drop: bool = False, restore_lake_to: Optional[str] = None) -> None:
    mpath = os.path.join(snap, MANIFEST)
    with open(mpath) as fh:
        manifest = json.load(fh)
    for name in manifest["files"]:
        p = os.path.join(snap, name)
        if name.endswith(".archive.gz"):
            tool = find_tool("mongorestore")
            if not tool:
                raise RuntimeError("mongorestore not found (set MONGO_TOOLS_DIR)")
            cmd = [tool, f"--uri={mongo_uri}", f"--archive={p}", "--gzip",
                   f"--nsInclude={manifest['database']}.*"]
            if manifest["database"] != db_name:
                cmd += [f"--nsFrom={manifest['database']}.*", f"--nsTo={db_name}.*"]
            if drop:
                cmd.append("--drop")
            subprocess.run(cmd, check=True)
        elif name.endswith(".jsonl.gz"):
            from bson import json_util
            from pymongo import MongoClient
            client = MongoClient(mongo_uri)
            try:
                with gzip.open(p, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        rec = json.loads(line)
                        doc = json_util.loads(json.dumps(rec["doc"]))
                        client[db_name][rec["_collection"]].replace_one({"_id": doc["_id"]}, doc, upsert=True)
            finally:
                client.close()
        elif name == "checkpoints.tar.gz" and restore_checkpoints_to:
            os.makedirs(restore_checkpoints_to, exist_ok=True)
            with tarfile.open(p, "r:gz") as tar:
                tar.extractall(restore_checkpoints_to, filter="data")
        elif name == "lake.tar.gz" and restore_lake_to:
            os.makedirs(restore_lake_to, exist_ok=True)
            with tarfile.open(p, "r:gz") as tar:
                tar.extractall(restore_lake_to, filter="data")


def backup_status(backup_dir: str) -> Dict[str, Any]:
    """Summary used by the dashboard's System Health card (reads manifests only)."""
    snaps = list_snapshots(backup_dir)
    if not snaps:
        return {"count": 0, "latest": None, "latest_time": None, "latest_verified": None,
                "total_bytes": 0, "latest_bytes": 0}
    latest = snaps[-1]
    manifest: Dict[str, Any] = {}
    try:
        with open(os.path.join(backup_dir, latest, MANIFEST)) as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        pass
    total = 0
    for s in snaps:
        for root, _d, files in os.walk(os.path.join(backup_dir, s)):
            total += sum(os.path.getsize(os.path.join(root, f)) for f in files)
    return {
        "count": len(snaps), "latest": latest, "latest_time": parse_snapshot_time(latest),
        "latest_verified": manifest.get("verified"), "latest_bytes": manifest.get("total_bytes", 0),
        "total_bytes": total,
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MongoDB + checkpoint backup / verify / rotate / restore")
    ap.add_argument("command", choices=["backup", "verify", "rotate", "restore", "status", "run"])
    ap.add_argument("--backup-dir", default=os.getenv("BACKUP_DIR", "backups"))
    ap.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", default=os.getenv("MONGODB_DATABASE", "network_threat_analytics"))
    ap.add_argument("--checkpoint-dir", default="checkpoints")
    ap.add_argument("--retention-days", type=int, default=7)
    ap.add_argument("--snapshot", default=None, help="Snapshot name (default: newest) for verify/restore")
    ap.add_argument("--restore-db", default=None, help="Restore into this DB name (default: original)")
    ap.add_argument("--restore-checkpoints-to", default=None)
    ap.add_argument("--lake-dir", default=None, help="Also snapshot this Parquet lake directory")
    ap.add_argument("--restore-lake-to", default=None)
    ap.add_argument("--drop", action="store_true", help="Drop collections before restoring")
    ap.add_argument("--no-mongodump", action="store_true", help="Force the pure-python dump fallback")
    a = ap.parse_args(argv)

    def pick() -> str:
        snaps = list_snapshots(a.backup_dir)
        if not snaps:
            raise SystemExit("No snapshots found in " + a.backup_dir)
        return os.path.join(a.backup_dir, a.snapshot or snaps[-1])

    if a.command in ("backup", "run"):
        snap = create_backup(a.backup_dir, a.mongo_uri, a.mongo_db, a.checkpoint_dir, not a.no_mongodump,
                          lake_dir=a.lake_dir)
        print(f"[Backup] created {snap}")
    if a.command in ("verify", "run"):
        snap = pick() if a.command == "verify" else snap
        res = verify_snapshot(snap)
        print(f"[Verify] {snap}: {'OK' if res['ok'] else 'FAILED'} {res['problems'] or ''}")
        if not res["ok"]:
            return 2
    if a.command in ("rotate", "run"):
        removed = rotate_snapshots(a.backup_dir, a.retention_days)
        print(f"[Rotate] retention={a.retention_days}d removed={removed or 'none'}")
    if a.command == "restore":
        restore_snapshot(pick(), a.mongo_uri, a.restore_db or a.mongo_db, a.restore_checkpoints_to, a.drop,
                         restore_lake_to=a.restore_lake_to)
        print("[Restore] done")
    if a.command == "status":
        st = backup_status(a.backup_dir)
        st["latest_time"] = st["latest_time"].isoformat() if st["latest_time"] else None
        print(json.dumps(st, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
