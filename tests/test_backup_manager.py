"""Tests for scripts/backup_manager.py (Phase 5): backup, verify, rotation, restore."""
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from scripts import backup_manager as bm


MONGO_URI = os.getenv("MONGODB_TEST_URI", "mongodb://localhost:27017")


def _ping(uri: str) -> bool:
    try:
        from pymongo import MongoClient
        MongoClient(uri, serverSelectionTimeoutMS=1500).admin.command("ping")
        return True
    except Exception:
        return False


def mongo_available() -> bool:
    return _ping(MONGO_URI)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _mk(self, days_old):
        name = (self.now - timedelta(days=days_old)).strftime(bm.TS_FORMAT)
        os.makedirs(os.path.join(self.d, name))
        return name

    def test_deletes_only_older_than_retention(self):
        old, edge, fresh = self._mk(10), self._mk(6), self._mk(0)
        removed = bm.rotate_snapshots(self.d, 7, now=self.now)
        self.assertEqual(removed, [old])
        self.assertEqual(bm.list_snapshots(self.d), sorted([edge, fresh]))

    def test_newest_always_kept_even_if_old(self):
        only = self._mk(30)
        self.assertEqual(bm.rotate_snapshots(self.d, 7, now=self.now), [])
        self.assertEqual(bm.list_snapshots(self.d), [only])

    def test_ignores_foreign_directories(self):
        os.makedirs(os.path.join(self.d, "not-a-snapshot"))
        self._mk(1)
        bm.rotate_snapshots(self.d, 7, now=self.now)
        self.assertTrue(os.path.isdir(os.path.join(self.d, "not-a-snapshot")))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ckpt = os.path.join(self.d, "ckpt")
        os.makedirs(os.path.join(self.ckpt, "offsets"))
        with open(os.path.join(self.ckpt, "offsets", "0"), "w") as fh:
            fh.write('v1\n{}\n{"t":{"0":5}}')
        self.db = f"bda_backup_test_{os.getpid()}"

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)
        if mongo_available():
            from pymongo import MongoClient
            c = MongoClient(MONGO_URI)
            for n in (self.db, self.db + "_restored"):
                c.drop_database(n)

    @unittest.skipUnless(mongo_available(), "MongoDB not running")
    def _backup(self, use_mongodump):
        from pymongo import MongoClient
        MongoClient(MONGO_URI)[self.db]["threat_alerts"].insert_many([{"_id": i, "v": i} for i in range(25)])
        return bm.create_backup(os.path.join(self.d, "bk"), MONGO_URI, self.db, self.ckpt,
                                use_mongodump=use_mongodump, read_preference="primary")

    @unittest.skipUnless(mongo_available(), "MongoDB not running")
    def test_python_fallback_backup_verify_restore(self):
        snap = self._backup(False)
        manifest = json.load(open(os.path.join(snap, "manifest.json")))
        self.assertEqual(manifest["mongo"]["collections"]["threat_alerts"], 25)
        self.assertIn("mongo.jsonl.gz", manifest["files"])
        self.assertIn("checkpoints.tar.gz", manifest["files"])
        self.assertTrue(bm.verify_snapshot(snap)["ok"])
        self.assertTrue(json.load(open(os.path.join(snap, "manifest.json")))["verified"])
        bm.restore_snapshot(snap, MONGO_URI, self.db + "_restored",
                            restore_checkpoints_to=os.path.join(self.d, "restored_ckpt"))
        from pymongo import MongoClient
        self.assertEqual(MongoClient(MONGO_URI)[self.db + "_restored"]["threat_alerts"].count_documents({}), 25)
        self.assertTrue(os.path.isfile(os.path.join(self.d, "restored_ckpt", "ckpt", "offsets", "0")))

    @unittest.skipUnless(mongo_available() and bm.find_tool("mongodump"), "MongoDB/mongodump unavailable")
    def test_mongodump_gzip_archive_backup_and_verify(self):
        snap = self._backup(True)
        self.assertTrue(os.path.isfile(os.path.join(snap, "mongo.archive.gz")))
        self.assertTrue(bm.verify_snapshot(snap)["ok"])

    @unittest.skipUnless(mongo_available(), "MongoDB not running")
    def test_corruption_is_detected(self):
        snap = self._backup(False)
        with open(os.path.join(snap, "checkpoints.tar.gz"), "ab") as fh:
            fh.write(b"corrupt")
        res = bm.verify_snapshot(snap)
        self.assertFalse(res["ok"])
        self.assertTrue(any("sha256" in p for p in res["problems"]))
        self.assertFalse(json.load(open(os.path.join(snap, "manifest.json")))["verified"])

    def test_verify_without_manifest_fails(self):
        os.makedirs(os.path.join(self.d, "x"))
        self.assertFalse(bm.verify_snapshot(os.path.join(self.d, "x"))["ok"])

    def test_status_empty_and_populated(self):
        self.assertEqual(bm.backup_status(os.path.join(self.d, "none"))["count"], 0)
        snap = os.path.join(self.d, "bk", "20261120T100000Z")
        os.makedirs(snap)
        json.dump({"verified": True, "total_bytes": 123}, open(os.path.join(snap, "manifest.json"), "w"))
        st = bm.backup_status(os.path.join(self.d, "bk"))
        self.assertEqual((st["count"], st["latest"], st["latest_verified"], st["latest_bytes"]),
                         (1, "20261120T100000Z", True, 123))

    def test_checkpoint_archive_roundtrip(self):
        out = os.path.join(self.d, "out")
        os.makedirs(out)
        info = bm.archive_checkpoints(self.ckpt, out)
        self.assertEqual(info["file"], "checkpoints.tar.gz")
        self.assertIsNone(bm.archive_checkpoints(os.path.join(self.d, "missing"), out))


class LakeBackupTests(unittest.TestCase):
    def test_lake_archive_roundtrip_and_missing_lake(self):
        d = tempfile.mkdtemp()
        try:
            lake = os.path.join(d, "lake", "events", "run_id=r", "protocol=tcp")
            os.makedirs(lake)
            open(os.path.join(lake, "p.snappy.parquet"), "wb").write(b"PAR1data")
            out = os.path.join(d, "snap")
            os.makedirs(out)
            info = bm.archive_lake(os.path.join(d, "lake"), out)
            self.assertEqual(info["file"], "lake.tar.gz")
            import tarfile
            with tarfile.open(os.path.join(out, "lake.tar.gz")) as t:
                self.assertTrue(any(n.endswith("p.snappy.parquet") for n in t.getnames()))
            self.assertIsNone(bm.archive_lake(os.path.join(d, "nope"), out))
            self.assertIsNone(bm.archive_lake(None, out))
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(mongo_available(), "MongoDB not running")
class DrillTests(unittest.TestCase):
    def test_drill_reports_matching_counts_and_cleans_up(self):
        from pymongo import MongoClient
        from scripts.dr_drill import run_drill
        db = f"bda_drill_test_{os.getpid()}"
        c = MongoClient(MONGO_URI)
        try:
            c[db]["threat_alerts"].insert_many([{"_id": i} for i in range(40)])
            res = run_drill(MONGO_URI, db, "nonexistent_ckpt")
            self.assertTrue(res["verify_ok"] and res["integrity_ok"])
            self.assertEqual(res["collections"]["threat_alerts"], {"source": 40, "restored": 40, "match": True})
            self.assertGreater(res["rto_seconds"], 0)
            self.assertNotIn(db + "_drill_restore", c.list_database_names())
        finally:
            c.drop_database(db)
            c.close()


class ToolConfigTests(unittest.TestCase):
    def test_uri_goes_to_private_temp_file_not_argv(self):
        uri = "mongodb://user:s3cret@localhost:27017/?authSource=admin"
        with bm.tool_config(uri) as arg:
            self.assertTrue(arg.startswith("--config="))
            self.assertNotIn("s3cret", arg)
            path = arg.split("=", 1)[1]
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            self.assertIn("s3cret", open(path).read())
        self.assertFalse(os.path.exists(path))          # removed afterwards

    def test_spark_consumer_log_redaction(self):
        from spark_consumer import redact_mongo_uri
        out = redact_mongo_uri("mongodb://user:s3cret@h1:27017,h2:27018/?replicaSet=x")
        self.assertEqual(out, "h1:27017,h2:27018")
        self.assertNotIn("s3cret", redact_mongo_uri("not a uri s3cret"))


if __name__ == "__main__":
    unittest.main()
