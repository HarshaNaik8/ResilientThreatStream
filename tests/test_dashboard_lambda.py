"""Tests for the Lambda dashboard helpers: rollups, lake stats, DR status, Kafka lag."""
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

import dashboard_utils as du


class FakeCursor(list):
    def sort(self, *_a, **_k):
        return self

    def limit(self, *_a, **_k):
        return self


class FakeColl:
    def __init__(self, docs):
        self.docs, self.last_query = docs, None

    def find(self, q):
        self.last_query = q
        return FakeCursor(d for d in self.docs if all(d.get(k) == v for k, v in q.items()))

    def distinct(self, key):
        return list({d[key] for d in self.docs})


class FakeDB(dict):
    pass


class RollupTests(unittest.TestCase):
    def setUp(self):
        t = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.coll = FakeColl([
            {"run_id": "a", "rollup_type": "protocol_summary", "key": "tcp", "data": {"events": 5}, "generated_at": t},
            {"run_id": "b", "rollup_type": "protocol_summary", "key": "udp", "data": {"events": 7}, "generated_at": t},
            {"run_id": "a", "rollup_type": "attack_family", "key": "DDoS", "data": {"events": 2}, "generated_at": t},
        ])
        self.db = FakeDB({du.ROLLUP_COLLECTION: self.coll})

    def test_filters_by_type_and_run(self):
        rows = du.get_historical_rollups(self.db, "protocol_summary", "a")
        self.assertEqual([r["events"] for r in rows], [5])
        self.assertEqual(rows[0]["run_id"], "a")

    def test_all_runs_returns_every_run(self):
        self.assertEqual(len(du.get_historical_rollups(self.db, "protocol_summary", "All Runs")), 2)
        self.assertEqual(len(du.get_historical_rollups(self.db, "protocol_summary", None)), 2)

    def test_missing_collection_returns_empty(self):
        class Boom:
            def __getitem__(self, _):
                raise du.PyMongoError("down")
        self.assertEqual(du.get_historical_rollups(Boom(), "x"), [])
        self.assertEqual(du.get_rollup_runs(Boom()), [])

    def test_rollup_runs(self):
        self.assertEqual(du.get_rollup_runs(self.db), ["a", "b"])


class LakeAndBackupStatusTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_lake_stats_absent(self):
        self.assertEqual(du.get_lake_stats(os.path.join(self.d, "nope")), {"available": False, "bytes": 0, "files": 0})
        self.assertFalse(du.get_lake_stats("")["available"])

    def test_lake_stats_counts_parquet_files(self):
        p = os.path.join(self.d, "events", "run_id=r", "protocol=tcp")
        os.makedirs(p)
        for n in ("a.snappy.parquet", "b.snappy.parquet", "_SUCCESS"):
            open(os.path.join(p, n), "wb").write(b"x" * 10)
        st = du.get_lake_stats(self.d)
        self.assertEqual((st["available"], st["bytes"], st["files"]), (True, 30, 2))

    def test_backup_status_none_then_present(self):
        self.assertFalse(du.get_backup_status(os.path.join(self.d, "bk"))["available"])
        snap = os.path.join(self.d, "bk", "20261120T010203Z")
        os.makedirs(snap)
        json.dump({"verified": True, "total_bytes": 10}, open(os.path.join(snap, "manifest.json"), "w"))
        st = du.get_backup_status(os.path.join(self.d, "bk"))
        self.assertTrue(st["available"])
        self.assertTrue(st["latest_verified"])
        self.assertEqual(st["latest_time"].year, 2026)

    def test_human_bytes(self):
        self.assertEqual(du.human_bytes(512), "512 B")
        self.assertEqual(du.human_bytes(2048), "2.0 KB")
        self.assertEqual(du.human_bytes(5 * 1024 ** 3), "5.0 GB")


class LagTests(unittest.TestCase):
    def test_compute_lag(self):
        res = du.compute_lag({0: 100, 1: 50, 2: 10}, {"0": 90, "1": 50})
        self.assertEqual(res["per_partition"], {0: 10, 1: 0, 2: 10})
        self.assertEqual((res["total"], res["partitions"]), (20, 3))

    def test_lag_never_negative(self):
        self.assertEqual(du.compute_lag({0: 5}, {"0": 9})["total"], 0)

    def test_read_checkpoint_offsets(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "offsets"))
            for i, off in ((1, 10), (2, 20)):
                open(os.path.join(d, "offsets", str(i)), "w").write(f'v1\n{{"conf":1}}\n{{"topic":{{"0":{off}}}}}')
            self.assertEqual(du.read_checkpoint_offsets(d), {"topic": {"0": 20}})
            self.assertEqual(du.read_checkpoint_offsets(os.path.join(d, "missing")), {})
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_kafka_unreachable_degrades_gracefully(self):
        res = du.get_kafka_consumer_lag("localhost:1", "t", "nowhere", timeout_ms=300)
        self.assertFalse(res["available"])


class ClusterStatusTests(unittest.TestCase):
    def test_unreachable_server_degrades_gracefully(self):
        self.assertFalse(du.get_replica_set_status("mongodb://localhost:1", timeout_ms=300)["available"])
        self.assertFalse(du.get_cluster_status("mongodb://localhost:1", timeout_ms=300)["available"])

    def test_live_sharded_cluster_if_present(self):
        res = du.get_cluster_status("mongodb://127.0.0.1:27019")
        if not (res["available"] and res["sharded"]):
            self.skipTest("sharded cluster not running")
        self.assertEqual(set(res["shards"]), {"shard1", "shard2"})
        for rs in res["shards"].values():
            self.assertTrue(rs["has_primary"])
            self.assertEqual(len(rs["members"]), 3)


if __name__ == "__main__":
    unittest.main()
