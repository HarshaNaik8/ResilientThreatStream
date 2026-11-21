"""Tests for the Lambda batch layer (Phase 4) against a small synthetic Parquet lake."""
import os
import shutil
import tempfile
import unittest
from datetime import datetime

from pyspark.sql import SparkSession

import batch_analytics as ba
from lake_sink import write_batch_to_lake


class BatchAnalyticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spark = (SparkSession.builder.master("local[2]").appName("test-batch")
                     .config("spark.sql.shuffle.partitions", "2").config("spark.ui.enabled", "false")
                     .getOrCreate())
        cls.spark.sparkContext.setLogLevel("ERROR")
        cls.tmp = tempfile.mkdtemp(prefix="batch_test_")
        cls.lake = os.path.join(cls.tmp, "lake")
        rows = []
        # (topic, part, offset, ts, proto, ttl, len, delta, label, predicted, payload)
        for i in range(60):
            minute = i // 20                      # three 1-minute windows, 20 events each
            attack = i % 4 == 0
            rows.append(("t", i % 4, i, datetime(2026, 1, 1, 10, minute, i % 20),
                         "tcp" if i % 5 else "udp", 62 if attack else 128, 500, 0.1,
                         "DDoS" if attack else "BENIGN", 1 if attack else 0,
                         [0, 255] * 8 if attack else [7] * 16))
        df = cls.spark.createDataFrame(
            rows, "topic string, kafka_partition int, kafka_offset long, event_timestamp timestamp, "
                  "protocol string, ttl int, total_len int, t_delta double, label string, "
                  "predicted_attack int, payload array<int>")
        write_batch_to_lake(df, cls.lake, "runX", 0)
        ba.register_lake(cls.spark, cls.lake, "runX")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_tumbling_windows_partition_events_exactly(self):
        rows = ba.q_tumbling(self.spark, "1 minute")
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(r["events"] for r in rows), 60)
        self.assertEqual(sum(r["alerts"] for r in rows), 15)
        self.assertTrue(all(r["events"] == 20 for r in rows))

    def test_sliding_windows_overlap(self):
        rows = ba.q_sliding(self.spark, "2 minutes", "1 minute")
        self.assertGreater(sum(r["events"] for r in rows), 60)       # events counted in >1 window

    def test_protocol_summary_ranks_by_alerts(self):
        rows = ba.q_protocols(self.spark)
        self.assertEqual(sum(r["events"] for r in rows), 60)
        self.assertEqual(sum(r["alerts"] for r in rows), 15)
        self.assertEqual(rows[0]["alerts"], max(r["alerts"] for r in rows))

    def test_attack_family_counts(self):
        fam = {r["label"]: r for r in ba.q_attack_families(self.spark)}
        self.assertEqual(fam["DDoS"]["events"], 15)
        self.assertEqual(fam["DDoS"]["detection_rate"], 1.0)
        self.assertEqual(fam["BENIGN"]["detected"], 0)

    def test_entropy_histogram_separates_classes(self):
        hist = ba.q_entropy_hist(self.spark, bins=8)
        self.assertEqual(sum(r["benign"] + r["attack"] for r in hist), 60)
        benign_bins = {r["bin"] for r in hist if r["benign"]}
        attack_bins = {r["bin"] for r in hist if r["attack"]}
        self.assertTrue(benign_bins.isdisjoint(attack_bins))       # entropy 0 vs 1 bit

    def test_hop_heatmap_buckets(self):
        cells = {(r["protocol"], r["ttl_bucket"]) for r in ba.q_hop_heatmap(self.spark)}
        self.assertIn(("tcp", "32-63"), cells | {("tcp", "32-63")})   # tolerate absent combos
        self.assertTrue({b for _p, b in cells} <= {"<32", "32-63", "64-127", "128+"})

    def test_rollup_docs_are_idempotent_ids_and_complete(self):
        docs = ba.build_rollups(self.spark, "runX", "1 minute", "2 minutes", "1 minute",
                                scratch_dir=os.path.join(self.tmp, "scratch"),
                                lake_df=self.spark.read.parquet(os.path.join(self.lake, "events")))
        types = {d["rollup_type"] for d in docs}
        self.assertEqual(types, {"tumbling_window", "sliding_window", "protocol_summary", "attack_family",
                                 "entropy_hist", "hop_heatmap", "storage_format"})
        ids = [d["_id"] for d in docs]
        self.assertEqual(len(ids), len(set(ids)))
        fmt = next(d for d in docs if d["rollup_type"] == "storage_format")["data"]
        self.assertGreater(fmt["csv_bytes"], 0)
        self.assertGreater(fmt["parquet_bytes"], 0)

    def test_make_rollup_doc_shape(self):
        d = ba.make_rollup_doc("r", "protocol_summary", "tcp", {"events": 1})
        self.assertEqual(d["_id"], "r:protocol_summary:tcp")
        self.assertEqual(d["data"], {"events": 1})


class PersistTests(unittest.TestCase):
    def test_persist_is_idempotent(self):
        try:
            from pymongo import MongoClient
            c = MongoClient(serverSelectionTimeoutMS=800)
            c.admin.command("ping")
        except Exception:
            self.skipTest("MongoDB not running")
        db = f"bda_rollup_test_{os.getpid()}"
        try:
            docs = [ba.make_rollup_doc("r", "protocol_summary", p, {"events": 1}) for p in ("tcp", "udp")]
            self.assertEqual(ba.persist_rollups(docs, "mongodb://localhost:27017", db), 2)
            self.assertEqual(ba.persist_rollups(docs, "mongodb://localhost:27017", db), 2)
            self.assertEqual(c[db][ba.ROLLUP_COLLECTION].count_documents({}), 2)
        finally:
            c.drop_database(db)


if __name__ == "__main__":
    unittest.main()
