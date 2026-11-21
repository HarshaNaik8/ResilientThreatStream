"""Tests for rebuilding MongoDB alerts from the Parquet lake (data-loss scenario C)."""
import os
import shutil
import tempfile
import unittest
from datetime import datetime

import pyarrow as pa
import pyarrow.parquet as pq

from scripts import lake_recovery as lr


def make_lake(root):
    part = os.path.join(root, "events", "run_id=r1", "protocol=tcp")
    os.makedirs(part)
    t = datetime(2026, 1, 1, 12)
    rows = {
        "topic": ["t"] * 3, "kafka_partition": [0, 1, 2], "kafka_offset": [10, 11, 12], "event_time": [t] * 3,
        "ttl": [62, 128, 64], "total_len": [40, 500, 60], "t_delta": [0.00001, 0.5, 0.1],
        "label": ["DoS Hulk", "BENIGN", "Bot"], "rule_attack": [1, 0, 0], "ml_attack": [1, 0, 1],
        "predicted_attack": [1, 0, 1], "batch_id": [7, 7, 7],
    }
    pq.write_table(pa.table(rows), os.path.join(part, "part-0.snappy.parquet"), compression="snappy")


class ReasonTests(unittest.TestCase):
    def test_reason_flags(self):
        self.assertEqual(lr.reason_from_flags(1, 0), "RULE_ALERT")
        self.assertEqual(lr.reason_from_flags(0, 1), "ML_PAYLOAD_ANOMALY")
        self.assertEqual(lr.reason_from_flags(1, 1), "RULE_ALERT;ML_PAYLOAD_ANOMALY")
        self.assertEqual(lr.reason_from_flags(None, None), "HEURISTIC_ALERT")


class LakeDocsTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        make_lake(self.d)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_only_predicted_alerts_with_deterministic_ids(self):
        docs = [d for batch in lr.lake_alert_docs(self.d, "r1") for d in batch]
        self.assertEqual(sorted(d["_id"] for d in docs), ["t:0:10", "t:2:12"])   # same id scheme as the live sink
        hulk = next(d for d in docs if d["kafka_offset"] == 10)
        self.assertEqual((hulk["run_id"], hulk["protocol"], hulk["ground_truth_is_attack"]), ("r1", "tcp", 1))
        self.assertEqual(hulk["detector_version"], "recovered-from-lake")

    def test_batch_metrics_rebuilt_from_verdicts_and_labels(self):
        # rows: offset10 DoS Hulk pred1 (TP), offset11 BENIGN pred0 (TN), offset12 Bot pred1 (TP)  -- all batch_id missing -> add
        docs = lr.rebuild_batch_metrics(self.d, "r1")
        self.assertEqual(len(docs), 1)
        d = docs[0]
        self.assertEqual(d["_id"], "r1:7")
        self.assertEqual((d["total_records"], d["alert_count"], d["normal_count"]), (3, 2, 1))
        self.assertEqual((d["tp"], d["fp"], d["tn"], d["fn"]), (2, 0, 1, 0))
        self.assertEqual((d["precision"], d["recall"]), (1.0, 1.0))
        self.assertTrue(d["recovered_from_lake"])

    def test_unknown_run_yields_nothing(self):
        self.assertEqual([d for b in lr.lake_alert_docs(self.d, "nope") for d in b], [])


if __name__ == "__main__":
    unittest.main()
