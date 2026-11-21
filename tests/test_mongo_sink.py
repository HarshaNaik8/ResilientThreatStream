"""
test_mongo_sink.py — Unit tests for MongoDB persistence, data modeling, and idempotency.

Tests all requirements specified in Stage 5:
- Connection failure handling
- Alert document structure and deterministic _id
- Batch summary document structure and safe metric calculations (None on zero division)
- Idempotent alert upsert (re-running does not duplicate documents)
- Idempotent metric upsert (re-running does not duplicate documents)
- Empty micro-batch handling
- Error propagation on persistence failure
"""

import unittest
from datetime import datetime, timezone
import pymongo
from mongo_sink import (
    build_alert_document,
    build_batch_metric_document,
    persist_micro_batch,
    init_mongo_collections,
    get_mongo_client,
    close_mongo_client,
    row_to_alert_document,
    persist_alerts_partition,
    persist_batch_metric
)


class TestMongoSink(unittest.TestCase):

    def setUp(self):
        # Use local test database for integration checks
        self.uri = "mongodb://localhost:27017"
        self.test_db_name = "test_network_threat_analytics"
        try:
            self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=2000)
            self.client.server_info()
            self.mongo_available = True
            # Clean test collections before test
            self.client[self.test_db_name]["threat_alerts"].drop()
            self.client[self.test_db_name]["batch_metrics"].drop()
            init_mongo_collections(self.client, self.test_db_name)
        except Exception:
            self.mongo_available = False

    def tearDown(self):
        if self.mongo_available:
            self.client[self.test_db_name]["threat_alerts"].drop()
            self.client[self.test_db_name]["batch_metrics"].drop()
            self.client.close()
        close_mongo_client()

    def test_alert_document_construction_and_deterministic_id(self):
        """Validates that alert documents are created with deterministic _id: {topic}:{partition}:{offset}."""
        doc = build_alert_document(
            topic="network-records",
            kafka_partition=0,
            kafka_offset=250,
            protocol="tcp",
            ttl=62,
            total_len=350,
            t_delta=0.00001,
            predicted_attack=1,
            alert_reason="RAPID_BURST_DELTA;KNOWN_ATTACK_ORIGIN_TTL",
            event_timestamp=datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc),
            ground_truth_label="DDoS",
            ground_truth_is_attack=1,
            detector_version="1.0-rules"
        )

        self.assertEqual(doc["_id"], "network-records:0:250")
        self.assertEqual(doc["topic"], "network-records")
        self.assertEqual(doc["kafka_partition"], 0)
        self.assertEqual(doc["kafka_offset"], 250)
        self.assertEqual(doc["predicted_attack"], 1)
        self.assertEqual(doc["ttl"], 62)
        self.assertEqual(doc["total_len"], 350)
        self.assertIn("stored_at", doc)
        self.assertEqual(doc["ground_truth_label"], "DDoS")
        self.assertEqual(doc["ground_truth_is_attack"], 1)

    def test_batch_metric_construction_and_safe_metrics(self):
        """Validates metric calculations, deterministic _id, and explicit None on zero division."""
        # Case A: Normal calculation
        metric_doc = build_batch_metric_document(
            run_id="run-abc-123",
            batch_id=1,
            total_records=100,
            valid_records=100,
            malformed_records=0,
            alert_count=50,
            normal_count=50,
            actual_attacks=40,
            actual_benign=60,
            tp=35,
            fp=15,
            tn=45,
            fn=5
        )

        self.assertEqual(metric_doc["_id"], "run-abc-123:1")
        self.assertEqual(metric_doc["precision"], 0.7)  # 35 / 50
        self.assertEqual(metric_doc["recall"], 0.875)  # 35 / 40
        self.assertEqual(metric_doc["fpr"], 0.25)       # 15 / 60
        self.assertAlmostEqual(metric_doc["f1"], 0.7778, places=4)

        # Case B: Zero-denominator handling — undefined metrics must be None, NOT 0.0
        zero_metric_doc = build_batch_metric_document(
            run_id="run-zero",
            batch_id=2,
            total_records=10,
            valid_records=10,
            malformed_records=0,
            alert_count=0,
            normal_count=10,
            actual_attacks=0,
            actual_benign=10,
            tp=0,
            fp=0,
            tn=10,
            fn=0
        )
        self.assertIsNone(zero_metric_doc["precision"], "Undefined precision (tp+fp=0) must be None")
        self.assertIsNone(zero_metric_doc["recall"], "Undefined recall (tp+fn=0) must be None")
        self.assertIsNone(zero_metric_doc["f1"], "Undefined F1 must be None")
        self.assertEqual(zero_metric_doc["fpr"], 0.0)

    def test_empty_micro_batch_handling(self):
        """Validates that empty micro-batches (no alerts, no metrics) execute without error."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        res = persist_micro_batch(self.client, self.test_db_name, alert_docs=[], metric_doc=None)
        self.assertEqual(res["alerts_upserted"], 0)
        self.assertEqual(res["metrics_upserted"], 0)

    def test_idempotent_alert_and_metric_upserts(self):
        """Validates that persisting the same micro-batch twice does NOT duplicate documents."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        alert1 = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=101,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST"
        )
        alert2 = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=102,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST"
        )
        metric = build_batch_metric_document(
            run_id="test-run-1", batch_id=0, total_records=2, valid_records=2,
            malformed_records=0, alert_count=2, normal_count=0,
            actual_attacks=2, actual_benign=0, tp=2, fp=0, tn=0, fn=0
        )

        # First persistence
        persist_micro_batch(self.client, self.test_db_name, [alert1, alert2], metric)
        self.assertEqual(self.client[self.test_db_name]["threat_alerts"].count_documents({}), 2)
        self.assertEqual(self.client[self.test_db_name]["batch_metrics"].count_documents({}), 1)

        # Second persistence with the exact same records (simulating Spark batch retry)
        persist_micro_batch(self.client, self.test_db_name, [alert1, alert2], metric)
        self.assertEqual(self.client[self.test_db_name]["threat_alerts"].count_documents({}), 2, "Count must remain 2 (no duplicates)")
        self.assertEqual(self.client[self.test_db_name]["batch_metrics"].count_documents({}), 1, "Count must remain 1 (no duplicates)")

    def test_connection_failure_handling(self):
        """Validates that an invalid connection URI causes an error rather than silent failure."""
        invalid_client = pymongo.MongoClient("mongodb://127.0.0.1:9999", serverSelectionTimeoutMS=500)
        alert = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=999,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST"
        )
        with self.assertRaises(RuntimeError):
            persist_micro_batch(invalid_client, "dummy_db", [alert], None)
        invalid_client.close()


    def test_collection_indexes_created(self):
        """Validates that indexes are created idempotently on threat_alerts and batch_metrics."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        alerts_indexes = self.client[self.test_db_name]["threat_alerts"].index_information()
        metrics_indexes = self.client[self.test_db_name]["batch_metrics"].index_information()

        self.assertIn("idx_kafka_offset", alerts_indexes)
        self.assertIn("idx_kafka_source", alerts_indexes)
        self.assertIn("idx_stored_at", alerts_indexes)
        self.assertIn("idx_protocol", alerts_indexes)
        self.assertIn("idx_predicted_attack", alerts_indexes)
        self.assertIn("idx_run_id", alerts_indexes)

        self.assertIn("idx_batch_id", metrics_indexes)
        self.assertIn("idx_run_batch", metrics_indexes)
        self.assertIn("idx_timestamp", metrics_indexes)

    def test_alert_document_with_run_id(self):
        """Validates that run_id is correctly included in alert documents when provided."""
        doc = build_alert_document(
            topic="network-records-full-run",
            kafka_partition=0,
            kafka_offset=100,
            protocol="tcp",
            ttl=64,
            total_len=120,
            t_delta=0.00001,
            predicted_attack=1,
            alert_reason="RAPID_BURST_DELTA",
            run_id="full-run-cicids2017"
        )
        self.assertEqual(doc["_id"], "network-records-full-run:0:100")
        self.assertEqual(doc["run_id"], "full-run-cicids2017")

        # When run_id is None, key is not added
        doc_legacy = build_alert_document(
            topic="network-records",
            kafka_partition=0,
            kafka_offset=101,
            protocol="tcp",
            ttl=64,
            total_len=120,
            t_delta=0.00001,
            predicted_attack=1,
            alert_reason="RAPID_BURST_DELTA"
        )
        self.assertNotIn("run_id", doc_legacy)

    def test_alert_upsert_updates_existing_record(self):
        """Validates that upserting an alert with updated metadata updates in place without duplication."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        alert_initial = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=200,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST",
            ground_truth_label=None
        )
        persist_micro_batch(self.client, self.test_db_name, [alert_initial], None)

        stored = self.client[self.test_db_name]["threat_alerts"].find_one({"_id": "network-records:0:200"})
        self.assertIsNone(stored.get("ground_truth_label"))

        # Re-persist with ground truth added
        alert_updated = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=200,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST;KNOWN_ATTACK_ORIGIN_TTL",
            ground_truth_label="DDoS", ground_truth_is_attack=1
        )
        persist_res = persist_micro_batch(self.client, self.test_db_name, [alert_updated], None)
        self.assertEqual(persist_res["alerts_upserted"], 1)

        stored_after = self.client[self.test_db_name]["threat_alerts"].find_one({"_id": "network-records:0:200"})
        self.assertEqual(stored_after["alert_reason"], "BURST;KNOWN_ATTACK_ORIGIN_TTL")
        self.assertEqual(stored_after["ground_truth_label"], "DDoS")
        self.assertEqual(self.client[self.test_db_name]["threat_alerts"].count_documents({}), 1)

    def test_malformed_only_batch_metric_persistence(self):
        """Validates that a micro-batch with only malformed records persists correct summary."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        metric = build_batch_metric_document(
            run_id="test-malformed-run", batch_id=0, total_records=5,
            valid_records=0, malformed_records=5, alert_count=0, normal_count=0,
            actual_attacks=None, actual_benign=None, tp=None, fp=None, tn=None, fn=None
        )
        persist_micro_batch(self.client, self.test_db_name, [], metric)

        stored = self.client[self.test_db_name]["batch_metrics"].find_one({"_id": "test-malformed-run:0"})
        self.assertIsNotNone(stored)
        self.assertEqual(stored["total_records"], 5)
        self.assertEqual(stored["malformed_records"], 5)
        self.assertEqual(stored["valid_records"], 0)
        self.assertIsNone(stored["precision"])
        self.assertIsNone(stored["recall"])

    def test_missing_optional_fields_in_alert_document(self):
        """Validates that None values for protocol, timestamps, and labels are handled safely."""
        doc = build_alert_document(
            topic="network-records", kafka_partition=0, kafka_offset=300,
            protocol=None, ttl=None, total_len=None, t_delta=None,
            predicted_attack=1, alert_reason="INVALID_METADATA",
            event_timestamp=None, ground_truth_label=None, ground_truth_is_attack=None
        )
        self.assertEqual(doc["_id"], "network-records:0:300")
        self.assertEqual(doc["protocol"], "unknown")
        self.assertIsNone(doc["ttl"])
        self.assertIsNone(doc["event_timestamp"])
        self.assertIsNone(doc["ground_truth_label"])

    def test_row_to_alert_document_transformation(self):
        """Validates transforming row dictionary/object into alert document with reason strings."""
        class MockRow:
            topic = "network-records"
            kafka_partition = 0
            kafka_offset = 555
            protocol = "tcp"
            ttl = 61
            total_len = 40
            t_delta = 0.00002
            predicted_attack = 1
            is_invalid_metadata = 0
            rule_burst_delta = 1
            rule_suspicious_ttl = 1
            rule_anomalous_len = 1
            event_timestamp = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
            label = "DDoS"
            has_valid_ground_truth = 1
            is_ground_truth_attack = 1

        doc = row_to_alert_document(MockRow())
        self.assertEqual(doc["_id"], "network-records:0:555")
        self.assertEqual(doc["alert_reason"], "RAPID_BURST_DELTA;KNOWN_ATTACK_ORIGIN_TTL;ANOMALOUS_LEN")
        self.assertEqual(doc["ground_truth_label"], "DDoS")
        self.assertEqual(doc["ground_truth_is_attack"], 1)

    def test_persist_alerts_partition_bounded_bulk_and_idempotency(self):
        """Validates that partition persistence writes in bounded chunks and is idempotent."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        rows = [
            {
                "topic": "network-records", "kafka_partition": 0, "kafka_offset": 501,
                "protocol": "tcp", "ttl": 62, "total_len": 500, "t_delta": 0.00001,
                "predicted_attack": 1, "is_invalid_metadata": 0, "rule_burst_delta": 1,
                "rule_suspicious_ttl": 1, "rule_anomalous_len": 0, "has_valid_ground_truth": 1,
                "is_ground_truth_attack": 1, "label": "PortScan"
            },
            {
                "topic": "network-records", "kafka_partition": 0, "kafka_offset": 502,
                "protocol": "udp", "ttl": 30, "total_len": 60, "t_delta": 0.00001,
                "predicted_attack": 1, "is_invalid_metadata": 0, "rule_burst_delta": 1,
                "rule_suspicious_ttl": 1, "rule_anomalous_len": 0, "has_valid_ground_truth": 1,
                "is_ground_truth_attack": 1, "label": "UDP-Flood"
            },
            {
                "topic": "network-records", "kafka_partition": 0, "kafka_offset": 503,
                "protocol": "tcp", "ttl": 64, "total_len": 1600, "t_delta": 0.00001,
                "predicted_attack": 1, "is_invalid_metadata": 0, "rule_burst_delta": 1,
                "rule_suspicious_ttl": 0, "rule_anomalous_len": 1, "has_valid_ground_truth": 0,
                "is_ground_truth_attack": 0, "label": "UNKNOWN"
            }
        ]

        # First write with small batch_size=2 (tests chunked bulk writes)
        written = persist_alerts_partition(iter(rows), self.uri, self.test_db_name, batch_size=2)
        self.assertEqual(written, 3)
        self.assertEqual(self.client[self.test_db_name]["threat_alerts"].count_documents({}), 3)

        # Retry exact same partition (tests idempotency)
        written_retry = persist_alerts_partition(iter(rows), self.uri, self.test_db_name, batch_size=2)
        self.assertEqual(written_retry, 3)
        self.assertEqual(self.client[self.test_db_name]["threat_alerts"].count_documents({}), 3, "No duplicates allowed")

    def test_persist_alerts_partition_empty(self):
        """Validates that empty partition iterator safely returns 0 without opening connection."""
        written = persist_alerts_partition(iter([]), "mongodb://invalid-host:9999", self.test_db_name)
        self.assertEqual(written, 0)

    def test_persist_alerts_partition_failure_raises(self):
        """Validates that persistence failure raises RuntimeError and makes error visible."""
        rows = [{"topic": "t", "kafka_partition": 0, "kafka_offset": 1, "predicted_attack": 1}]
        with self.assertRaises(RuntimeError):
            persist_alerts_partition(iter(rows), "mongodb://127.0.0.1:9999", self.test_db_name)

    def test_persist_batch_metric_single_upsert(self):
        """Validates persist_batch_metric writes single summary document idempotently."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        metric = build_batch_metric_document(
            run_id="run-single-test", batch_id=0, total_records=10,
            valid_records=10, malformed_records=0, alert_count=5, normal_count=5,
            actual_attacks=5, actual_benign=5, tp=4, fp=1, tn=4, fn=1
        )
        persist_batch_metric(self.client, self.test_db_name, metric)
        self.assertEqual(self.client[self.test_db_name]["batch_metrics"].count_documents({}), 1)

        # Re-run same batch
        persist_batch_metric(self.client, self.test_db_name, metric)
        self.assertEqual(self.client[self.test_db_name]["batch_metrics"].count_documents({}), 1)


if __name__ == "__main__":
    unittest.main()
