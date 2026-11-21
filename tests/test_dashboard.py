"""
test_dashboard.py — Unit and Integration Tests for Stage 6 Dashboard Utilities.

Validates:
- MongoDB connection testing and failure handling
- Empty collection handling
- Missing optional fields in alerts and batch summaries
- Undefined evaluation metrics (safe division by zero -> None)
- Alert count and overview aggregations
- Aggregate confusion-matrix calculations (summed TP/FP/TN/FN)
- Filtering and pagination behavior on threat alerts
"""

import unittest
from datetime import datetime, timezone, timedelta
import pymongo
from pymongo.errors import PyMongoError

from dashboard_utils import (
    get_mongo_connection,
    test_mongo_connection,
    calculate_aggregate_confusion_matrix,
    get_overview_metrics,
    get_traffic_summary,
    get_filtered_alerts,
    get_historical_batches,
    get_available_runs
)
from mongo_sink import (
    init_mongo_collections,
    build_alert_document,
    build_batch_metric_document,
    persist_micro_batch,
    close_mongo_client
)


class TestDashboardUtils(unittest.TestCase):

    def setUp(self):
        self.uri = "mongodb://localhost:27017"
        self.test_db_name = "test_network_threat_analytics_dashboard"
        try:
            self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=2000)
            self.client.server_info()
            self.mongo_available = True
            self.db = self.client[self.test_db_name]
            self.db["threat_alerts"].drop()
            self.db["batch_metrics"].drop()
            init_mongo_collections(self.client, self.test_db_name)
        except Exception:
            self.mongo_available = False

    def tearDown(self):
        if self.mongo_available:
            self.client[self.test_db_name]["threat_alerts"].drop()
            self.client[self.test_db_name]["batch_metrics"].drop()
            self.client.close()
        close_mongo_client()

    def test_connection_testing_success_and_failure(self):
        """Validates test_mongo_connection on valid and unreachable targets."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        # 1. Valid local connection
        is_conn, err = test_mongo_connection(self.client)
        self.assertTrue(is_conn)
        self.assertIsNone(err)

        # 2. Invalid connection
        bad_client = pymongo.MongoClient("mongodb://127.0.0.1:9998", serverSelectionTimeoutMS=500)
        is_conn_bad, err_bad = test_mongo_connection(bad_client)
        self.assertFalse(is_conn_bad)
        self.assertIsNotNone(err_bad)
        bad_client.close()

    def test_empty_collections_overview_and_confusion_matrix(self):
        """Validates that empty collections return safe, graceful default metrics without crashing."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        # Overview with 0 documents
        overview = get_overview_metrics(self.db)
        self.assertEqual(overview["total_records"], 0)
        self.assertEqual(overview["accumulated_alerts"], 0)
        self.assertEqual(overview["accumulated_normal"], 0)
        self.assertIsNone(overview["overall_alert_rate"])
        self.assertIsNone(overview["most_recent_batch_time"])
        self.assertEqual(overview["stored_alerts_count"], 0)

        # Confusion matrix with 0 batches
        matrix = calculate_aggregate_confusion_matrix([])
        self.assertFalse(matrix["has_eval_data"])
        self.assertIsNone(matrix["precision"])
        self.assertIsNone(matrix["recall"])
        self.assertIsNone(matrix["f1"])
        self.assertIsNone(matrix["fpr"])

        # Traffic summary with 0 alerts
        traffic = get_traffic_summary(self.db)
        self.assertEqual(traffic["total_alerts"], 0)
        self.assertEqual(traffic["protocol_counts"], {})
        self.assertEqual(traffic["unique_reason_counts"], {})
        self.assertEqual(traffic["rule_frequency"], {})

        # Filtered alerts with 0 alerts
        alerts, count = get_filtered_alerts(self.db)
        self.assertEqual(len(alerts), 0)
        self.assertEqual(count, 0)

    def test_aggregate_confusion_matrix_weighted_calculation(self):
        """
        Validates that aggregate confusion matrix is computed from SUMMED counts
        rather than an unweighted average of individual batch metrics.
        """
        # Batch 1: Small batch, 10 records: TP=1, FP=1, TN=8, FN=0 -> Batch Precision = 1/(1+1) = 0.5
        b1 = {
            "batch_id": 1, "tp": 1, "fp": 1, "tn": 8, "fn": 0,
            "precision": 0.5, "recall": 1.0, "f1": 0.6667, "fpr": 0.1111
        }
        # Batch 2: Large batch, 100 records: TP=90, FP=10, TN=0, FN=0 -> Batch Precision = 90/(90+10) = 0.9
        b2 = {
            "batch_id": 2, "tp": 90, "fp": 10, "tn": 0, "fn": 0,
            "precision": 0.9, "recall": 1.0, "f1": 0.9474, "fpr": None
        }

        # If unweighted average was used: Precision would be (0.5 + 0.9)/2 = 0.7
        # Correct summed calculation:
        # Total TP = 91, Total FP = 11 -> Precision = 91 / (91 + 11) = 91/102 = 0.8922
        # Total TN = 8, Total FN = 0 -> Recall = 91 / (91 + 0) = 1.0
        # Total Benign = 11 + 8 = 19 -> FPR = 11 / 19 = 0.5789
        matrix = calculate_aggregate_confusion_matrix([b1, b2])

        self.assertTrue(matrix["has_eval_data"])
        self.assertEqual(matrix["tp"], 91)
        self.assertEqual(matrix["fp"], 11)
        self.assertEqual(matrix["tn"], 8)
        self.assertEqual(matrix["fn"], 0)
        self.assertEqual(matrix["actual_attacks"], 91)
        self.assertEqual(matrix["actual_benign"], 19)
        self.assertAlmostEqual(matrix["precision"], 0.8922, places=4)
        self.assertEqual(matrix["recall"], 1.0)
        self.assertAlmostEqual(matrix["fpr"], 0.5789, places=4)
        self.assertAlmostEqual(matrix["accuracy"], 99 / 110, places=4)

    def test_undefined_evaluation_metrics_zero_division(self):
        """Validates that undefined metrics (zero in denominator) return None safely."""
        # Case where no attacks are predicted or present (TP=0, FP=0, FN=0, TN=10)
        b_zero = {
            "batch_id": 0, "tp": 0, "fp": 0, "tn": 10, "fn": 0
        }
        matrix = calculate_aggregate_confusion_matrix([b_zero])
        self.assertTrue(matrix["has_eval_data"])
        self.assertIsNone(matrix["precision"])
        self.assertIsNone(matrix["recall"])
        self.assertIsNone(matrix["f1"])
        self.assertEqual(matrix["fpr"], 0.0)

    def test_missing_optional_fields_and_malformed_docs(self):
        """Validates handling of documents with missing or null attributes."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        # Alert document with missing/None fields
        doc_sparse = {
            "_id": "sparse:0:1",
            "topic": "network-records",
            "kafka_partition": 0,
            "kafka_offset": 1,
            "event_timestamp": None,
            "stored_at": datetime.now(timezone.utc),
            "protocol": None,  # null protocol
            "ttl": None,
            "total_len": None,
            "t_delta": None,
            "predicted_attack": 1,
            "alert_reason": None,  # null reason
            "ground_truth_label": None,
            "ground_truth_is_attack": None
        }
        self.db["threat_alerts"].insert_one(doc_sparse)

        # Batch metric document with missing evaluation fields
        metric_sparse = {
            "_id": "sparse_run:0",
            "run_id": "sparse_run",
            "batch_id": 0,
            "timestamp": datetime.now(timezone.utc),
            "total_records": 10,
            "valid_records": 8,
            "malformed_records": 2,
            "alert_count": 1,
            "normal_count": 7,
            "tp": None, "fp": None, "tn": None, "fn": None
        }
        self.db["batch_metrics"].insert_one(metric_sparse)

        overview = get_overview_metrics(self.db)
        self.assertEqual(overview["total_records"], 10)
        self.assertEqual(overview["stored_alerts_count"], 1)

        traffic = get_traffic_summary(self.db)
        self.assertEqual(traffic["total_alerts"], 1)
        self.assertIn("unknown", traffic["protocol_counts"])

        alerts, count = get_filtered_alerts(self.db)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(count, 1)

    def test_filtering_and_sorting_behavior(self):
        """Validates query filtering by protocol, reason, ground truth, and pagination."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        # Insert 3 test alerts
        t0 = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)
        a1 = build_alert_document(
            topic="test", kafka_partition=0, kafka_offset=10,
            protocol="tcp", ttl=62, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="RAPID_BURST_DELTA;KNOWN_ATTACK_ORIGIN_TTL",
            event_timestamp=t0, ground_truth_label="DDoS", ground_truth_is_attack=1
        )
        a2 = build_alert_document(
            topic="test", kafka_partition=0, kafka_offset=20,
            protocol="udp", ttl=128, total_len=20, t_delta=0.1,
            predicted_attack=1, alert_reason="INVALID_PACKET_LEN",
            event_timestamp=t0 + timedelta(seconds=1), ground_truth_label="PortScan", ground_truth_is_attack=1
        )
        a3 = build_alert_document(
            topic="test", kafka_partition=0, kafka_offset=30,
            protocol="tcp", ttl=64, total_len=1600, t_delta=0.00002,
            predicted_attack=1, alert_reason="RAPID_BURST_DELTA;OVERSIZED_MTU_LEN",
            event_timestamp=t0 + timedelta(seconds=2), ground_truth_label="BENIGN", ground_truth_is_attack=0
        )
        persist_micro_batch(self.client, self.test_db_name, [a1, a2, a3], None)

        # 1. Protocol filter
        tcp_alerts, tcp_count = get_filtered_alerts(self.db, protocol="tcp")
        self.assertEqual(tcp_count, 2)
        self.assertEqual(len(tcp_alerts), 2)

        udp_alerts, udp_count = get_filtered_alerts(self.db, protocol="udp")
        self.assertEqual(udp_count, 1)

        # 2. Alert Reason filter (regex substring)
        burst_alerts, burst_count = get_filtered_alerts(self.db, alert_reason="BURST")
        self.assertEqual(burst_count, 2)

        mtu_alerts, mtu_count = get_filtered_alerts(self.db, alert_reason="OVERSIZED")
        self.assertEqual(mtu_count, 1)

        # 3. Ground Truth filter
        ddos_alerts, ddos_count = get_filtered_alerts(self.db, ground_truth="DDoS")
        self.assertEqual(ddos_count, 1)

        benign_alerts, benign_count = get_filtered_alerts(self.db, ground_truth="BENIGN")
        self.assertEqual(benign_count, 1)

        attack_alerts, attack_count = get_filtered_alerts(self.db, ground_truth="ATTACK (All attacks)")
        self.assertEqual(attack_count, 2)

        # 4. Pagination: limit=1, skip=1
        page_alerts, total = get_filtered_alerts(self.db, sort_field="kafka_offset", sort_direction=1, limit=1, skip=1)
        self.assertEqual(total, 3)
        self.assertEqual(len(page_alerts), 1)
        self.assertEqual(page_alerts[0]["kafka_offset"], 20)

        # 5. Run ID filtering
        a_run1 = build_alert_document(
            topic="test", kafka_partition=0, kafka_offset=40,
            protocol="tcp", ttl=64, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST",
            run_id="run-alpha"
        )
        a_run2 = build_alert_document(
            topic="test", kafka_partition=0, kafka_offset=50,
            protocol="tcp", ttl=64, total_len=100, t_delta=0.00001,
            predicted_attack=1, alert_reason="BURST",
            run_id="run-beta"
        )
        persist_micro_batch(self.client, self.test_db_name, [a_run1, a_run2], None)

        alpha_alerts, alpha_count = get_filtered_alerts(self.db, run_id="run-alpha")
        self.assertEqual(alpha_count, 1)
        self.assertEqual(alpha_alerts[0]["kafka_offset"], 40)
        self.assertEqual(alpha_alerts[0].get("run_id"), "run-alpha")

        beta_alerts, beta_count = get_filtered_alerts(self.db, run_id="run-beta")
        self.assertEqual(beta_count, 1)
        self.assertEqual(beta_alerts[0]["kafka_offset"], 50)
        self.assertEqual(beta_alerts[0].get("run_id"), "run-beta")

        # Legacy / unassigned documents (without run_id)
        legacy_alerts, legacy_count = get_filtered_alerts(self.db, run_id="Legacy / Unassigned")
        self.assertEqual(legacy_count, 3)  # a1, a2, a3 have no run_id

    def test_historical_batches_cumulative_and_sorting(self):
        """Validates that get_historical_batches sorts correctly and computes cumulative counts."""
        if not self.mongo_available:
            self.skipTest("MongoDB not available")

        t0 = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)
        m1 = build_batch_metric_document(
            run_id="run-A", batch_id=0, total_records=50, valid_records=50, malformed_records=0,
            alert_count=20, normal_count=30, actual_attacks=20, actual_benign=30,
            tp=18, fp=2, tn=28, fn=2, timestamp=t0
        )
        m2 = build_batch_metric_document(
            run_id="run-A", batch_id=1, total_records=30, valid_records=30, malformed_records=0,
            alert_count=10, normal_count=20, actual_attacks=10, actual_benign=20,
            tp=9, fp=1, tn=19, fn=1, timestamp=t0 + timedelta(seconds=5)
        )
        persist_micro_batch(self.client, self.test_db_name, [], m1)
        persist_micro_batch(self.client, self.test_db_name, [], m2)

        batches = get_historical_batches(self.db, run_id="run-A")
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0]["cumulative_records"], 50)
        self.assertEqual(batches[0]["cumulative_alerts"], 20)
        self.assertEqual(batches[0]["alert_rate"], 0.4)

        self.assertEqual(batches[1]["cumulative_records"], 80)
        self.assertEqual(batches[1]["cumulative_alerts"], 30)
        self.assertAlmostEqual(batches[1]["alert_rate"], 0.3333, places=4)


if __name__ == "__main__":
    unittest.main()
