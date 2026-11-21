"""Tests for the Spark MLlib payload detector and hybrid logic (Phase 3)."""
import random
import unittest

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

import ml_payload_detector as ml


class MetricsTests(unittest.TestCase):
    def test_metrics_from_counts(self):
        m = ml.metrics_from_counts(tp=8, fp=2, tn=88, fn=2)
        self.assertEqual(m["precision"], 0.8)
        self.assertEqual(m["recall"], 0.8)
        self.assertEqual(m["f1"], 0.8)
        self.assertEqual(m["accuracy"], 0.96)
        self.assertAlmostEqual(m["fpr"], 2 / 90, places=3)

    def test_zero_division_is_safe(self):
        m = ml.metrics_from_counts(0, 0, 0, 0)
        self.assertEqual((m["precision"], m["recall"], m["f1"], m["accuracy"], m["fpr"]), (0, 0, 0, 0, 0))

    def test_feature_contract(self):
        self.assertEqual(len(ml.PAYLOAD_COLUMNS), 1500)
        self.assertEqual(ml.PAYLOAD_COLUMNS[0], "payload_byte_1")
        self.assertEqual(ml.PCA_K, 32)


class MLSparkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spark = (SparkSession.builder.master("local[2]").appName("test-ml")
                     .config("spark.sql.shuffle.partitions", "2").config("spark.ui.enabled", "false")
                     .config("spark.driver.memory", "1g").getOrCreate())
        cls.spark.sparkContext.setLogLevel("ERROR")
        rnd = random.Random(0)
        rows = []
        for i in range(240):
            attack = i % 2
            # attack payloads concentrate on high bytes in the first 100 positions; benign on low bytes
            base = 200 if attack else 10
            payload = [min(255, max(0, int(rnd.gauss(base, 15)))) if j < 100 else 0 for j in range(1500)]
            # metadata deliberately UNinformative so the model must use the payload
            rows.append((rnd.choice([64, 128]), rnd.choice([100, 500]), rnd.random(),
                         "tcp", "DoS Hulk" if attack else "BENIGN", payload))
        cls.df = cls.spark.createDataFrame(rows, ["ttl", "total_len", "t_delta", "protocol", "label", "payload"])
        feats = ml.with_attack_target(ml.with_features_from_payload_array(cls.df))
        cls.model = ml.build_pipeline(num_trees=15, max_depth=6, k=8).fit(feats)
        cls.feats = feats

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def test_target_derived_from_label(self):
        counts = dict(self.feats.groupBy("is_attack").count().collect())
        self.assertEqual(counts[1.0], 120)
        self.assertEqual(counts[0.0], 120)

    def test_label_is_not_a_model_input(self):
        """Zero data leakage: the assembler/RF only see PCA(payload)+metadata, never label/is_attack."""
        assembler = self.model.stages[1]
        self.assertEqual(assembler.getInputCols(), ["pca_features"] + ml.META_FEATURES)
        for name in ("label", "is_attack"):
            self.assertNotIn(name, assembler.getInputCols())
        self.assertEqual(self.model.stages[0].getInputCol(), "features")

    def test_inference_does_not_read_label(self):
        no_label = ml.with_features_from_payload_array(self.df.drop("label"))
        scored = ml.score_dataframe(self.model, no_label)          # must not raise
        self.assertIn("ml_attack_prob", scored.columns)
        self.assertNotIn("label", scored.columns)

    def test_model_separates_payload_classes(self):
        scored = ml.score_dataframe(self.model, self.feats).withColumn("p", F.col("ml_attack"))
        m = ml.confusion_metrics(scored, "p")
        self.assertGreater(m["recall"], 0.95)
        self.assertGreater(m["precision"], 0.95)

    def test_pca_k_and_probability_range(self):
        self.assertEqual(self.model.stages[0].getK(), 8)
        scored = ml.score_dataframe(self.model, self.feats)
        lo, hi = scored.agg(F.min("ml_attack_prob"), F.max("ml_attack_prob")).first()
        self.assertGreaterEqual(lo, 0.0)
        self.assertLessEqual(hi, 1.0)

    def test_heavy_columns_dropped_after_scoring(self):
        scored = ml.score_dataframe(self.model, self.feats)
        for c in ("features", "pca_features", "model_input", "probability", "payload"):
            self.assertNotIn(c, scored.columns)

    def test_hybrid_is_rule_or_ml(self):
        df = self.spark.createDataFrame(
            [(0, 0), (1, 0), (0, 1), (1, 1)], ["predicted_attack", "ml_attack"])
        out = {(r.rule_attack, r.ml_attack): r.predicted_attack for r in ml.apply_hybrid(df).collect()}
        self.assertEqual(out, {(0, 0): 0, (1, 0): 1, (0, 1): 1, (1, 1): 1})

    def test_rule_baseline_matches_detector_policy(self):
        df = self.spark.createDataFrame(
            [(62, 500, 0.00001), (64, 500, 0.5), (300, 500, 0.5), (64, 10, 0.5)],
            ["ttl", "total_len", "t_delta"])
        preds = [r.rule_pred for r in ml.rule_predictions(df).collect()]
        self.assertEqual(preds, [1, 0, 1, 1])   # burst+susp-ttl, benign, invalid ttl, invalid len


if __name__ == "__main__":
    unittest.main()
