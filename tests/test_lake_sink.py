"""Tests for the Parquet data lake sink (tiered storage, Phase 1)."""
import os
import shutil
import tempfile
import unittest
from datetime import datetime

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    ArrayType, DoubleType, IntegerType, LongType, StringType, StructField, StructType, TimestampType,
)

import lake_sink
from lake_sink import (
    LAKE_COLUMNS, build_lake_dataframe, lake_file_count, lake_size_bytes, payload_stats, write_batch_to_lake,
)

SCHEMA = StructType([
    StructField("topic", StringType()), StructField("kafka_partition", IntegerType()),
    StructField("kafka_offset", LongType()), StructField("event_timestamp", TimestampType()),
    StructField("protocol", StringType()), StructField("ttl", IntegerType()),
    StructField("total_len", IntegerType()), StructField("t_delta", DoubleType()),
    StructField("label", StringType()), StructField("predicted_attack", IntegerType()),
    StructField("payload", ArrayType(IntegerType())),
])


class PayloadStatsTests(unittest.TestCase):
    def test_constant_payload_has_zero_entropy(self):
        e, m, nz = payload_stats([7] * 100)
        self.assertEqual(e, 0.0)
        self.assertEqual(m, 7.0)
        self.assertEqual(nz, 100)

    def test_uniform_two_values_is_one_bit(self):
        e, _m, nz = payload_stats([0, 255] * 50)
        self.assertAlmostEqual(e, 1.0, places=6)
        self.assertEqual(nz, 50)

    def test_missing_payload(self):
        self.assertEqual(payload_stats(None), (None, None, None))
        self.assertEqual(payload_stats([]), (None, None, None))
        self.assertEqual(payload_stats([None, None]), (None, None, None))


class LakeWriteReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spark = (SparkSession.builder.master("local[2]").appName("test-lake")
                     .config("spark.sql.shuffle.partitions", "2").config("spark.ui.enabled", "false")
                     .getOrCreate())
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lake_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _df(self, with_payload=True):
        t = datetime(2026, 1, 1, 12, 0, 0)
        rows = [
            ("n", 0, 1, t, "tcp", 62, 40, 0.00001, "DoS Hulk", 1, [0, 255] * 10),
            ("n", 1, 2, t, "TCP ", 128, 500, 0.5, "BENIGN", 0, [5] * 20),
            ("n", 2, 3, t, None, 64, 60, 0.1, "BENIGN", 0, None),
        ]
        df = self.spark.createDataFrame(rows, SCHEMA)
        return df if with_payload else df.drop("payload")

    def test_schema_is_stable_without_payload_or_ml(self):
        out = build_lake_dataframe(self._df(with_payload=False), "r1", 0)
        self.assertEqual(out.columns, LAKE_COLUMNS)
        self.assertTrue(all(r.payload_entropy is None for r in out.collect()))

    def test_protocol_normalised_and_payload_stats(self):
        rows = {r.kafka_offset: r for r in build_lake_dataframe(self._df(), "r1", 0).collect()}
        self.assertEqual(rows[2].protocol, "tcp")       # trimmed + lowercased
        self.assertEqual(rows[3].protocol, "unknown")   # null protocol
        self.assertAlmostEqual(rows[1].payload_entropy, 1.0, places=5)
        self.assertIsNone(rows[3].payload_entropy)

    def test_roundtrip_partitioned_snappy_parquet(self):
        lake = os.path.join(self.tmp, "lake")
        n1 = write_batch_to_lake(self._df(), lake, "runA", 0)
        n2 = write_batch_to_lake(self._df(), lake, "runA", 1)      # append-only
        self.assertEqual((n1, n2), (3, 3))

        events = os.path.join(lake, "events")
        self.assertTrue(os.path.isdir(os.path.join(events, "run_id=runA", "protocol=tcp")))
        self.assertTrue(os.path.isdir(os.path.join(events, "run_id=runA", "protocol=unknown")))
        files = [f for _r, _d, fs in os.walk(events) for f in fs if f.endswith(".parquet")]
        self.assertTrue(files and all("snappy" in f for f in files), files)

        back = self.spark.read.parquet(events)
        self.assertEqual(back.count(), 6)
        self.assertEqual(sorted(back.select("batch_id").distinct().rdd.map(lambda r: r[0]).collect()), [0, 1])
        hulk = back.filter("label = 'DoS Hulk'").collect()
        self.assertEqual(len(hulk), 2)
        self.assertEqual(hulk[0].ttl, 62)
        self.assertEqual(hulk[0].predicted_attack, 1)
        # partition columns survive discovery
        self.assertEqual(back.filter("run_id = 'runA'").count(), 6)

    def test_empty_batch_writes_nothing(self):
        lake = os.path.join(self.tmp, "lake")
        self.assertEqual(write_batch_to_lake(self._df().limit(0), lake, "r", 0), 0)
        self.assertEqual(lake_file_count(lake), 0)

    def test_lake_size_helpers(self):
        lake = os.path.join(self.tmp, "lake")
        self.assertEqual(lake_size_bytes(lake), 0)
        write_batch_to_lake(self._df(), lake, "r", 0)
        self.assertGreater(lake_size_bytes(lake), 0)
        self.assertGreater(lake_file_count(lake), 0)


if __name__ == "__main__":
    unittest.main()
