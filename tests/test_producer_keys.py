"""Tests for keyed Kafka routing and payload extraction in producer.py (Phase 2)."""
import unittest
from collections import Counter

from producer import PAYLOAD_COLUMNS, compute_partition_key, extract_payload


def kafka_partition(key: bytes, n: int) -> int:
    """Same hash Kafka's default partitioner uses (murmur2 & 0x7fffffff) % n."""
    from kafka.partitioner.default import murmur2
    return (murmur2(key) & 0x7FFFFFFF) % n


class PartitionKeyTests(unittest.TestCase):
    def msg(self, proto="tcp", ttl=62, ln=500):
        return {"protocol": proto, "ttl": ttl, "total_len": ln}

    def test_none_strategy_has_no_key(self):
        self.assertIsNone(compute_partition_key(self.msg(), 1, "none"))

    def test_protocol_strategy_is_stable_per_protocol(self):
        a = compute_partition_key(self.msg("tcp"), 1, "protocol")
        b = compute_partition_key(self.msg("tcp", ttl=1), 999, "protocol")
        self.assertEqual(a, b)
        self.assertNotEqual(a, compute_partition_key(self.msg("udp"), 1, "protocol"))

    def test_flow_strategy_is_deterministic_and_bytes(self):
        k = compute_partition_key(self.msg(), 5, "flow")
        self.assertIsInstance(k, bytes)
        self.assertEqual(k, compute_partition_key(self.msg(), 5, "flow"))

    def test_unknown_strategy_raises(self):
        with self.assertRaises(ValueError):
            compute_partition_key(self.msg(), 1, "bogus")

    def test_flow_key_spreads_evenly_over_four_partitions(self):
        counts = Counter(kafka_partition(compute_partition_key(self.msg(), i, "flow"), 4) for i in range(8000))
        self.assertEqual(set(counts), {0, 1, 2, 3})
        for c in counts.values():
            self.assertGreater(c, 8000 * 0.20)          # within ~5pp of the ideal 25%
            self.assertLess(c, 8000 * 0.30)

    def test_protocol_key_is_skewed_demonstrating_hot_partitions(self):
        parts = {kafka_partition(compute_partition_key(self.msg(p), 0, "protocol"), 4) for p in ("tcp", "udp", "icmp")}
        self.assertLessEqual(len(parts), 3)             # at most 3 keys => at most 3 of 4 partitions used


class PayloadExtractionTests(unittest.TestCase):
    def test_extracts_1500_ints_with_blanks_as_none(self):
        row = {c: str(i % 256) for i, c in enumerate(PAYLOAD_COLUMNS)}
        row["payload_byte_3"] = ""
        p = extract_payload(row)
        self.assertEqual(len(p), 1500)
        self.assertEqual(p[0], 0)
        self.assertEqual(p[1], 1)
        self.assertIsNone(p[2])

    def test_missing_columns_yield_none(self):
        self.assertEqual(extract_payload({}), [None] * 1500)


if __name__ == "__main__":
    unittest.main()
