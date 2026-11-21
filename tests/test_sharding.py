"""Tests for the sharding / replication design (pure logic + live checks when the cluster is up)."""
import socket
import unittest

from scripts import shard_setup as ss
from scripts.shard_demo import shards_touched


def mongos_up() -> bool:
    try:
        socket.create_connection((ss.HOST, ss.MONGOS_PORT), timeout=0.5).close()
        return True
    except OSError:
        return False


class ReplSetConfigTests(unittest.TestCase):
    def test_each_shard_has_three_data_bearing_replicas(self):
        cfg = ss.replset_config("shard1", ss.REPLSETS["shard1"])
        self.assertEqual(cfg["_id"], "shard1")
        self.assertEqual(len(cfg["members"]), 3)
        self.assertFalse([m for m in cfg["members"] if m.get("arbiterOnly")])
        self.assertEqual(len({m["host"] for m in cfg["members"]}), 3)
        self.assertNotIn("configsvr", cfg)

    def test_config_server_flag(self):
        self.assertTrue(ss.replset_config("cfg", ss.REPLSETS["cfg"])["configsvr"])

    def test_majority_survives_one_failure(self):
        for name in ("shard1", "shard2"):
            n = len(ss.REPLSETS[name]["members"])
            self.assertGreaterEqual(n - 1, n // 2 + 1)      # 2 of 3 voters remain => election possible

    def test_ports_are_unique_and_do_not_clash_with_standalone(self):
        ports = [p for spec in ss.REPLSETS.values() for p, _k in spec["members"]] + [ss.MONGOS_PORT]
        self.assertEqual(len(ports), len(set(ports)))
        self.assertNotIn(27017, ports)


class ShardKeyDesignTests(unittest.TestCase):
    def test_alerts_use_hashed_id_for_even_writes(self):
        keys = dict(ss.SHARDED_COLLECTIONS)
        self.assertEqual(keys["threat_alerts"], {"_id": "hashed"})
        self.assertEqual(keys["historical_threat_rollups"], {"run_id": 1, "rollup_type": 1})

    def test_balance_ratio(self):
        self.assertEqual(ss.balance_ratio({"a": 100, "b": 100}), 1.0)
        self.assertEqual(ss.balance_ratio({"a": 150, "b": 100}), 1.5)
        self.assertEqual(ss.balance_ratio({"a": 5, "b": 0}), float("inf"))
        self.assertEqual(ss.balance_ratio({"a": 5}), 1.0)

    def test_shards_touched(self):
        self.assertEqual(shards_touched({"queryPlanner": {"winningPlan": {"shards": [{}, {}]}}}), 2)
        self.assertEqual(shards_touched({"queryPlanner": {"winningPlan": {"stage": "SINGLE_SHARD"}}}), 1)


@unittest.skipUnless(mongos_up(), "sharded cluster (mongos :27019) not running")
class LiveClusterTests(unittest.TestCase):
    def test_two_shards_registered_and_collections_sharded(self):
        from pymongo import MongoClient
        c = MongoClient(ss.HOST, ss.MONGOS_PORT)
        names = {s["_id"] for s in c.admin.command("listShards")["shards"]}
        self.assertEqual(names, {"shard1", "shard2"})
        colls = {d["_id"] for d in c.config.collections.find({"_id": {"$regex": "^" + ss.DB_NAME}})}
        for coll, _ in ss.SHARDED_COLLECTIONS:
            self.assertIn(f"{ss.DB_NAME}.{coll}", colls)
        c.close()


if __name__ == "__main__":
    unittest.main()
