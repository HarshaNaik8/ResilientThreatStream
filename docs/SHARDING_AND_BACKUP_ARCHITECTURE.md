# Sharding, Replication & Backup Architecture (Data-Loss Handling)

The original pipeline wrote to **one MongoDB node and kept no other copy** of the data: one disk failure or one wrong
command meant total loss. This layer fixes that with four independent protections. It needs **no change to the streaming
code** - the pipeline already resolves MongoDB through `MONGODB_URI`, so pointing it at the router is the only switch.

Lesson Plan (26ECSC404) mapping: **Unit 1 - Big Data Storage**: *Clusters, NoSQL document stores (MongoDB), Sharding,
Replication, Combining Sharding and Replication*; PI 1.4.2.1 (*NoSQL with sharding/replication, validated with CRUD*).

## 1. Topology (`scripts/sharded_cluster.sh`)

```
                 clients: Spark sink, batch job, dashboard, backup tools
                                  |  MONGODB_URI=mongodb://127.0.0.1:27019
                             +----v----+
                             |  mongos |  :27019  query router (knows which shard holds which chunk)
                             +--+---+--+
              +-----------------+   +-----------------+        config server (replica set "cfg", :27100)
      +-------v--------+                 +--------v-------+      = the chunk map / shard metadata
      | shard1 (RS)    |   horizontal    | shard2 (RS)    |
      | :27111 PRIMARY |   partitioning  | :27121         |
      | :27112 SECOND. |   (sharding)    | :27122 PRIMARY |
      | :27113 SECOND. |                 | :27123 SECOND. |
      +----------------+                 +----------------+
        3 replicas of half the data         3 replicas of the other half
```

* **Sharding** splits the data across two shards -> storage/write scale-out.
* **Replication**: every shard is a 3-member replica set. Each write is copied (oplog) to 2 more nodes; if any node dies the
  other two elect a new primary. **Sharding + replication combined** = scale-out *and* fault tolerance (textbook pattern).
* Resource-aware: 7 `mongod` processes with a 0.25 GB cache each (~2 GB RAM). The standalone `mongod` on `:27017` is left
  untouched and still holds the earlier verified runs.
* *Design note:* a Primary-Secondary-**Arbiter** layout (2 data copies) was tried first. With one data node killed, reads
  through `mongos` stalled ("waiting for replication timed out"), so it was replaced with 3 data-bearing replicas.

## 2. Shard-key decisions

| Collection | Shard key | Reason |
|-----------|-----------|--------|
| `threat_alerts` | `{_id: "hashed"}` | Write-heavy. `_id = topic:partition:offset` increases monotonically, so a *ranged* key would send every insert to one "hot" shard; hashing spreads writes evenly. The sink's idempotent `ReplaceOne({_id}, upsert=True)` is a targeted single-shard operation. |
| `historical_threat_rollups` | `{run_id: 1, rollup_type: 1}` | Always read as "rollups of run X, type Y" -> targeted range queries; low write rate. |
| `batch_metrics` | not sharded | Tiny; lives on the primary shard. Sharding it only adds routing overhead. |

Trade-off: queries on `run_id` alone against `threat_alerts` are scatter-gather (both shards are asked); `_id` lookups are targeted.

## 3. Measured evidence (`python -m scripts.shard_demo --failover`, this laptop)

| Check | Result |
|-------|--------|
| Load through mongos (idempotent upserts) | 200,000 alerts in 26.8 s |
| Distribution (hashed `_id`) | shard2 188,683 / shard1 188,642 -> **max/min = 1.0** |
| Routing, `_id` equality | **1 shard** contacted (targeted) |
| Routing, `run_id` filter | **2 shards** contacted (scatter-gather) |
| Primary of shard1 stepped down under write load | 10,104 probe writes in 25 s, **0 errors**, worst stall 10.0 s (election) |

Both shards share one laptop, so this shows correct **distribution, routing and failover**, not a throughput gain.

## 4. Four layers of protection and the failure each one handles

| Layer | Mechanism | Failure it handles | Demonstrated by |
|-------|-----------|--------------------|-----------------|
| 1. Replication | 3 replicas per shard, automatic election | A database **server crashes** | Scenario A |
| 2. Snapshot backup | `scripts/backup_manager.py`: `mongodump --gzip` + checkpoints + Parquet lake, SHA-256 manifest, verification, 7-day rotation | Database **deleted/corrupted** (operator error, bad write, disk loss) | Scenario B |
| 3. Parquet data lake | Append-only, immutable copy of **every** event (Lambda master dataset) | **Database and backups both lost** | Scenario C (`scripts/lake_recovery.py`) |
| 4. Kafka offsets in checkpoints | Spark checkpoint archived in every snapshot | Streaming job restarts without re-reading or skipping data | snapshot contents |

### Measured by `python -m scripts.data_loss_demo` (run `demo-run`, 12,000 events, 9,089 alerts)

| Scenario | What is destroyed | Recovery | Measured result |
|----------|-------------------|----------|-----------------|
| A | `kill -9` on shard1's **primary** `mongod` | automatic election | 60/60 writes still accepted, longest stall 9.6 s, **9,089 / 9,089 alerts intact**, dead node rejoins and re-syncs |
| B | the **whole database** is dropped | verified snapshot, `mongorestore` into the re-created sharded layout | 9,135 documents restored in **0.9 s (RTO)**, counts **identical** |
| C | database **and every snapshot** deleted | alerts + batch metrics rebuilt from the Parquet lake | 9,089 alerts with the **same `_id`s** in 1.1 s; batch metrics re-aggregated **identical** to the live values; rollups recomputed with `batch_analytics.py` |

Recovery objectives
* **RPO** = backup interval (daily cron: <= 24 h) for scenario B; **0 events** for scenario C, because the lake is written
  in the same micro-batch as MongoDB (dual write).
* **RTO** measured above (seconds at demo scale; grows with data volume).
* `python -m scripts.dr_drill --lake-dir data/lake` repeats backup -> verify -> restore-to-scratch -> compare and prints RPO/RTO inputs.

What scenario C cannot restore (stated explicitly): the per-rule reason breakdown of an alert (the lake stores the rule/ML
*verdicts*, so recovered alerts say `RULE_ALERT` / `ML_PAYLOAD_ANOMALY`), original batch timestamps, and malformed-record counts.

Not covered: an off-machine copy (`backups/` and the lake live on the same disk; copy them to external or object storage
for a true 3-2-1 policy) and point-in-time recovery between snapshots.

## 5. Operating it

```bash
make services           # standalone mongod, sharded cluster, Kafka + topics
make shards-status      # members, roles, documents per shard
make shard-demo         # distribution / routing / primary failover evidence
make backup && make drill
make data-loss-demo     # the three failure scenarios above
make shards-down        # data persists in ~/bigdata-tools/shard-cluster
```
