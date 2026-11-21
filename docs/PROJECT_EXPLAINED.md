# Project Explained (read this first)

Everything here is checked against the code and against measured runs on this laptop (8 cores, 7.5 GB RAM).
Where something is a limitation, it says so.

---

## 1. The project in one paragraph

We replay 1.41 million recorded network packets (CIC-IDS2017) as if they were arriving live. Each packet goes through
**Kafka** (a durable message log split into 4 partitions), is analysed by **Spark Structured Streaming** (fast metadata rules
**OR** a Spark MLlib model that reads the 1,500 payload bytes), and the verdict is written to **two places at once**: a
**sharded, replicated MongoDB** (for the live dashboard) and an **append-only Parquet data lake** (the permanent copy of every event).
A **batch job** later re-analyses the lake, **backups** protect MongoDB, and a **Streamlit dashboard** shows everything.

## 2. What the mentor asked, and the answer

> "The architecture has no protection against data loss / no backup."

The original pipeline had one MongoDB and one copy of everything. Now there are **four independent lines of defence**, each aimed at a
different way of losing data (you can demonstrate every one live, see `DEMO_GUIDE.md`):

| # | Defence | Concept (Lesson Plan U1.2) | Failure it handles |
|---|---------|----------------------------|--------------------|
| 1 | **Sharding + replication**: 2 shards, each a 3-node replica set, behind a `mongos` router | Sharding, replication, *combining sharding and replication* | A database **server dies** (no data lost, automatic failover) and the data set is **split** across shards |
| 2 | **Snapshot backups** (`backup_manager.py`): gzip `mongodump` + Spark checkpoints + lake, SHA-256 verified, 7-day rotation | Backup, recovery, RPO/RTO | The database is **deleted or corrupted** (replicas copy mistakes too) |
| 3 | **Parquet data lake** (the Lambda "master dataset") | Lambda architecture, immutable columnar storage | The database **and every backup** are lost: alerts are rebuilt from the lake |
| 4 | **Spark checkpoints** stored inside every snapshot | Fault-tolerant stream processing | The streaming job restarts without re-reading or skipping Kafka data |

## 3. Why sharding (and why not replication only)

You were asked to choose between them. The honest answer is that they solve **different** problems, so the design uses sharding as the
scaling structure and replication inside each shard (which is also how MongoDB itself requires a production shard to be built).

| Question | Replica set only | Sharded cluster (what we built) |
|----------|------------------|---------------------------------|
| Where do writes go? | One primary takes **all** writes | Writes are **split** across shard primaries (hashed `_id`) |
| How much data fits? | What one machine's disk holds | Capacity grows by adding shards |
| Survives a server crash? | Yes | Yes (each shard is a replica set) |
| Survives `DROP DATABASE` / a bad write? | **No**, the mistake is replicated instantly | **No**, which is why backups and the lake exist |
| Lesson Plan topic | Replication | Sharding, replication, **and their combination** |

Why we chose sharding for this project:
1. The alert collection is the write-heavy, ever-growing part (one document per detected threat; 377,325 stored in the cluster now).
   Sharding is the answer for a collection that outgrows one node; a replica set is not.
2. The pipeline is a **streaming** workload: many parallel Spark writers. A single replica-set primary is a bottleneck by design.
3. It covers more of the syllabus: partitioning by shard key, routing (`mongos`), metadata (config server), *and* replication.
4. It needed **no pipeline code changes**: only `MONGODB_URI` points to the router.

**Honest limitation.** Both shards run on one laptop, so sharding here demonstrates **correct distribution, routing and failover**,
not a throughput gain. Real benefit appears when shards sit on separate machines.

## 4. How the cluster works (plain language)

```
   Spark sink / dashboard / batch job / backup tool
                      |   MONGODB_URI=mongodb://127.0.0.1:27019
                +-----v-----+      +----------------+
                |  mongos   |----->| config server  |  "which shard owns which hash range?"
                |  :27019   |      |  :27100        |
                +--+-----+--+      +----------------+
        +----------+     +-----------+
  +-----v--------+         +---------v----+
  | shard1 (RS)  |         | shard2 (RS)  |      RS = replica set: one PRIMARY, two SECONDARY copies.
  | :27111  :27112 :27113  | :27121 :27122 :27123 |   If the primary dies, the two others vote and elect a new one.
  +--------------+         +--------------+
```

* **Shard key `{_id: "hashed"}` on `threat_alerts`.** `_id` is `topic:partition:offset`, which only grows. With a normal (ranged) key
  every new alert would hit the *newest* shard, creating a hot spot. Hashing spreads them evenly: measured **188,683 vs 188,642** documents
  (max/min = 1.0).
* **Routing (measured).** A lookup by `_id` contacts **1 shard** (targeted); filtering by `run_id` contacts **2** (scatter-gather).
  That trade-off is why `_id` is the key: the pipeline's idempotent upserts are all by `_id`.
* **`historical_threat_rollups` key `{run_id, rollup_type}`**: always queried that way, so reads are targeted. `batch_metrics` is tiny and is not sharded.
* **Replication**: every write is copied (oplog) to the 2 secondaries. **Election**: when a primary is killed, the remaining members elect a new
  one. Measured: **60/60 writes still accepted, worst stall about 10 s, 0 documents lost**.
* **Why 3 data nodes per shard, not 2 + an arbiter?** We tried the arbiter layout (less RAM); with one data node down, reads stalled, so we
  use 3 real copies. All MongoDB processes together (7 cluster nodes, router and the legacy standalone) use about **1.2 GB** of RAM.

## 5. The streaming data flow, step by step

1. `producer.py` reads the CSV and publishes JSON to Kafka topic `network-records-demo` / `-multi` (**4 partitions**, key = hash of the
   flow so load is even: 7,345-7,565 records per partition). `--include-payload` adds the 1,500 bytes.
2. `spark_consumer.py` reads micro-batches (every 2 s, up to 10,000 records) and computes for each packet:
   - **rule verdict** (burst time-delta, suspicious TTL, anomalous length, invalid metadata) and
   - **ML verdict**: `PCA(32)` over the 1,500 bytes + `RandomForest` (Spark MLlib). **Hybrid = rule OR ML.**
   The ground-truth `label` is **never** an input; it is used only afterwards to compute precision/recall (tests assert this).
3. For each micro-batch it writes (a) alerts + batch metrics to **sharded MongoDB** and (b) every event to the **Parquet lake**
   (`data/lake/events/run_id=.../protocol=.../`, Snappy). This **dual write** is what makes scenario C possible.
4. `batch_analytics.py` (Spark SQL over the lake) computes tumbling/sliding-window trends, top protocols, payload-entropy histograms,
   per-attack-family detection and a TTL heatmap, stored in `historical_threat_rollups`.
5. `dashboard.py` reads alerts + metrics (speed layer) and rollups (batch layer) and shows the health of the data tier.

This is the **Lambda architecture**: speed layer (streaming), batch layer (lake + SQL), serving layer (MongoDB).

## 6. The three data-loss scenarios (what happens, why it works)

| Scenario | What we destroy | What brings it back | Measured result (`make data-loss-demo`) |
|----------|-----------------|---------------------|------------------------------------------|
| **A** Node crash | `kill -9` on a shard's primary | **Replication**: election, node re-syncs on restart | 60/60 writes accepted, longest stall 10.2 s, **9,089/9,089 alerts intact** |
| **B** Database deleted | `DROP DATABASE` through mongos | **Snapshot restore** into the re-created sharded layout | 9,139 documents restored in **1.1 s (RTO)**, counts identical |
| **C** DB **and** backups deleted | database + all snapshots | **Rebuild from the Parquet lake** with the same `_id`s | 9,089 alerts re-created in **1.6 s**, identical `_id` set; batch metrics re-aggregated |

* **RPO** (data you could lose): scenario B = up to the backup interval (daily cron: 24 h); scenario C = **0 events**, because the lake is written in the same micro-batch as MongoDB.
* **RTO** (time to recover): seconds at this scale; grows with data volume.
* **What C cannot restore** (stated, not hidden): per-rule reason text of each alert (the lake stores the rule/ML *verdicts*, so recovered alerts say `RULE_ALERT` / `ML_PAYLOAD_ANOMALY`), original batch timestamps, and malformed-record counts. Rollups are recomputed by re-running `batch_analytics.py`.
* **Not covered**: everything is on one machine and one disk. For a real 3-2-1 policy, copy `backups/` and the lake to external or object storage.

## 7. Results you may quote (all measured)

| Item | Value |
|------|-------|
| Baseline heuristic, full 1,410,255 records | Precision 98.28%, **Recall 67.67%**, F1 80.15% (338,843 attacks missed) |
| Hybrid rules + MLlib, same full run (`full-hybrid-cicids2017`) | Precision 98.25%, **Recall 99.85%**, F1 99.04%, FPR 5.15% (TP 1,046,576, FP 18,652, TN 343,456, FN 1,571) |
| Trade-off | ML raises recall, but FPR rises from 3.43% to 5.15% |
| ML caveats | PCA(32) keeps 74.2% of variance (not 95%; k=128 reaches 81.9% with no gain); trained on a 10k sample (about 0.6% overlap with the full run); CIC-IDS2017 attacks are very separable, so live traffic will score lower |
| Kafka 1 -> 4 partitions (420k records, with lake dual-write) | 9,635 -> 12,889 rec/s (+34%); the 20,000 rec/s target was **not** reached on this laptop |
| Parquet vs CSV | 3.98x smaller, about 11x faster single-column scan |
| Tests | 106 unit/integration tests pass (`make test`) |

## 8. Likely mentor questions

* **"Is this really sharding if it is on one laptop?"** Yes, it is a genuine sharded cluster (config server, `mongos`, 2 shard replica sets, hashed shard key, balancer). It proves distribution, routing and failover; throughput scaling needs separate machines.
* **"Why not just a replica set?"** Section 3: it cannot split writes or data, and it still replicates mistakes.
* **"If replicas exist, why also backups?"** A replica copies `DROP DATABASE` within milliseconds. Backups are point-in-time; scenario B shows it.
* **"What if the backups are gone too?"** Scenario C: the lake is the immutable master dataset.
* **"Why hash the `_id`?"** Monotonic keys cause a hot shard (all inserts on one node).
* **"Is the ML leaking labels?"** No: labels are only the training target and the evaluation column; `tests/test_ml_payload.py` checks the model inputs.
* **"What does the lake cost / what does it keep?"** The full 1,410,255-event run is **43 MB** (columnar, Snappy). Per event it keeps the metadata, label, rule/ML verdicts and payload *statistics* (entropy, mean, non-zero count), **not** the 1,500 raw bytes (those stay in the source CSV/Kafka). That is enough to rebuild alerts and metrics and to run all batch analytics.
* **"What is the weakest part?"** Single machine (no off-site copy), 10 s failover stall, FPR 5%, ML trained on a small sample.

## 9. Where things are

| Path | Role |
|------|------|
| `producer.py`, `spark_consumer.py`, `mongo_sink.py`, `lake_sink.py`, `threat_detector.py` | Ingestion, detection, the two sinks |
| `ml_payload_detector.py`, `models/payload_rf/` | MLlib PCA + RandomForest hybrid detector |
| `batch_analytics.py` | Batch layer (Spark SQL on the lake) |
| `scripts/sharded_cluster.sh`, `scripts/shard_setup.py`, `scripts/shard_demo.py` | Build and demonstrate the sharded cluster |
| `scripts/backup_manager.py`, `scripts/dr_drill.py`, `scripts/lake_recovery.py`, `scripts/data_loss_demo.py` | Backup, drill, lake recovery, the three scenarios |
| `scripts/start_services.sh`, `scripts/demo_env.sh`, `scripts/reset_demo.sh` | Start everything / demo environment / clean slate |
| `dashboard.py`, `dashboard_utils.py` | Streamlit SOC dashboard |
| `tests/` | 106 tests |
| `docs/` | This file, `DEMO_GUIDE.md`, architecture references, the PPT |
