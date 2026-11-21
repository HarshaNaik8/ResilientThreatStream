# Lambda Architecture Evolution & Mapping to the BDA Lesson Plan (26ECSC404)

All numbers below were **measured on this laptop** (8 cores, ~7 GB RAM, Ubuntu 26.04, Spark 3.5.6 `local[*]`,
Kafka 4.3.1 KRaft, MongoDB 8.0.4). Reproduce with `scripts/run_lambda_demo.sh`.

## 1. Architecture

```
CSV replay -> producer.py (keyed, optional payload)
           -> Kafka  network-records-multi (4 partitions)
           -> Spark Structured Streaming  ── SPEED LAYER ──────────────┐
                 rules (metadata)  OR  MLlib PCA+RandomForest (payload) │
                 foreachBatch dual-write:                               │
                   ├─ MongoDB  threat_alerts / batch_metrics   (HOT)    │
                   └─ Parquet lake  events/run_id=/protocol=   (COLD)   │
Parquet lake -> batch_analytics.py (Spark SQL) ── BATCH LAYER           │
           -> MongoDB historical_threat_rollups  ── SERVING LAYER ──────┤
Streamlit SOC dashboard  <── alerts + metrics (speed) + rollups (batch) ┘
scripts/backup_manager.py  -> mongodump.gz + checkpoint tar.gz, 7-day rotation, verification
```

## 2. Bottleneck results

| # | Bottleneck | Change | Measured result |
|---|-----------|--------|-----------------|
| A | Single store, no backup | Dual-write to Parquet (Snappy, partitioned `run_id/protocol`) | 30,000 streamed events = 30,000 lake rows; CSV 3.7 MB vs Parquet 0.96 MB (**3.98x**), 1-column scan 1.54 s vs 0.14 s |
| B | 1 partition | 4 partitions, `flow` key, `spark.sql.shuffle.partitions=8` | Producer spread 7,565/7,540/7,550/7,345 (even). Spark ingest of 420k metadata records with lake dual-write: **9,635 rec/s (1 partition) -> 12,889 rec/s (4 partitions), +34 %**. The 20,000 rec/s target was **not** reached on this 8-core/7 GB laptop. |
| C | 1,500 payload dims unused | `ml_payload_detector.py`: PCA(k=32) + RandomForest(60 trees, depth 12) + metadata | See table 3 |
| D | No batch layer | `batch_analytics.py` (tumbling + sliding windows, protocol/entropy/attack-family/TTL-heatmap rollups) | 46 rollup docs from 30,000 lake events in 6.2 s |
| E | No DR | `scripts/backup_manager.py` (mongodump `--gzip`, checkpoint tar.gz, SHA-256 manifest, `mongorestore --dryRun`, 7-day rotation) | Snapshot created + verified OK; corruption/rotation/restore covered by tests |

### 3. Detection quality (labels used only for evaluation)

Streaming run `lambda-hybrid-30k`: a **held-out 30,000-record random sample** (seed 2024) of the full dataset, replayed
through Kafka and scored in Spark. The model was trained on a *different* 10,000-row sample (seed 42; ~0.7 % expected
row overlap, negligible).

| Detector | Precision | Recall | F1 | Accuracy | FPR |
|----------|-----------|--------|----|----------|-----|
| Baseline rules (same stream) | 0.9844 | 0.6769 | 0.8022 | 0.7516 | 0.0311 |
| **Hybrid rules OR ML** (same stream) | 0.9830 | **0.9984** | **0.9906** | 0.9860 | 0.0503 |

Offline held-out split of the training sample (`docs/ml_benchmark.json`, 1,954 test rows): rules F1 0.8117, **ML-only F1 0.9962
(FPR 0.0179)**, hybrid F1 0.9904 (FPR 0.0516). The hybrid raises recall at the cost of FPR because rule false positives are
unioned with ML ones; **ML-only had the best F1 offline** - choose the hybrid when catching every volumetric signature matters
more than FPR. Per-family recall (rules -> ML): Infiltration 0 -> 0.993, SSH-Patator 0.07 -> 1.0, FTP-Patator 0.16 -> 1.0,
Web Brute Force 0 -> 1.0, Web XSS 0 -> 1.0, Bot 0 -> 0.8 (only 5 test samples for Bot/XSS: treat as indicative).

**Caveats (do not over-claim):** (1) PCA k=32 explains **74.2 %** of variance, not 95 %; k=128 explains 81.9 % with no F1 gain
(`docs/ml_benchmark_pca128.json`) - payload bytes are high-entropy, so 95 % would need far more components. (2) The streaming
numbers are on a 30k sample, **not** a re-run of the 1.41M-record full experiment (the earlier verified baseline - P 98.28 %,
R 67.67 %, F1 80.15 % - remains the full-scale reference). (3) CIC-IDS2017 attack families are highly separable by payload
signatures; results on live traffic will be lower. (4) The `event_time` axis is Kafka ingestion time (replay wall-clock).

## 3. Course concept mapping (Lesson Plan units -> this project)

| Unit / topic | Where applied | Interpretation |
|--------------|---------------|----------------|
| U1.1 Big-data characteristics (3V), types of data, analytics life cycle | 4.9 GB / 1.41 M records (volume), replay at 10^3-10^4 rec/s (velocity), semi-structured JSON + 1,500 raw bytes (variety) | The pipeline phases follow the life cycle: acquire (Kafka) -> prepare (schema/corrupt-record capture) -> analyse (rules + MLlib) -> visualise (dashboard) -> act (alerts) |
| U1.2 NoSQL document stores, **sharding & replication** (PI 1.4.2.1) | MongoDB `threat_alerts` (deterministic `_id = topic:partition:offset`, upserts = idempotent), `historical_threat_rollups`, indexes on run/offset | Hot store holds only alerts + rollups. Implemented as 2 shards x 3 replicas behind `mongos` (hashed `_id` shard key; see [SHARDING_AND_BACKUP_ARCHITECTURE.md](SHARDING_AND_BACKUP_ARCHITECTURE.md)) plus snapshot backup/restore and lake recovery; Kafka's 4 partitions are the same partition-for-parallelism idea |
| U1.2 On-disk vs in-memory storage; file formats / **RCFile vs Parquet** (PI 2.2.4.1) | Parquet-Snappy cold tier vs CSV benchmark (3.98x smaller, ~11x faster column scan); Spark `cache()` for in-memory reuse of each micro-batch | Columnar layout + column pruning is why analytical scans over 1 column beat row CSV |
| U1.3 Parallel/distributed processing, MapReduce, Spark | `groupBy` aggregations (map -> shuffle -> reduce), `spark.sql.shuffle.partitions=8`, per-partition Mongo writers (`foreachPartition`), Random Forest/PCA distributed over partitions | Scale-out measured: 1 -> 4 partitions = +34 % ingest throughput (PI 2.2.1.1 throughput vs partitioning) |
| U2.4 Batch vs stream; **Lambda** | Speed layer (Structured Streaming) + batch layer (Spark SQL over lake) + serving layer (Mongo rollups) | Streaming gives low-latency approximate views; the batch layer recomputes exact history from the immutable master dataset |
| U2.4 Sources/sinks, immutable streams, stateless vs stateful | Source: Kafka; sinks: Mongo + Parquet (dual `foreachBatch` sink); append-only lake; rule detector is **stateless**, window aggregations are **stateful** | Immutable events + deterministic keys make re-processing safe (idempotent upserts) |
| U2.4 **Tumbling & sliding windows** (PI 3.3.2.1) | `q_tumbling` / `q_sliding` in `batch_analytics.py`, plotted together in the dashboard | Tumbling = exact, non-overlapping, coarser latency; sliding = overlapping smoother trend (each event in window/slide buckets). Choose by accuracy-vs-latency need |
| U2.5-6 Hive/Pig style analysis, HQL | Spark SQL (HiveQL-compatible) queries over Parquet; `window()` GROUP BY | Same declarative model as HQL on RCFile/Parquet |
| Visualisation (CO5, PI 5.2.1.1) | Dashboard tabs: batch trends, entropy distribution, TTL heatmap, per-family detection, DR health | Each chart is traceable to a query in `batch_analytics.py` |

CO coverage: CO1 (issues: skew, single point of failure, leakage), CO2 (storage efficiency: Parquet vs CSV, hot/cold tiers), CO3
(stream tools: Kafka + Structured Streaming), CO4 (real-time model: hybrid detector), CO5 (visualisation).

## 4. Interpretation guide for the dashboard

* **Tumbling vs sliding chart**: bars (non-overlapping) are exact per-window counts; the line (overlapping) hides short spikes less.
* **Entropy distribution**: encrypted/compressed or random-fill payloads concentrate at high entropy; zero-padded text protocols at low.
* **Detection by attack family**: contrast `detection_rate` (final hybrid) with `rule_only_rate` - the gap is the value of payload ML.
* **Kafka lag** = log-end offset - checkpoint offset (Structured Streaming does not commit to consumer groups); 0 means caught up.
* **Partition key trade-off**: `--key-by protocol` keeps per-protocol order but only ~3 keys -> hot partitions; `flow` balances load.

## 5. Zero-leakage controls (tested)

`test_ml_payload.py::test_label_is_not_a_model_input` asserts the pipeline's inputs exclude `label`/`is_attack`;
`test_inference_does_not_read_label` scores a frame with `label` dropped. `label` is only the training target and the
post-prediction evaluation column.
