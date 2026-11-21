# Dataset Information: CIC-IDS2017 Network Threat Stream

This directory is designated for streaming data inputs used by the **Real-Time Network Threat Analytics Pipeline**.

> [!NOTE]
> Large raw CSV files (`Payload_data_CICIDS2017.csv` at ~4.91 GB and `stream_sample_10k.csv` at ~34.9 MB) are excluded from version control via `.gitignore` to comply with Git repository best practices and GitHub file size limits.

---

## 1. Dataset Overview

The benchmark evaluation uses the **CIC-IDS-2017** (Canadian Institute for Cybersecurity) payload-level intrusion dataset:
- **Total Dataset Size:** 4.91 GB (~4.57 GiB)
- **Total Ingestion Records:** 1,410,255 network records
- **Total Feature Columns:** 1,505 columns
- **Ground-Truth Attack Records:** 1,048,147 (74.32%)
- **Ground-Truth Benign Records:** 362,108 (25.68%)

### Feature Dimensions:
- **5 Flow & Header Attributes:**
  - `protocol` (Transport protocol: TCP = 6, UDP = 17, ICMP = 1)
  - `total_len` (Total packet / IP payload length in bytes)
  - `ttl` (Time to Live)
  - `t_delta` (Inter-arrival time delta between consecutive flows)
  - `label` (Ground-truth classification: `0` for Benign, `1` for Attack/Intrusion)
- **1,500 Raw Payload Byte Attributes:**
  - `payload_byte_0` through `payload_byte_1499` (Integer byte representations `0-255` capturing deep packet byte patterns, protocol handshakes, and attack payloads).

---

## 2. Ingestion & Replay Architecture

This pipeline is designed as a **high-throughput historical replay stream**:
1. The **Python Kafka Producer** (`producer.py`) reads network flow records sequentially from the dataset.
2. Flow records are serialized into JSON and published to Apache Kafka (`network-records-full-run` or development topic) with microsecond event timestamps.
3. **Apache Spark Structured Streaming** (`spark_consumer.py`) ingests from Kafka in streaming micro-batches, deserializes the JSON records, enforces schema validation, computes heuristic threat indicators, and persists enriched alerts and batch summaries into MongoDB.

---

## 3. Dataset Setup Instructions

To reproduce local replay runs:
1. Place the full CSV file (`Payload_data_CICIDS2017.csv`) in the parent course project directory or configure the path in `producer.py`:
   ```bash
   python producer.py --csv ../Payload_data_CICIDS2017.csv --topic network-records-full-run
   ```
2. For fast development or integration testing, generate a 10,000-record sample:
   ```bash
   python tools/prepare_stream_sample.py
   # Produces data/stream_sample_10k.csv
   ```
3. Run the development sample:
   ```bash
   python producer.py --csv data/stream_sample_10k.csv --topic network-records --max-records 10000
   ```
