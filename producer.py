import argparse
import csv
import json
import os
import sys
import time
from kafka import KafkaProducer
from kafka.errors import KafkaError


def safe_int(value):
    """Safely convert value to integer or None."""
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    try:
        return int(val_str)
    except ValueError:
        try:
            return int(float(val_str))
        except ValueError:
            return None


def safe_float(value):
    """Safely convert value to float or None."""
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    try:
        return float(val_str)
    except ValueError:
        return None


def safe_str(value, default="unknown"):
    """Safely convert value to string, stripped, or default."""
    if value is None:
        return default
    val_str = str(value).strip()
    return val_str if val_str else default


KEY_STRATEGIES = ("flow", "protocol", "none")
PAYLOAD_COLUMNS = [f"payload_byte_{i}" for i in range(1, 1501)]


def compute_partition_key(message, seq, strategy="flow"):
    """
    Build the Kafka partition key (bytes, or None for sticky/round-robin routing).

    * flow     - hash-friendly key from flow metadata + sequence; near-uniform
                 spread over partitions (default, avoids skew).
    * protocol - all records of one protocol share a partition (preserves
                 per-protocol ordering, but only ~3 distinct keys => skew).
    * none     - no key; the client's default partitioner spreads records.
    """
    if strategy == "none":
        return None
    if strategy == "protocol":
        return str(message.get("protocol") or "unknown").encode("utf-8")
    if strategy == "flow":
        return (
            f"{message.get('protocol')}|{message.get('ttl')}|"
            f"{message.get('total_len')}|{seq}"
        ).encode("utf-8")
    raise ValueError(f"Unknown key strategy: {strategy!r} (choose from {KEY_STRATEGIES})")


def extract_payload(row):
    """Return the 1,500 payload bytes of a CSV row as a list of ints (None for blanks)."""
    return [safe_int(row.get(c)) for c in PAYLOAD_COLUMNS]


def main():
    p = argparse.ArgumentParser(
        description="Replay historical network CSV records into a Kafka topic as JSON."
    )
    p.add_argument(
        "--input",
        default="data/stream_sample_10k.csv",
        help="Path to CSV dataset or sample file (default: data/stream_sample_10k.csv)",
    )
    p.add_argument(
        "--topic",
        default="network-records",
        help="Kafka topic to publish records to (default: network-records)",
    )
    p.add_argument(
        "--bootstrap",
        default="localhost:9092",
        help="Kafka bootstrap server(s) comma-separated (default: localhost:9092)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.005,
        help="Seconds to pause between records; 0 means no intentional delay (default: 0.005)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of data records to publish; 0 means all rows (default: 0)",
    )
    p.add_argument(
        "--sync",
        action="store_true",
        help="Synchronously wait for delivery acknowledgement on every record",
    )
    p.add_argument(
        "--key-by",
        default="flow",
        choices=list(KEY_STRATEGIES),
        help="Partition-key strategy: flow (balanced, default), protocol, none",
    )
    p.add_argument(
        "--include-payload",
        action="store_true",
        help="Also publish the 1,500 payload bytes (needed by the ML hybrid detector)",
    )
    args = p.parse_args()

    # Resolve input file path
    input_path = args.input
    if not os.path.exists(input_path):
        script_relative = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), input_path
        )
        if os.path.exists(script_relative):
            input_path = script_relative

    if not os.path.isfile(input_path):
        print(
            f"[Error] Input dataset file not found: {args.input}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Initialize KafkaProducer
    print(f"[Producer] Connecting to Kafka broker(s) at {args.bootstrap}...")
    try:
        producer = KafkaProducer(
            bootstrap_servers=args.bootstrap.split(","),
            value_serializer=lambda obj: json.dumps(obj, separators=(",", ":")).encode("utf-8"),
            acks="all",
            linger_ms=10,
            batch_size=131072,
            retries=5,
            max_request_size=8 * 1024 * 1024,
            request_timeout_ms=10000,
        )
        # Verify cluster accessibility
        partitions = producer.partitions_for(args.topic)
        if partitions is None:
            print(f"[Producer] Note: Topic '{args.topic}' metadata not found or being auto-created.")
        else:
            print(f"[Producer] Connected to topic '{args.topic}' with partitions: {partitions}")
    except Exception as exc:
        print(f"[Error] Failed to connect to Kafka broker at {args.bootstrap}: {exc}", file=sys.stderr)
        sys.exit(1)

    records_read = 0
    records_delivered = 0
    records_failed = 0
    delivery_errors = []

    def on_send_success(record_metadata):
        nonlocal records_delivered
        records_delivered += 1

    def on_send_error(exception):
        nonlocal records_failed
        records_failed += 1
        if len(delivery_errors) < 5:
            delivery_errors.append(str(exception))

    print(f"[Producer] Starting replay from '{input_path}' into topic '{args.topic}'...")
    if args.limit > 0:
        print(f"[Producer] Limit configured: {args.limit:,} records")
    if args.delay > 0:
        print(f"[Producer] Pacing delay configured: {args.delay} seconds/record")

    start_time = time.time()
    try:
        with open(input_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records_read += 1

                # Extract only metadata fields for the streaming pipeline.
                # Exclude high-dimensional payload-byte fields at this stage.
                # Ground-truth 'label' is preserved for evaluation only.
                message = {
                    "ttl": safe_int(row.get("ttl")),
                    "total_len": safe_int(row.get("total_len")),
                    "protocol": safe_str(row.get("protocol"), default="unknown"),
                    "t_delta": safe_float(row.get("t_delta")),
                    "label": safe_str(row.get("label"), default="UNKNOWN"),
                }

                if args.include_payload:
                    message["payload"] = extract_payload(row)

                try:
                    key = compute_partition_key(message, records_read, args.key_by)
                    future = producer.send(args.topic, value=message, key=key)
                    if args.sync:
                        future.get(timeout=10)
                        records_delivered += 1
                    else:
                        future.add_callback(on_send_success)
                        future.add_errback(on_send_error)
                except Exception as exc:
                    records_failed += 1
                    if len(delivery_errors) < 5:
                        delivery_errors.append(str(exc))

                if records_read % 1000 == 0:
                    if not args.sync:
                        producer.flush()
                    print(f"[Producer] Processed {records_read:,} records (acknowledged: {records_delivered:,})...")

                if args.delay > 0:
                    time.sleep(args.delay)

                if args.limit and records_read >= args.limit:
                    break

        print("[Producer] Flushing pending messages to Kafka...")
        producer.flush()
    except KeyboardInterrupt:
        print("\n[Producer] Replay interrupted by user. Flushing buffered records...")
        producer.flush()
    finally:
        producer.close()
        end_time = time.time()

    elapsed_time = end_time - start_time
    effective_throughput = (records_delivered / elapsed_time) if elapsed_time > 0 else 0.0

    print("\n" + "=" * 60)
    print("PRODUCER REPLAY SUMMARY")
    print("=" * 60)
    print(f"Input file:               {input_path}")
    print(f"Target topic:             {args.topic}")
    print(f"Bootstrap servers:        {args.bootstrap}")
    print(f"Configured limit:         {args.limit if args.limit > 0 else 'All rows'}")
    print(f"Configured delay:         {args.delay} s")
    print(f"Synchronous mode:         {args.sync}")
    print(f"Partition key strategy:   {args.key_by}")
    print(f"Payload included:         {args.include_payload}")
    print("-" * 60)
    print(f"Records read from CSV:    {records_read:,}")
    print(f"Records acknowledged:     {records_delivered:,}")
    print(f"Records failed:           {records_failed:,}")
    print(f"Elapsed time:             {elapsed_time:.3f} s")
    print(f"Effective throughput:     {effective_throughput:.2f} records/s")
    print("=" * 60)

    if records_failed > 0:
        print("\n[Warning] Some messages failed to deliver. Sample errors:")
        for err in delivery_errors:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
