
import csv
import os
from collections import Counter

FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "Payload_data_CICIDS2017.csv"
)

PAYLOAD_COLUMNS = 1500
SAMPLE_LIMIT = 10000

label_counts = Counter()
protocol_counts = Counter()
invalid_payload_values = 0
empty_payload_values = 0
sample_rows = 0

print("Validating the first 10,000 records...")

with open(
    FILE_PATH,
    "r",
    encoding="utf-8-sig",
    errors="replace",
    newline=""
) as f:
    reader = csv.DictReader(f)

    headers = reader.fieldnames or []
    payload_columns = [
        c for c in headers if c.startswith("payload_byte_")
    ]

    print("Total columns:", len(headers))
    print("Payload-byte columns:", len(payload_columns))
    print("Has label column:", "label" in headers)

    for row in reader:
        sample_rows += 1

        label_counts[(row.get("label") or "").strip()] += 1
        protocol_counts[(row.get("protocol") or "").strip()] += 1

        for col in payload_columns:
            value = (row.get(col) or "").strip()

            if not value:
                empty_payload_values += 1
            else:
                try:
                    number = int(value)
                    if not 0 <= number <= 255:
                        invalid_payload_values += 1
                except ValueError:
                    invalid_payload_values += 1

        if sample_rows >= SAMPLE_LIMIT:
            break

print("\nSample records checked:", sample_rows)
print("Labels in sample:", label_counts)
print("Protocols in sample:", protocol_counts)
print("Empty payload values:", empty_payload_values)
print("Invalid payload values:", invalid_payload_values)
print("Validation completed.")
