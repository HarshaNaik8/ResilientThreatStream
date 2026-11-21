
import csv
from collections import Counter
import os

FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "Payload_data_CICIDS2017.csv"
)

label_counts = Counter()
total_rows = 0
invalid_rows = 0

print("Scanning dataset labels. This may take some time...")

with open(
    FILE_PATH,
    "r",
    encoding="utf-8-sig",
    errors="replace",
    newline=""
) as f:
    reader = csv.DictReader(f)

    for row in reader:
        total_rows += 1
        label = (row.get("label") or "").strip()

        if label:
            label_counts[label] += 1
        else:
            invalid_rows += 1

        if total_rows % 1_000_000 == 0:
            print(f"Scanned {total_rows:,} rows...")

print("\n========== LABEL SUMMARY ==========")
print("Total data rows:", f"{total_rows:,}")
print("Rows without labels:", f"{invalid_rows:,}")
print("\nRecords per label:")

for label, count in label_counts.most_common():
    print(f"{label}: {count:,} ({count / max(total_rows, 1) * 100:.2f}%)")

print("\nDone.")
