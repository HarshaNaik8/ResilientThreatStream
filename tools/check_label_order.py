
import csv
import os

FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "Payload_data_CICIDS2017.csv"
)

POSITIONS = [1, 10000, 100000, 500000, 1000000, 1400000]

print("Checking labels at selected row positions...")

with open(
    FILE_PATH,
    "r",
    encoding="utf-8-sig",
    errors="replace",
    newline=""
) as f:
    reader = csv.DictReader(f)

    targets = set(POSITIONS)
    row_number = 0

    for row in reader:
        row_number += 1

        if row_number in targets:
            print(
                f"Row {row_number:,}: "
                f"label={row.get('label')}, "
                f"protocol={row.get('protocol')}"
            )

        if row_number >= max(POSITIONS):
            break

print("Finished.")
