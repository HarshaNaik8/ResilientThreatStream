
import csv
import os

FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "Payload_data_CICIDS2017.csv"
)

print("File exists:", os.path.exists(FILE_PATH))

if os.path.exists(FILE_PATH):
    print("File size:", round(os.path.getsize(FILE_PATH) / (1024**3), 2), "GiB")

    with open(FILE_PATH, "r", encoding="utf-8-sig",
              errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, [])

        print("\nTOTAL COLUMNS:", len(header))
        print("\nFIRST 10 COLUMNS:")
        print(header[:10])

        print("\nLAST 30 COLUMNS:")
        print(header[-30:])

        keywords = [
            "label", "class", "attack", "time", "flow",
            "source", "destination", "src", "dst", "protocol"
        ]

        print("\nPOSSIBLE IMPORTANT COLUMNS:")
        print([
            c for c in header
            if any(k in c.lower() for k in keywords)
        ])

        print("\nFIRST RECORD: NON-PAYLOAD FIELDS ONLY")
        row = next(reader, [])
        for col, value in zip(header, row):
            if not col.lower().startswith("payload_byte_"):
                print(f"{col}: {value[:80]}")

    print("\nInspection completed.")
