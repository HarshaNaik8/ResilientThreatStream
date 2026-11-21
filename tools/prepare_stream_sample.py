
import argparse
import os
import random


def prepare_sample(input_path, output_path, num_rows, seed=42):
    """
    Randomly sample records from a large CSV using reservoir sampling,
    shuffle the selected records, and save them to a new CSV file.
    The original dataset remains unchanged.
    """

    if num_rows <= 0:
        raise ValueError("Number of rows must be greater than zero.")

    if not os.path.isfile(input_path):
        raise FileNotFoundError(
            f"Dataset not found: {input_path}"
        )

    random_generator = random.Random(seed)
    reservoir = []

    print("Starting dataset sampling...")
    print(f"Input file: {input_path}")
    print(f"Requested sample size: {num_rows:,}")

    # Read and preserve the CSV header.
    with open(input_path, "r", encoding="utf-8-sig", newline="") as file:
        header = file.readline()

        if not header:
            raise ValueError("The input CSV is empty.")

        total_rows = 0

        # Reservoir sampling: bounded-memory random selection.
        for line in file:
            total_rows += 1

            if len(reservoir) < num_rows:
                reservoir.append(line)
            else:
                random_index = random_generator.randrange(total_rows)

                if random_index < num_rows:
                    reservoir[random_index] = line

            if total_rows % 100_000 == 0:
                print(
                    f"Scanned {total_rows:,} rows; "
                    f"sample contains {len(reservoir):,} rows."
                )

    if total_rows == 0:
        raise ValueError("The input CSV contains no data rows.")

    # Shuffle the selected records to reduce ordering effects.
    random_generator.shuffle(reservoir)

    # Create the output directory if necessary.
    output_directory = os.path.dirname(
        os.path.abspath(output_path)
    )
    os.makedirs(output_directory, exist_ok=True)

    # Write the header and sampled records.
    with open(
        output_path, "w", encoding="utf-8", newline=""
    ) as output_file:
        output_file.write(header)
        output_file.writelines(reservoir)

    print("\nSampling completed successfully!")
    print(f"Total rows scanned: {total_rows:,}")
    print(f"Rows selected: {len(reservoir):,}")
    print(f"Output file: {output_path}")
    print("Original dataset was not modified.")


def main():
    parser = argparse.ArgumentParser(
        description="Prepare a random sample from a large network dataset."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the original CSV dataset."
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path where the sampled CSV will be saved."
    )

    parser.add_argument(
        "--rows",
        type=int,
        default=10_000,
        help="Number of records to sample (default: 10000)."
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible sampling."
    )

    args = parser.parse_args()

    try:
        prepare_sample(
            input_path=args.input,
            output_path=args.output,
            num_rows=args.rows,
            seed=args.seed
        )
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
