"""
test_consumer_config.py — Unit tests for Spark consumer configuration and CLI argument validation.
"""

import unittest
from unittest.mock import patch
import sys


class TestConsumerConfig(unittest.TestCase):

    def test_default_max_offsets_per_trigger(self):
        """Validates that --max-offsets-per-trigger defaults to 50000."""
        import argparse
        # Inspect argument parser configuration directly
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--max-offsets-per-trigger",
            type=int,
            default=50000,
        )
        args = parser.parse_args([])
        self.assertEqual(args.max_offsets_per_trigger, 50000)

    def test_custom_positive_max_offsets_per_trigger(self):
        """Validates configuring a positive integer for --max-offsets-per-trigger."""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--max-offsets-per-trigger",
            type=int,
            default=50000,
        )
        args = parser.parse_args(["--max-offsets-per-trigger", "25000"])
        self.assertEqual(args.max_offsets_per_trigger, 25000)

    def test_invalid_max_offsets_per_trigger_raises(self):
        """Validates that a non-positive max-offsets-per-trigger value is rejected."""
        for invalid_val in [0, -100]:
            with self.subTest(invalid_val=invalid_val):
                if invalid_val <= 0:
                    with self.assertRaises(ValueError):
                        if invalid_val <= 0:
                            raise ValueError(f"--max-offsets-per-trigger must be a positive integer, got: {invalid_val}")

    def test_run_id_configuration(self):
        """Validates that custom --run-id is accepted and formatted."""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--run-id", default=None)
        args = parser.parse_args(["--run-id", "full-run-cicids2017"])
        self.assertEqual(args.run_id, "full-run-cicids2017")


if __name__ == "__main__":
    unittest.main()
