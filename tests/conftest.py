"""Pytest configuration and shared fixtures for bluetooth_sniffle tests."""

import sys
from pathlib import Path

import pytest

# Ensure src/ is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Optionally add reference Sniffle library if present
SNIFFLE_CLI_DIR = Path("/home/self/git/Sniffle/Sniffle/python_cli")
if SNIFFLE_CLI_DIR.exists() and str(SNIFFLE_CLI_DIR) not in sys.path:
    sys.path.insert(0, str(SNIFFLE_CLI_DIR))


@pytest.fixture
def ground_truth_vectors() -> dict[str, str]:
    """Verified ground-truth packet vectors from explorer_survey_2/handoff.md."""
    return {
        "iBeacon": "0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5",
        "AltBeacon": "0201061bff1801beace2c56db5dffb48d2b060d0f5a71096e000010002c500",
        "Eddystone-UID": "0201060303aafe1716aafe00ec0102030405060708090a0102030405060000",
        "Eddystone-URL": "0201060303aafe1216aafe10ee036578616d706c650074657374",
        "Eddystone-TLM": "0201060303aafe1116aafe20000bb81480000003e800002710",
        "GAEN": "02011a03036ffd17166ffd0102030405060708090a0b0c0d0e0f1011223344",
        "Palindromic_MAC": "c011222211c0",
        "SCAN_REQ": "c30cc011222211c0c033444433c0",
        "SCAN_RSP": "4423c033444433c00a09506f504554732d30311107000102030405060708090a0b0c0d0e0f",
    }
