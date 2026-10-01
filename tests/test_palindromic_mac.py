"""Unit Tests for Palindromic MAC Addresses (PoPETs 2025-0103).

Asserts:
  - Mathematical symmetry (B0 == B5, B1 == B4, B2 == B3)
  - Endianness invariance (bytes == reversed(bytes))
  - Ground-truth Vector 7 compliance
  - Deterministic generation via seed
  - BLE address classification (Static, NRPA, RPA, Public)
  - String formatting and parsing helpers
"""

import pytest

from bluetooth_sniffle.protocol.mac import (
    classify_mac_address,
    generate_palindromic_mac,
    is_palindromic_mac,
    mac_to_str,
    str_to_mac,
)


class TestPalindromicMacGeneration:
    """Tests address generation and symmetry properties."""

    def test_vector_7_ground_truth(self, ground_truth_vectors):
        """Vector 7: C0:11:22:22:11:C0 (Static Random)."""
        expected_hex = ground_truth_vectors["Palindromic_MAC"]
        raw = bytes.fromhex(expected_hex)

        assert is_palindromic_mac(raw)
        assert is_palindromic_mac("C0:11:22:22:11:C0")
        assert mac_to_str(raw) == "C0:11:22:22:11:C0"
        assert classify_mac_address(raw) == "Static"

    def test_symmetry_random_generations(self):
        """Generates 100 random palindromic MACs and confirms strict symmetry."""
        for _ in range(100):
            mac = generate_palindromic_mac()
            assert len(mac) == 6
            assert mac[0] == mac[5]
            assert mac[1] == mac[4]
            assert mac[2] == mac[3]
            assert mac == mac[::-1]
            assert is_palindromic_mac(mac)

    def test_seed_determinism(self):
        """Identical seeds produce identical MAC addresses."""
        seed = b"\x12\x34\x56"
        mac1 = generate_palindromic_mac("static", seed=seed)
        mac2 = generate_palindromic_mac("static", seed=seed)
        assert mac1 == mac2

        # Hex string seed
        mac3 = generate_palindromic_mac("static", seed="12:34:56")
        assert mac3 == mac1

        # Different seed produces different MAC
        mac_diff = generate_palindromic_mac("static", seed=b"\x99\x88\x77")
        assert mac_diff != mac1

    def test_short_seed_raises(self):
        with pytest.raises(ValueError, match="Seed must contain at least 3 bytes"):
            generate_palindromic_mac("static", seed=b"\x01\x02")

    def test_invalid_address_type_raises(self):
        with pytest.raises(ValueError, match="Invalid address_type"):
            generate_palindromic_mac("unknown_type")


class TestMacClassification:
    """Tests compliance with Bluetooth Core Spec address types."""

    def test_static_random_classification(self):
        for _ in range(20):
            mac = generate_palindromic_mac("static")
            # Top 2 bits of B5 must be 11b (0xC0..0xFF)
            assert (mac[5] >> 6) == 0b11
            assert (mac[0] >> 6) == 0b11
            assert classify_mac_address(mac) == "Static"

    def test_nrpa_classification(self):
        for _ in range(20):
            mac = generate_palindromic_mac("nrpa")
            # Top 2 bits of B5 must be 00b (0x00..0x3F)
            assert (mac[5] >> 6) == 0b00
            assert (mac[0] >> 6) == 0b00
            assert classify_mac_address(mac) == "NRPA"
            # Ensure not all zero
            assert mac != b"\x00" * 6

    def test_rpa_classification(self):
        for _ in range(20):
            mac = generate_palindromic_mac("rpa")
            # Top 2 bits of B5 must be 01b (0x40..0x7F)
            assert (mac[5] >> 6) == 0b01
            assert (mac[0] >> 6) == 0b01
            assert classify_mac_address(mac) == "RPA"

    def test_public_classification(self):
        for _ in range(20):
            mac = generate_palindromic_mac("public")
            # Bit 0 must be 0 (IEEE 802 unicast)
            assert (mac[0] & 0x01) == 0
            assert (mac[5] & 0x01) == 0
            assert classify_mac_address(mac) == "Public"

    def test_explicit_is_random_flag(self):
        mac = generate_palindromic_mac("static")
        # Overridden as public when is_random is False (TxAdd = 0)
        assert classify_mac_address(mac, is_random=False) == "Public"
        assert classify_mac_address(mac, is_random=True) == "Static"

        nrpa_mac = generate_palindromic_mac("nrpa")
        assert classify_mac_address(nrpa_mac, is_random=True) == "NRPA"

        rpa_mac = generate_palindromic_mac("rpa")
        assert classify_mac_address(rpa_mac, is_random=True) == "RPA"

        # Explicit RFU when is_random is True and top2 bits are 10b
        rfu_mac = bytes([0x80, 0x11, 0x22, 0x22, 0x11, 0x80])
        assert classify_mac_address(rfu_mac, is_random=True) == "RFU"

    def test_classify_mac_address_string_input(self):
        assert classify_mac_address("00:11:22:22:11:00") == "NRPA"
        assert classify_mac_address("40:11:22:22:11:40") == "RPA"
        assert classify_mac_address("C0:11:22:22:11:C0") == "Static"
        assert classify_mac_address("80:11:22:22:11:80") == "Public"

    def test_nrpa_all_zeros_avoidance(self):
        # When seed would generate all zeros, b2 is forced to 0x01
        mac = generate_palindromic_mac("nrpa", seed=b"\x00\x00\x00")
        assert mac == bytes([0x00, 0x00, 0x01, 0x01, 0x00, 0x00])
        assert is_palindromic_mac(mac)
        assert classify_mac_address(mac) == "NRPA"

    def test_invalid_mac_classification_length(self):
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            classify_mac_address(b"\x01\x02\x03")


class TestMacFormattingAndParsing:
    """Tests string conversion and parser tolerance."""

    def test_round_trip(self):
        original = bytes([0xC0, 0xAA, 0x55, 0x55, 0xAA, 0xC0])
        formatted = mac_to_str(original)
        assert formatted == "C0:AA:55:55:AA:C0"
        restored = str_to_mac(formatted)
        assert restored == original

    def test_str_to_mac_delimiters_and_case(self):
        expected = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        # Colon delimited uppercase and lowercase
        assert str_to_mac("AA:BB:CC:DD:EE:FF") == expected
        assert str_to_mac("aa:bb:cc:dd:ee:ff") == expected
        # Dash delimited
        assert str_to_mac("AA-BB-CC-DD-EE-FF") == expected
        assert str_to_mac("aa-bb-cc-dd-ee-ff") == expected
        # Continuous hex without separators
        assert str_to_mac("AABBCCDDEEFF") == expected
        assert str_to_mac("aabbccddeeff") == expected

    def test_str_to_mac_invalid_strings(self):
        with pytest.raises(ValueError, match="expected 12 hexadecimal characters"):
            str_to_mac("AA:BB:CC:DD:EE")  # Only 5 bytes
        with pytest.raises(ValueError, match="expected 12 hexadecimal characters"):
            str_to_mac("AA:BB:CC:DD:EE:FF:00")  # 7 bytes
        with pytest.raises(ValueError, match="Invalid hexadecimal"):
            str_to_mac("AA:BB:CC:DD:EE:ZZ")  # Non-hex characters

    def test_mac_to_str_invalid_length(self):
        with pytest.raises(ValueError, match="MAC address must be exactly 6 bytes"):
            mac_to_str(b"\x00" * 5)
        with pytest.raises(ValueError, match="MAC address must be exactly 6 bytes"):
            mac_to_str(b"\x00" * 7)

    def test_is_palindromic_mac_false_cases(self):
        assert not is_palindromic_mac(bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
        assert not is_palindromic_mac("01:02:03:04:05:06")
        assert not is_palindromic_mac("invalid_string")
        assert not is_palindromic_mac(b"\x01\x02\x03")
        assert not is_palindromic_mac(12345)
