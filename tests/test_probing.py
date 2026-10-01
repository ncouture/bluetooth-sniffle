"""Unit Tests for Active Probing Frames (PoPETs 2025-0103).

Asserts:
  - Exact bit-for-bit compliance with ground-truth Vector 8 (SCAN_REQ) and Vector 9 (SCAN_RSP)
  - Cross-decoding with Sniffle Link Layer PDU decoder
  - Header bitfield encoding (PDU types, TxAdd, RxAdd)
  - Scan response AD structure combinations and 31-byte limit enforcement
"""

import sys
from uuid import UUID

import pytest

from bluetooth_sniffle.protocol.probing import (
    build_scan_req,
    build_scan_rsp,
)

# Optional reference Sniffle decoder check
if "/home/self/git/Sniffle/Sniffle/python_cli" not in sys.path:
    sys.path.insert(0, "/home/self/git/Sniffle/Sniffle/python_cli")

try:
    from sniffle.packet_decoder import DPacketMessage
    SNIFFLE_AVAILABLE = True
except ImportError:
    SNIFFLE_AVAILABLE = False


class TestScanReqBuilding:
    """Tests SCAN_REQ Link Layer frame construction."""

    def test_vector_8_exact_match(self, ground_truth_vectors):
        """Vector 8: SCAN_REQ (14 bytes)."""
        scan_a = "C0:11:22:22:11:C0"
        adv_a = "C0:33:44:44:33:C0"

        pdu = build_scan_req(scan_a, adv_a, scan_a_random=True, adv_a_random=True)
        expected_hex = ground_truth_vectors["SCAN_REQ"]

        assert pdu.hex() == expected_hex
        assert len(pdu) == 14
        # Byte 0: Type 3 (0x03) | TxAdd (0x40) | RxAdd (0x80) = 0xC3
        assert pdu[0] == 0xC3
        # Byte 1: Length = 12
        assert pdu[1] == 12

    def test_scan_req_address_types(self):
        scan_a = bytes.fromhex("c011222211c0")
        adv_a = bytes.fromhex("c033444433c0")

        # Public ScanA, Public AdvA -> 0x03
        p1 = build_scan_req(scan_a, adv_a, scan_a_random=False, adv_a_random=False)
        assert p1[0] == 0x03

        # Random ScanA, Public AdvA -> 0x43
        p2 = build_scan_req(scan_a, adv_a, scan_a_random=True, adv_a_random=False)
        assert p2[0] == 0x43

        # Public ScanA, Random AdvA -> 0x83
        p3 = build_scan_req(scan_a, adv_a, scan_a_random=False, adv_a_random=True)
        assert p3[0] == 0x83

        # Random ScanA, Random AdvA -> 0xC3
        p4 = build_scan_req(scan_a, adv_a, scan_a_random=True, adv_a_random=True)
        assert p4[0] == 0xC3

    def test_scan_req_invalid_addresses(self):
        with pytest.raises(ValueError):
            build_scan_req(b"\x00" * 5, b"\x00" * 6)
        with pytest.raises(ValueError):
            build_scan_req(b"\x00" * 6, b"\x00" * 7)
        with pytest.raises(ValueError):
            build_scan_req("invalid_mac", "C0:33:44:44:33:C0")


class TestScanRspBuilding:
    """Tests SCAN_RSP Link Layer frame construction."""

    def test_vector_9_exact_match(self, ground_truth_vectors):
        """Vector 9: SCAN_RSP (37 bytes)."""
        adv_a = "C0:33:44:44:33:C0"
        local_name = "PoPETs-01"
        service_uuids_128 = ["00010203-0405-0607-0809-0a0b0c0d0e0f"]

        pdu = build_scan_rsp(
            adv_a=adv_a,
            local_name=local_name,
            service_uuids_128=service_uuids_128,
            adv_a_random=True,
        )
        expected_hex = ground_truth_vectors["SCAN_RSP"]

        assert pdu.hex() == expected_hex
        assert len(pdu) == 37
        # Byte 0: Type 4 (0x04) | TxAdd (0x40) = 0x44
        assert pdu[0] == 0x44
        # Byte 1: Payload Length = 35 (6B AdvA + 11B Name + 18B UUID128)
        assert pdu[1] == 35

    def test_scan_rsp_16bit_uuids(self):
        adv_a = "C0:33:44:44:33:C0"
        pdu = build_scan_rsp(
            adv_a=adv_a,
            service_uuids_16=[0xFEAA, "0xFD6F", b"\x12\x34"],
            adv_a_random=False,
        )
        assert pdu[0] == 0x04  # Public AdvA (TxAdd = 0)
        # AD structure for 16-bit UUIDs: [0x07, 0x03, 0xAA, 0xFE, 0x6F, 0xFD, 0x12, 0x34]
        assert b"\x07\x03\xaa\xfe\x6f\xfd\x12\x34" in pdu

    def test_scan_rsp_uuid128_formats(self):
        u128_str = "00010203-0405-0607-0809-0a0b0c0d0e0f"
        u128_obj = UUID(u128_str)
        u128_bytes = u128_obj.bytes

        p1 = build_scan_rsp("C0:33:44:44:33:C0", service_uuids_128=[u128_str])
        p2 = build_scan_rsp("C0:33:44:44:33:C0", service_uuids_128=[u128_obj])
        p3 = build_scan_rsp("C0:33:44:44:33:C0", service_uuids_128=[u128_bytes])
        assert p1 == p2 == p3

    def test_scan_rsp_payload_limit_enforced(self):
        # 29 bytes of name + 2 bytes AD header (len + type) = 31 bytes (exactly max)
        long_name = "A" * 29
        pdu = build_scan_rsp("C0:33:44:44:33:C0", local_name=long_name)
        assert len(pdu) == 2 + 6 + 31  # 39 bytes total

        # 30 bytes of name + 2 bytes AD header = 32 bytes (> 31)
        too_long_name = "A" * 30
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp("C0:33:44:44:33:C0", local_name=too_long_name)

    def test_scan_rsp_raw_ad_data_and_bytes_adva(self):
        adv_a_raw = bytes.fromhex("c033444433c0")
        custom_ad = bytes([0x03, 0xFF, 0x4C, 0x00])  # Apple MSD stub
        pdu = build_scan_rsp(adv_a_raw, raw_ad_data=custom_ad)
        assert len(pdu) == 2 + 6 + len(custom_ad)
        assert custom_ad in pdu

    def test_scan_rsp_invalid_inputs(self):
        with pytest.raises(ValueError, match="AdvA must be 6 bytes"):
            build_scan_rsp(b"\x00" * 5)
        with pytest.raises(ValueError, match="16-bit UUID must be 2 bytes"):
            build_scan_rsp("C0:33:44:44:33:C0", service_uuids_16=[b"\x00" * 3])
        with pytest.raises(TypeError, match="Unsupported 16-bit UUID type"):
            build_scan_rsp("C0:33:44:44:33:C0", service_uuids_16=[3.14])
        with pytest.raises(ValueError, match="128-bit UUID must be 16 bytes"):
            build_scan_rsp("C0:33:44:44:33:C0", service_uuids_128=[b"\x00" * 15])
        with pytest.raises(TypeError, match="Unsupported 128-bit UUID type"):
            build_scan_rsp("C0:33:44:44:33:C0", service_uuids_128=[3.14])


@pytest.mark.skipif(not SNIFFLE_AVAILABLE, reason="Reference Sniffle library not installed")
class TestSniffleProbingInteroperability:
    """Verifies that generated probing frames are parsed by Sniffle's DPacketMessage."""

    def test_scan_req_pdu_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["SCAN_REQ"])
        pkt = DPacketMessage.from_body(raw)
        assert pkt.pdutype == "SCAN_REQ"
        assert pkt.ScanA == bytes.fromhex("c011222211c0")
        assert pkt.AdvA == bytes.fromhex("c033444433c0")

    def test_scan_rsp_pdu_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["SCAN_RSP"])
        pkt = DPacketMessage.from_body(raw)
        assert pkt.pdutype == "SCAN_RSP"
        assert pkt.AdvA == bytes.fromhex("c033444433c0")
