"""Adversarial Challenge Test Suite for Milestone 1 Probing Frames and Burst Scheduling.

Adversarially challenges:
  1. build_scan_req parameter combinations and edge cases:
     - All 4 combinations of public/random addresses (TxAdd, RxAdd)
     - Non-palindromic and palindromic MAC formats (raw bytes, hyphenated, colon-delimited, hex)
     - Malformed / invalid MAC lengths and strings
  2. build_scan_rsp parameter combinations and edge cases:
     - Public vs random AdvA
     - Empty local name ("") vs maximal 29-byte local name (exact 31 bytes AD payload)
     - Unicode / multi-byte UTF-8 local names (length calculation based on encoded bytes)
     - Maximal 128-bit UUID list combinations pushing scan response to exact 31 bytes:
       * 1x 128-bit UUID (18B) + 11-char name (13B) = 31 bytes
       * 1x 128-bit UUID (18B) + 4x 16-bit UUIDs (10B) + 1-char name (3B) = 31 bytes
       * 1x 128-bit UUID (18B) + 13B raw AD data = 31 bytes
     - Overflowing payloads exceeding 31 bytes (assert ValueError raised):
       * 30-char name alone (32 bytes)
       * 2x 128-bit UUIDs (34 bytes)
       * 1x 128-bit UUID (18B) + 12-char name (14B) = 32 bytes
       * 1x 128-bit UUID (18B) + 5x 16-bit UUIDs (12B) + empty name (2B) = 32 bytes
       * 15x 16-bit UUIDs (32 bytes)
  3. BurstCycleHelper timing calculations & profile rotation:
     - High-frequency advertising (20ms interval, e.g. 5.0s -> 250 pkts, 0.02s -> 1 pkt, 0.019s -> 0 pkts)
     - Long intervals (1000ms, 10240ms)
     - 0-duration bursts (0.0s -> 0 pkts, total cycle duration 0.0s / 5.0s)
     - Negative duration / zero interval validation (assert ValueError raised)
     - Profile rotation edge cases (empty schedule, single profile, multi-profile cycle, dynamic addition, reset)
  4. Cross-validation against reference Sniffle decoder (DPacketMessage.from_body and decode_adv_data).
"""

from __future__ import annotations

import sys
from uuid import UUID

import pytest

from bluetooth_sniffle.protocol.beacons import BurstCycleHelper, BurstProfile
from bluetooth_sniffle.protocol.probing import (
    AD_TYPE_COMPLETE_LOCAL_NAME,
    build_scan_req,
    build_scan_rsp,
)

# Reference Sniffle decoder check
if "/home/self/git/Sniffle/Sniffle/python_cli" not in sys.path:
    sys.path.insert(0, "/home/self/git/Sniffle/Sniffle/python_cli")

try:
    from sniffle.advdata.decoder import decode_adv_data
    from sniffle.packet_decoder import DPacketMessage
    SNIFFLE_AVAILABLE = True
except ImportError:
    SNIFFLE_AVAILABLE = False


class TestScanReqAdversarial:
    """Adversarial stress-testing of build_scan_req."""

    @pytest.mark.parametrize(
        ("scan_rnd", "adv_rnd", "expected_hdr0"),
        [
            (False, False, 0x03),  # TxAdd=0, RxAdd=0
            (True, False, 0x43),   # TxAdd=1, RxAdd=0
            (False, True, 0x83),   # TxAdd=0, RxAdd=1
            (True, True, 0xC3),    # TxAdd=1, RxAdd=1
        ],
    )
    def test_scan_req_all_address_type_combinations(
        self, scan_rnd: bool, adv_rnd: bool, expected_hdr0: int
    ) -> None:
        scan_a = "11:22:33:44:55:66"
        adv_a = "AA:BB:CC:DD:EE:FF"

        pdu = build_scan_req(scan_a, adv_a, scan_a_random=scan_rnd, adv_a_random=adv_rnd)

        assert len(pdu) == 14
        assert pdu[0] == expected_hdr0
        assert pdu[1] == 12  # Payload length is always 12 bytes
        assert pdu[2:8] == bytes.fromhex("112233445566")
        assert pdu[8:14] == bytes.fromhex("aabbccddeeff")

    @pytest.mark.skipif(not SNIFFLE_AVAILABLE, reason="Sniffle decoder not installed")
    @pytest.mark.parametrize(
        ("scan_rnd", "adv_rnd"),
        [
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_scan_req_sniffle_cross_validation(self, scan_rnd: bool, adv_rnd: bool) -> None:
        scan_a = bytes.fromhex("c011222211c0")
        adv_a = bytes.fromhex("c033444433c0")

        pdu = build_scan_req(scan_a, adv_a, scan_a_random=scan_rnd, adv_a_random=adv_rnd)
        pkt = DPacketMessage.from_body(pdu)

        assert pkt.pdutype == "SCAN_REQ"
        assert pkt.TxAdd == int(scan_rnd)
        assert pkt.RxAdd == int(adv_rnd)
        assert pkt.ScanA == scan_a
        assert pkt.AdvA == adv_a
        # Ensure string representation formats without unhandled exceptions
        s = str(pkt)
        assert "SCAN_REQ" in s
        assert "AdvA:" in s

    def test_scan_req_mac_input_formats(self) -> None:
        raw_scan = bytes.fromhex("c011222211c0")
        raw_adv = bytes.fromhex("c033444433c0")

        # Colon-delimited uppercase
        p1 = build_scan_req("C0:11:22:22:11:C0", "C0:33:44:44:33:C0")
        # Hyphen-delimited lowercase
        p2 = build_scan_req("c0-11-22-22-11-c0", "c0-33-44-44-33-c0")
        # Raw bytes
        p3 = build_scan_req(raw_scan, raw_adv)
        # Bytearray
        p4 = build_scan_req(bytearray(raw_scan), bytearray(raw_adv))

        assert p1 == p2 == p3 == p4

    @pytest.mark.parametrize(
        "invalid_mac",
        [
            b"\x00" * 5,          # 5 bytes
            b"\x00" * 7,          # 7 bytes
            b"",                  # 0 bytes
            "11:22:33:44:55",     # 5 bytes hex string
            "11:22:33:44:55:66:77",  # 7 bytes hex string
            "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",  # non-hex chars
            "not-a-mac",
            "",
        ],
    )
    def test_scan_req_invalid_mac_inputs(self, invalid_mac: bytes | str) -> None:
        valid_mac = "C0:11:22:22:11:C0"
        with pytest.raises(ValueError):
            build_scan_req(invalid_mac, valid_mac)
        with pytest.raises(ValueError):
            build_scan_req(valid_mac, invalid_mac)


class TestScanRspAdversarial:
    """Adversarial stress-testing of build_scan_rsp."""

    def test_scan_rsp_public_vs_random_adva(self) -> None:
        adv_a = "AA:BB:CC:DD:EE:FF"

        # Public AdvA -> TxAdd = 0 -> Header 0x04
        p_pub = build_scan_rsp(adv_a, adv_a_random=False)
        assert p_pub[0] == 0x04
        assert p_pub[1] == 6  # 6 bytes AdvA + 0 bytes AD data

        # Random AdvA -> TxAdd = 1 -> Header 0x44
        p_rnd = build_scan_rsp(adv_a, adv_a_random=True)
        assert p_rnd[0] == 0x44
        assert p_rnd[1] == 6

    def test_scan_rsp_empty_local_name(self) -> None:
        """Empty string local_name='' creates a valid 2-byte AD structure."""
        adv_a = "C0:33:44:44:33:C0"
        pdu = build_scan_rsp(adv_a, local_name="", adv_a_random=True)

        assert len(pdu) == 2 + 6 + 2  # 10 bytes
        assert pdu[1] == 8  # Payload length = 6 (AdvA) + 2 (Name AD)
        # AD structure: len=1, type=0x09, name=b''
        assert pdu[8:] == bytes([0x01, AD_TYPE_COMPLETE_LOCAL_NAME])

        if SNIFFLE_AVAILABLE:
            pkt = DPacketMessage.from_body(pdu)
            assert pkt.pdutype == "SCAN_RSP"
            records = decode_adv_data(pkt.adv_data)
            assert len(records) == 1
            assert records[0].name == ""

    def test_scan_rsp_maximal_local_name_exact_31_bytes(self) -> None:
        """29-byte name + 2-byte AD header = exactly 31 bytes AD payload."""
        adv_a = "C0:33:44:44:33:C0"
        max_name = "N" * 29
        pdu = build_scan_rsp(adv_a, local_name=max_name, adv_a_random=False)

        assert len(pdu) == 2 + 6 + 31  # 39 bytes total
        assert pdu[1] == 37  # 6 + 31
        ad_payload = pdu[8:]
        assert len(ad_payload) == 31
        assert ad_payload[0] == 30  # len = 1 (type) + 29 (data) = 30
        assert ad_payload[1] == AD_TYPE_COMPLETE_LOCAL_NAME
        assert ad_payload[2:] == max_name.encode("utf-8")

        if SNIFFLE_AVAILABLE:
            pkt = DPacketMessage.from_body(pdu)
            records = decode_adv_data(pkt.adv_data)
            assert len(records) == 1
            assert records[0].name == max_name

    def test_scan_rsp_local_name_overflow_raises(self) -> None:
        """30-byte name + 2-byte AD header = 32 bytes (> 31) -> ValueError."""
        adv_a = "C0:33:44:44:33:C0"
        overflow_name = "N" * 30
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(adv_a, local_name=overflow_name)

    def test_scan_rsp_unicode_local_name_byte_counting(self) -> None:
        """Unicode characters occupy multiple UTF-8 bytes; limit applies to encoded bytes."""
        adv_a = "C0:33:44:44:33:C0"
        # Each euro sign '€' is 3 bytes in UTF-8
        # 9 chars * 3 bytes = 27 bytes. Add 2 ascii chars = 29 bytes.
        exact_unicode = "€" * 9 + "AB"
        assert len(exact_unicode.encode("utf-8")) == 29

        pdu = build_scan_rsp(adv_a, local_name=exact_unicode)
        assert len(pdu[8:]) == 31

        if SNIFFLE_AVAILABLE:
            pkt = DPacketMessage.from_body(pdu)
            records = decode_adv_data(pkt.adv_data)
            assert records[0].name == exact_unicode

        # Adding 1 more ASCII char makes encoded length 30 -> AD structure 32 bytes -> overflow
        overflow_unicode = exact_unicode + "C"
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(adv_a, local_name=overflow_unicode)

    def test_scan_rsp_exact_31_bytes_combinations(self) -> None:
        """Pushes combinations with 128-bit UUIDs to the exact 31-byte boundary."""
        adv_a = "C0:33:44:44:33:C0"
        u128 = UUID("00112233-4455-6677-8899-aabbccddeeff")

        # Combo 1: 1x 128-bit UUID (18B) + 11-char name (13B) = 31B
        p1 = build_scan_rsp(adv_a, local_name="A" * 11, service_uuids_128=[u128])
        assert len(p1[8:]) == 31

        # Combo 2: 1x 128-bit UUID (18B) + 4x 16-bit UUIDs (10B) + 1-char name (3B) = 31B
        u16_list = [0x1234, 0x5678, 0x9ABC, 0xDEF0]
        p2 = build_scan_rsp(
            adv_a,
            local_name="Z",
            service_uuids_16=u16_list,
            service_uuids_128=[u128],
        )
        assert len(p2[8:]) == 31

        # Combo 3: 1x 128-bit UUID (18B) + 13B raw AD data = 31B
        raw_ad = bytes([12, 0xFF, 0x4C, 0x00]) + b"\x01" * 9  # 13 bytes total
        p3 = build_scan_rsp(adv_a, service_uuids_128=[u128], raw_ad_data=raw_ad)
        assert len(p3[8:]) == 31

        if SNIFFLE_AVAILABLE:
            for p in (p1, p2, p3):
                pkt = DPacketMessage.from_body(p)
                assert pkt.pdutype == "SCAN_RSP"
                records = decode_adv_data(pkt.adv_data)
                assert len(records) >= 1

    def test_scan_rsp_combinations_overflow_raises(self) -> None:
        """Pushes various combinations beyond 31 bytes; asserts ValueError."""
        adv_a = "C0:33:44:44:33:C0"
        u128_a = UUID("00112233-4455-6677-8899-aabbccddeeff")
        u128_b = UUID("11223344-5566-7788-99aa-bbccddeeff00")

        # Case 1: Two 128-bit UUIDs = 1B (len) + 1B (type) + 32B (data) = 34B > 31B
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(adv_a, service_uuids_128=[u128_a, u128_b])

        # Case 2: 1x 128-bit UUID (18B) + 12-char name (14B) = 32B
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(adv_a, local_name="A" * 12, service_uuids_128=[u128_a])

        # Case 3: 1x 128-bit UUID (18B) + 5x 16-bit UUIDs (12B) + empty name (2B) = 32B
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(
                adv_a,
                local_name="",
                service_uuids_16=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000],
                service_uuids_128=[u128_a],
            )

        # Case 4: 15x 16-bit UUIDs = 1B (len) + 1B (type) + 30B = 32B > 31B
        with pytest.raises(ValueError, match="exceeds standard 31-byte limit"):
            build_scan_rsp(adv_a, service_uuids_16=[0x1000 + i for i in range(15)])


class TestBurstCycleHelperAdversarial:
    """Adversarial stress-testing of BurstCycleHelper and BurstProfile."""

    def test_high_frequency_advertising_20ms(self) -> None:
        """20ms interval is the minimum interval for BLE advertising."""
        # 5.0 seconds at 20ms = 250 packets
        assert BurstCycleHelper.estimate_packet_count(5.0, 20) == 250

        # Exact packet interval boundaries
        assert BurstCycleHelper.estimate_packet_count(0.020, 20) == 1
        assert BurstCycleHelper.estimate_packet_count(0.019, 20) == 0
        assert BurstCycleHelper.estimate_packet_count(0.039, 20) == 1
        assert BurstCycleHelper.estimate_packet_count(0.040, 20) == 2

    def test_long_interval_advertising_1000ms_and_beyond(self) -> None:
        """Long intervals (1000ms up to 10240ms max BLE interval)."""
        assert BurstCycleHelper.estimate_packet_count(5.0, 1000) == 5
        assert BurstCycleHelper.estimate_packet_count(0.5, 1000) == 0
        assert BurstCycleHelper.estimate_packet_count(0.999, 1000) == 0
        assert BurstCycleHelper.estimate_packet_count(1.0, 1000) == 1
        assert BurstCycleHelper.estimate_packet_count(100.0, 1000) == 100

        # Max BLE interval 10.24s (10240ms)
        assert BurstCycleHelper.estimate_packet_count(20.48, 10240) == 2
        assert BurstCycleHelper.estimate_packet_count(5.0, 10240) == 0

    def test_zero_duration_bursts(self) -> None:
        """0-duration bursts produce 0 packets and preserve cycle duration arithmetic."""
        assert BurstCycleHelper.estimate_packet_count(0.0, 20) == 0
        assert BurstCycleHelper.estimate_packet_count(0.0, 100) == 0
        assert BurstCycleHelper.estimate_packet_count(0.0, 1000) == 0

        assert BurstCycleHelper.total_cycle_duration(0.0, 5.0) == 5.0
        assert BurstCycleHelper.total_cycle_duration(5.0, 0.0) == 5.0
        assert BurstCycleHelper.total_cycle_duration(0.0, 0.0) == 0.0

    def test_invalid_timing_parameters(self) -> None:
        """Negative durations or non-positive intervals must raise ValueError."""
        with pytest.raises(ValueError, match="interval_ms must be positive"):
            BurstCycleHelper.estimate_packet_count(5.0, 0)
        with pytest.raises(ValueError, match="interval_ms must be positive"):
            BurstCycleHelper.estimate_packet_count(5.0, -20)
        with pytest.raises(ValueError, match="burst_duration_s cannot be negative"):
            BurstCycleHelper.estimate_packet_count(-0.001, 100)

        with pytest.raises(ValueError, match="Durations cannot be negative"):
            BurstCycleHelper.total_cycle_duration(-1.0, 5.0)
        with pytest.raises(ValueError, match="Durations cannot be negative"):
            BurstCycleHelper.total_cycle_duration(5.0, -1.0)

    def test_profile_rotation_edge_cases(self) -> None:
        # Edge Case 1: Empty schedule
        helper = BurstCycleHelper()
        assert helper.current_profile is None
        with pytest.raises(ValueError, match="No burst profiles configured"):
            helper.next_profile()

        # Edge Case 2: Single profile schedule
        p1 = BurstProfile(name="p1", adv_data=b"\x01")
        helper.add_profile(p1)
        assert helper.current_profile == p1
        for _ in range(5):
            assert helper.next_profile() == p1
            assert helper.current_profile == p1

        # Edge Case 3: Two profiles round-robin
        p2 = BurstProfile(name="p2", adv_data=b"\x02")
        helper.add_profile(p2)
        helper.reset()
        assert helper.current_profile == p1

        # Sequence of 6 calls across 2 profiles
        sequence = [helper.next_profile().name for _ in range(6)]
        assert sequence == ["p1", "p2", "p1", "p2", "p1", "p2"]

        # Edge Case 4: Reset mid-cycle
        assert helper.current_profile == p1
        _ = helper.next_profile()  # advances to p2
        assert helper.current_profile == p2
        helper.reset()
        assert helper.current_profile == p1

        # Edge Case 5: Dynamic addition of profiles mid-cycle
        p3 = BurstProfile(name="p3", adv_data=b"\x03")
        _ = helper.next_profile()  # returns p1, pointer is at 1 (p2)
        helper.add_profile(p3)      # total 3 profiles
        assert helper.next_profile().name == "p2"  # returns p2, pointer is at 2 (p3)
        assert helper.next_profile().name == "p3"  # returns p3, pointer wraps to 0 (p1)
        assert helper.next_profile().name == "p1"  # wraps cleanly
