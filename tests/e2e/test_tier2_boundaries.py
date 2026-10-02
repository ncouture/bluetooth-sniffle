"""Tier 2: Boundary and Edge-Case Tests (Milestone 5).

Verifies boundary value conditions, edge cases, numeric saturation, rollover,
and fallback behaviors across all 20 features per TEST_INFRA.md and PoPETs 2025-0103.
Exactly 5 tests per feature (100 tests total).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bluetooth_sniffle.cli import main
from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.protocol.beacons import (
    BurstCycleHelper,
    build_altbeacon,
    build_eddystone_tlm,
    build_eddystone_uid,
    build_eddystone_url,
    build_gaen,
    build_ibeacon,
)
from bluetooth_sniffle.protocol.mac import (
    generate_palindromic_mac,
    is_palindromic_mac,
    mac_to_str,
    str_to_mac,
)
from bluetooth_sniffle.protocol.probing import (
    build_scan_req,
    build_scan_rsp,
)
from bluetooth_sniffle.protocol.wire import (
    PacketMessage,
    StateMessage,
    decode_msg,
)
from bluetooth_sniffle.sniff.correlation import (
    StimulusResponseCorrelator,
)
from bluetooth_sniffle.sniff.dissector import (
    BleAddressType,
    classify_address,
    dissect_advertising_pdu,
)
from bluetooth_sniffle.sniff.pcap import (
    PcapBleReader,
    PcapBleWriter,
    normalize_rssi,
)
from bluetooth_sniffle.sniff.telemetry import TelemetrySession
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator

# ==============================================================================
# Feature 1: Apple iBeacon Boundaries (5 tests)
# ==============================================================================


class TestFeature01IBeaconBoundaries:
    """Feature 1 Boundary: numeric extremes, signed RSSI, and overflow validation."""

    def test_f01_major_minor_zero_limits(self) -> None:
        raw = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=0, minor=0, tx_power=-59)
        assert raw[25:27] == bytes([0x00, 0x00])
        assert raw[27:29] == bytes([0x00, 0x00])

    def test_f01_major_minor_max_limits(self) -> None:
        raw = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=65535, minor=65535, tx_power=-59)
        assert raw[25:27] == bytes([0xFF, 0xFF])
        assert raw[27:29] == bytes([0xFF, 0xFF])

    def test_f01_tx_power_boundary_limits(self) -> None:
        raw_min = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, tx_power=-128)
        raw_zero = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, tx_power=0)
        raw_max = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, tx_power=127)
        assert raw_min[-1] == 0x80
        assert raw_zero[-1] == 0x00
        assert raw_max[-1] == 0x7F

    def test_f01_major_overflow_raises(self) -> None:
        with pytest.raises(ValueError, match="Major must be 0..65535"):
            build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=-1, minor=1)
        with pytest.raises(ValueError, match="Major must be 0..65535"):
            build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=65536, minor=1)

    def test_f01_minor_overflow_raises(self) -> None:
        with pytest.raises(ValueError, match="Minor must be 0..65535"):
            build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=1, minor=-1)
        with pytest.raises(ValueError, match="Minor must be 0..65535"):
            build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=1, minor=65536)


# ==============================================================================
# Feature 2: AltBeacon Boundaries (5 tests)
# ==============================================================================


class TestFeature02AltBeaconBoundaries:
    """Feature 2 Boundary: 20-byte ID saturation, ref_rssi range, and reserved field."""

    def test_f02_ref_rssi_boundaries(self) -> None:
        raw_min = build_altbeacon(beacon_id=bytes(20), ref_rssi=-128)
        raw_zero = build_altbeacon(beacon_id=bytes(20), ref_rssi=0)
        raw_max = build_altbeacon(beacon_id=bytes(20), ref_rssi=127)
        assert raw_min[29] == 0x80
        assert raw_zero[29] == 0x00
        assert raw_max[29] == 0x7F

    def test_f02_mfg_reserved_boundaries(self) -> None:
        raw_zero = build_altbeacon(beacon_id=bytes(20), mfg_reserved=0x00)
        raw_max = build_altbeacon(beacon_id=bytes(20), mfg_reserved=0xFF)
        assert raw_zero[30] == 0x00
        assert raw_max[30] == 0xFF

    def test_f02_mfg_id_boundaries(self) -> None:
        raw_zero = build_altbeacon(mfg_id=0x0000, beacon_id=bytes(20))
        raw_max = build_altbeacon(mfg_id=0xFFFF, beacon_id=bytes(20))
        assert raw_zero[5:7] == bytes([0x00, 0x00])
        assert raw_max[5:7] == bytes([0xFF, 0xFF])

    def test_f02_beacon_id_all_zeros_and_all_ones(self) -> None:
        raw_zeros = build_altbeacon(beacon_id=bytes(20))
        raw_ones = build_altbeacon(beacon_id=bytes([0xFF] * 20))
        assert raw_zeros[9:29] == bytes(20)
        assert raw_ones[9:29] == bytes([0xFF] * 20)

    def test_f02_beacon_id_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="AltBeacon ID must be exactly 20 bytes"):
            build_altbeacon(beacon_id=bytes(19))
        with pytest.raises(ValueError, match="AltBeacon ID must be exactly 20 bytes"):
            build_altbeacon(beacon_id=bytes(21))


# ==============================================================================
# Feature 3: Eddystone-UID Boundaries (5 tests)
# ==============================================================================


class TestFeature03EddystoneUidBoundaries:
    """Feature 3 Boundary: 10-byte namespace and 6-byte instance boundary vectors."""

    def test_f03_namespace_and_instance_all_zeros(self) -> None:
        raw = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=0)
        assert raw[13:23] == bytes(10)
        assert raw[23:29] == bytes(6)

    def test_f03_namespace_and_instance_all_ones(self) -> None:
        raw = build_eddystone_uid(namespace=bytes([0xFF] * 10), instance=bytes([0xFF] * 6), tx_power=0)
        assert raw[13:23] == bytes([0xFF] * 10)
        assert raw[23:29] == bytes([0xFF] * 6)

    def test_f03_tx_power_boundaries(self) -> None:
        raw_min = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=-128)
        raw_zero = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=0)
        raw_max = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=127)
        assert raw_min[12] == 0x80
        assert raw_zero[12] == 0x00
        assert raw_max[12] == 0x7F

    def test_f03_namespace_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="namespace must be 10 bytes"):
            build_eddystone_uid(namespace=bytes(9), instance=bytes(6))
        with pytest.raises(ValueError, match="namespace must be 10 bytes"):
            build_eddystone_uid(namespace=bytes(11), instance=bytes(6))

    def test_f03_instance_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="instance must be 6 bytes"):
            build_eddystone_uid(namespace=bytes(10), instance=bytes(5))
        with pytest.raises(ValueError, match="instance must be 6 bytes"):
            build_eddystone_uid(namespace=bytes(10), instance=bytes(7))


# ==============================================================================
# Feature 4: Eddystone-URL Boundaries (5 tests)
# ==============================================================================


class TestFeature04EddystoneUrlBoundaries:
    """Feature 4 Boundary: length saturation up to 31 bytes, scheme and non-ASCII errors."""

    def test_f04_minimal_length_url(self) -> None:
        # Minimal URL "https://a.com/" encodes prefix 0x03, 'a', suffix 0x00 -> valid payload
        raw = build_eddystone_url("https://a.com/")
        assert len(raw) <= 31
        assert raw[11] == 0x10

    def test_f04_exact_31_byte_saturation(self) -> None:
        # Base headers: 3B flags + 4B service list + 6B service data header = 13 bytes
        # 31 - 13 = 18 bytes for encoded URL. Prefix takes 1 byte, so 17 characters in body.
        # "https://" (prefix 1B) + "12345678901234567" (17B) = 18B encoded -> total 31B
        url = "https://" + "a" * 17
        raw = build_eddystone_url(url)
        assert len(raw) == 31

    def test_f04_oversized_url_raises(self) -> None:
        # 18 characters in body would require 19B encoded -> total 32B (exceeds 31B limit)
        url = "https://" + "a" * 18
        with pytest.raises(ValueError, match="exceeds maximum allowable 31 bytes"):
            build_eddystone_url(url)

    def test_f04_invalid_scheme_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="does not start with a valid Eddystone-URL scheme"):
            build_eddystone_url("ftp://example.com")

    def test_f04_unsupported_non_ascii_raises(self) -> None:
        with pytest.raises(ValueError, match="Non-ASCII character"):
            build_eddystone_url("https://example.com/über")


# ==============================================================================
# Feature 5: Eddystone-TLM Boundaries (5 tests)
# ==============================================================================


class TestFeature05EddystoneTlmBoundaries:
    """Feature 5 Boundary: 8.8 fixed point temperature, counters up to 2^32-1, None temp."""

    def test_f05_vbatt_boundaries(self) -> None:
        raw_zero = build_eddystone_tlm(vbatt_mv=0, temp_c=20.0, adv_cnt=0, sec_cnt=0)
        raw_max = build_eddystone_tlm(vbatt_mv=65535, temp_c=20.0, adv_cnt=0, sec_cnt=0)
        assert raw_zero[13:15] == bytes([0x00, 0x00])
        assert raw_max[13:15] == bytes([0xFF, 0xFF])

    def test_f05_temp_c_boundaries(self) -> None:
        raw_zero = build_eddystone_tlm(vbatt_mv=3000, temp_c=0.0, adv_cnt=0, sec_cnt=0)
        assert raw_zero[15:17] == bytes([0x00, 0x00])

        raw_pos = build_eddystone_tlm(vbatt_mv=3000, temp_c=127.0, adv_cnt=0, sec_cnt=0)
        assert raw_pos[15] == 127
        assert raw_pos[16] == 0

    def test_f05_temp_c_unsupported_none(self) -> None:
        # Per Eddystone-TLM spec, unsupported temperature is encoded as 0x8000 (-128.0 C)
        raw_none = build_eddystone_tlm(vbatt_mv=3000, temp_c=None, adv_cnt=0, sec_cnt=0)
        assert raw_none[15:17] == bytes([0x80, 0x00])

    def test_f05_adv_cnt_max_limit(self) -> None:
        raw_max = build_eddystone_tlm(vbatt_mv=3000, temp_c=20.0, adv_cnt=0xFFFFFFFF, sec_cnt=0)
        assert raw_max[17:21] == bytes([0xFF, 0xFF, 0xFF, 0xFF])

    def test_f05_sec_cnt_max_limit(self) -> None:
        raw_max = build_eddystone_tlm(vbatt_mv=3000, temp_c=20.0, adv_cnt=0, sec_cnt=0xFFFFFFFF)
        assert raw_max[21:25] == bytes([0xFF, 0xFF, 0xFF, 0xFF])


# ==============================================================================
# Feature 6: GAEN Boundaries (5 tests)
# ==============================================================================


class TestFeature06GaenBoundaries:
    """Feature 6 Boundary: 16B RPI and 4B AEM all-zeros, all-ones, and invalid lengths."""

    def test_f06_rpi_aem_all_zeros(self) -> None:
        raw = build_gaen(rpi=bytes(16), aem=bytes(4))
        assert raw[11:27] == bytes(16)
        assert raw[27:31] == bytes(4)

    def test_f06_rpi_aem_all_ones(self) -> None:
        raw = build_gaen(rpi=bytes([0xFF] * 16), aem=bytes([0xFF] * 4))
        assert raw[11:27] == bytes([0xFF] * 16)
        assert raw[27:31] == bytes([0xFF] * 4)

    def test_f06_rpi_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="16 bytes"):
            build_gaen(rpi=bytes(15), aem=bytes(4))
        with pytest.raises(ValueError, match="16 bytes"):
            build_gaen(rpi=bytes(17), aem=bytes(4))

    def test_f06_aem_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="4 bytes"):
            build_gaen(rpi=bytes(16), aem=bytes(3))
        with pytest.raises(ValueError, match="4 bytes"):
            build_gaen(rpi=bytes(16), aem=bytes(5))

    def test_f06_flags_boundaries(self) -> None:
        raw_00 = build_gaen(rpi=bytes(16), aem=bytes(4), flags=0x00)
        raw_ff = build_gaen(rpi=bytes(16), aem=bytes(4), flags=0xFF)
        assert raw_00[2] == 0x00
        assert raw_ff[2] == 0xFF


# ==============================================================================
# Feature 7: Palindromic MAC Boundaries (5 tests)
# ==============================================================================


class TestFeature07PalindromicMacBoundaries:
    """Feature 7 Boundary: seed lengths, NRPA zero-avoidance, and delimiter parsing."""

    def test_f07_seed_exact_3_bytes(self) -> None:
        mac = generate_palindromic_mac("static", seed=b"\x01\x02\x03")
        assert len(mac) == 6
        assert is_palindromic_mac(mac)

    def test_f07_seed_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="Seed must contain at least 3 bytes"):
            generate_palindromic_mac("static", seed=b"\x01\x02")

    def test_f07_nrpa_all_zero_avoidance(self) -> None:
        # When seed is all zeros, NRPA must avoid being completely zero
        mac = generate_palindromic_mac("nrpa", seed=b"\x00\x00\x00")
        assert mac != bytes(6)
        assert is_palindromic_mac(mac)

    def test_f07_mac_to_str_boundary_cases(self) -> None:
        assert mac_to_str(bytes(6)) == "00:00:00:00:00:00"
        assert mac_to_str(bytes([0xFF] * 6)) == "FF:FF:FF:FF:FF:FF"

    def test_f07_str_to_mac_invalid_formats(self) -> None:
        with pytest.raises(ValueError, match="expected 12 hexadecimal characters"):
            str_to_mac("")
        with pytest.raises(ValueError, match="expected 12 hexadecimal characters"):
            str_to_mac("11:22:33")
        with pytest.raises(ValueError, match="Invalid hexadecimal"):
            str_to_mac("GG:11:22:33:44:55")


# ==============================================================================
# Feature 8: Active Probing Boundaries (5 tests)
# ==============================================================================


class TestFeature08ActiveProbingBoundaries:
    """Feature 8 Boundary: zero addresses, empty SCAN_RSP name, and payload saturation."""

    def test_f08_scan_req_all_zeros_addresses(self) -> None:
        req = build_scan_req(scan_a=bytes(6), adv_a=bytes(6))
        assert len(req) == 14
        assert req[2:8] == bytes(6)
        assert req[8:14] == bytes(6)

    def test_f08_scan_req_all_ones_addresses(self) -> None:
        req = build_scan_req(scan_a=bytes([0xFF] * 6), adv_a=bytes([0xFF] * 6))
        assert len(req) == 14
        assert req[2:8] == bytes([0xFF] * 6)
        assert req[8:14] == bytes([0xFF] * 6)

    def test_f08_scan_rsp_zero_length_name(self) -> None:
        rsp = build_scan_rsp(adv_a=bytes(6), local_name="")
        # 2B header + 6B AdvA + 2B empty name AD structure = 10B
        assert len(rsp) == 10
        assert rsp[1] == 8
        frame = dissect_advertising_pdu(rsp)
        assert frame.device_name == ""

    def test_f08_scan_rsp_max_name_saturation(self) -> None:
        # Max AD data is 31 bytes: 1B length + 1B type (0x09) + 29B name = 31 bytes
        name_29 = "A" * 29
        rsp = build_scan_rsp(adv_a=bytes(6), local_name=name_29)
        assert len(rsp) == 39
        assert rsp[1] == 37
        frame = dissect_advertising_pdu(rsp)
        assert frame.device_name == name_29

    def test_f08_scan_rsp_oversized_name_raises(self) -> None:
        # 30 chars name -> 32B AD data > 31B limit
        name_30 = "A" * 30
        with pytest.raises(ValueError, match="31-byte limit"):
            build_scan_rsp(adv_a=bytes(6), local_name=name_30)


# ==============================================================================
# Feature 9: Burst Injection Timing Boundaries (5 tests)
# ==============================================================================


class TestFeature09BurstTimingBoundaries:
    """Feature 9 Boundary: timing calculation limits, negative durations, and zero interval."""

    def test_f09_burst_helper_estimate_packet_count_boundary(self) -> None:
        # 0.02s (20ms) duration at 20ms interval = 1 packet
        count = BurstCycleHelper.estimate_packet_count(0.02, 20)
        assert count == 1

    def test_f09_burst_helper_large_duration(self) -> None:
        # 3600s at 100ms interval = 36,000 packets
        count = BurstCycleHelper.estimate_packet_count(3600.0, 100)
        assert count == 36000

    def test_f09_burst_helper_zero_interval_raises(self) -> None:
        with pytest.raises(ValueError, match="interval_ms must be positive"):
            BurstCycleHelper.estimate_packet_count(5.0, 0)

    def test_f09_burst_helper_negative_duration_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            BurstCycleHelper.estimate_packet_count(-1.0, 100)

    def test_f09_burst_helper_empty_profiles_raises(self) -> None:
        helper = BurstCycleHelper()
        with pytest.raises(ValueError, match="No burst profiles configured"):
            helper.next_profile()


# ==============================================================================
# Feature 10: Wire Framing Boundaries (5 tests)
# ==============================================================================


class TestFeature10WireFramingBoundaries:
    """Feature 10 Boundary: empty lines, whitespace, truncated bodies, and short messages."""

    def test_f10_empty_line_decode_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot decode empty wire line"):
            decode_msg(b"")

    def test_f10_whitespace_only_line_decode_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot decode empty wire line"):
            decode_msg(b"   \r\n\t  ")

    def test_f10_too_short_payload_decode_raises(self) -> None:
        # Base64 for a single byte b"\x01" is "AQ=="
        with pytest.raises(ValueError, match="too short"):
            decode_msg(b"AQ==\r\n")

    def test_f10_packet_message_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="PacketMessage body too short"):
            PacketMessage(bytes(9))

    def test_f10_state_message_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="StateMessage body too short"):
            StateMessage(b"")


# ==============================================================================
# Feature 11: Mock Device Boundaries (5 tests)
# ==============================================================================


class TestFeature11MockDeviceBoundaries:
    """Feature 11 Boundary: timeout zero, closed operations, and unmapped channels."""

    def test_f11_mock_serial_read_empty_timeout(self) -> None:
        ser = MockSerialInterface(timeout=0.0)
        assert ser.read(10) == b""
        assert ser.readline() == b""

    def test_f11_mock_serial_write_closed_raises(self) -> None:
        ser = MockSerialInterface()
        ser.close()
        with pytest.raises(RuntimeError, match="closed"):
            ser.write(b"data\r\n")

    def test_f11_bus_unregistered_device_state(self) -> None:
        bus = VirtualRadioBus()
        ser_unregistered = MockSerialInterface()
        assert bus.get_state(ser_unregistered) is None

    def test_f11_controller_read_empty_queue(self) -> None:
        ctrl = SniffleDeviceController(port="mock://dev", mock=True)
        ctrl.open()
        assert ctrl.read_packet(timeout=0.0) is None
        ctrl.close()

    def test_f11_bus_non_adv_channel_delivery(self) -> None:
        bus = VirtualRadioBus()
        ctrl = SniffleDeviceController(port="mock://dev", mock=True, bus=bus)
        ctrl.open()
        ctrl.start_sniffing(chan=37)
        # Deliver on data channel 10 (sniffer is on 37)
        bus.deliver_raw_packet(pdu=b"\x00\x06\x11\x22\x33\x44\x55\x66", chan=10, rssi=-60)
        assert ctrl.read_packet(timeout=0.02) is None
        ctrl.close()


# ==============================================================================
# Feature 12: Topology A Boundaries (5 tests)
# ==============================================================================


class TestFeature12TopologyABoundaries:
    """Feature 12 Boundary: 31-byte limit, 0-byte payload, not-started injection."""

    def test_f12_inject_not_running_raises(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        with pytest.raises(RuntimeError, match="Topology A is not running"):
            topo.inject_beacon(adv_data=bytes([0x02, 0x01, 0x06]))

    def test_f12_zero_length_adv_data(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        topo.inject_beacon(adv_data=b"", interval_ms=50, mode=2)
        assert topo.stimuli_count == 1
        topo.stop()

    def test_f12_exact_31_byte_adv_data(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        payload = bytes([0xAA] * 31)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        assert topo.stimuli_count == 1
        topo.stop()

    def test_f12_read_packet_timeout_zero(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        assert topo.read_packet(timeout=0.0) is None
        topo.stop()

    def test_f12_drain_packets_empty(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        assert topo.observer.drain_packets() == []
        topo.stop()


# ==============================================================================
# Feature 13: Topology B Boundaries (5 tests)
# ==============================================================================


class TestFeature13TopologyBBoundaries:
    """Feature 13 Boundary: channel pairs, idempotent lifecycle, empty queue timeouts."""

    def test_f13_identical_channels_cli_rejection(self) -> None:
        ret = main(["topology-b", "--mock", "--chan1", "38", "--chan2", "38"])
        assert ret == 2

    def test_f13_outermost_primary_channels(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=39)
        topo.start()
        assert topo.chan1 == 37
        assert topo.chan2 == 39
        topo.stop()

    def test_f13_double_start_is_idempotent(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        topo.start()  # Should not raise
        assert topo.is_running
        topo.stop()

    def test_f13_double_stop_is_idempotent(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        topo.stop()
        topo.stop()  # Should not raise
        assert not topo.is_running

    def test_f13_read_merged_packet_timeout_zero(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        assert topo.read_merged_packet(timeout=0.0) is None
        topo.stop()


# ==============================================================================
# Feature 14: Dissector Boundaries (5 tests)
# ==============================================================================


class TestFeature14DissectorBoundaries:
    """Feature 14 Boundary: minimal PDU, truncated payloads, UTF-8 fallback, length extremes."""

    def test_f14_minimum_pdu_length_2_bytes(self) -> None:
        # PDU with valid AdvA and 0-byte AD payload
        frame = dissect_advertising_pdu(bytes([0x00, 0x06]) + bytes(6))
        assert frame.pdu_type == "ADV_IND"
        assert frame.length == 6
        assert not frame.is_malformed
        assert frame.device_name is None

    def test_f14_pdu_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2 bytes"):
            dissect_advertising_pdu(bytes([0x00]))

    def test_f14_truncated_pdu_marked_malformed(self) -> None:
        # Declares 10 bytes payload, but only 2 provided
        frame = dissect_advertising_pdu(bytes([0x00, 0x0A, 0x01, 0x02]))
        assert frame.is_malformed is True
        assert "Truncated PDU payload" in (frame.error_details or "")

    def test_f14_corrupted_utf8_fallback(self) -> None:
        # Invalid UTF-8 sequence in Complete Local Name (0x09)
        adv_a = bytes(6)
        invalid_utf8 = b"\xFF\xFE\xFD"
        ad_payload = bytes([len(invalid_utf8) + 1, 0x09]) + invalid_utf8
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        # Should decode gracefully with hex representation fallback
        assert frame.device_name == "<hex:fffefd>"

    def test_f14_max_complete_local_name(self) -> None:
        adv_a = bytes(6)
        name_23 = "PoPETs2025TestLongName!"
        ad_payload = bytes([len(name_23) + 1, 0x09]) + name_23.encode("utf-8")
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.device_name == name_23


# ==============================================================================
# Feature 15: MSD Boundaries (5 tests)
# ==============================================================================


class TestFeature15MsdBoundaries:
    """Feature 15 Boundary: company IDs 0x0000/0xFFFF, empty data, truncated sub-records."""

    def test_f15_msd_min_length_2_bytes(self) -> None:
        # Only company ID (0x004C Apple), 0 bytes payload
        adv_a = bytes(6)
        ad_payload = bytes([0x03, 0xFF, 0x4C, 0x00])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        assert frame.manufacturer_data[0].company_id == 0x004C
        assert frame.manufacturer_data[0].data == b""

    def test_f15_msd_apple_truncated_continuity(self) -> None:
        adv_a = bytes(6)
        # Apple MSD with sub-type 0x05 declaring length 10, but only 2 bytes provided
        ad_payload = bytes([0x06, 0xFF, 0x4C, 0x00, 0x05, 0x0A, 0x01, 0x02])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        assert frame.manufacturer_data[0].company_id == 0x004C

    def test_f15_msd_microsoft_truncated(self) -> None:
        adv_a = bytes(6)
        # Microsoft MSD requires >= 25 bytes for full CDP decode; 5 bytes should decode safely as generic
        ad_payload = bytes([0x07, 0xFF, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        assert frame.manufacturer_data[0].company_id == 0x0006

    def test_f15_msd_saturated_29_bytes(self) -> None:
        adv_a = bytes(6)
        # 29 bytes MSD (total AD: 1B len + 1B type + 29B data = 31B payload)
        msd_data = bytes([0x18, 0x01]) + bytes([0xAA] * 27)
        ad_payload = bytes([len(msd_data) + 1, 0xFF]) + msd_data
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        assert frame.manufacturer_data[0].company_id == 0x0118

    def test_f15_msd_company_id_boundaries(self) -> None:
        adv_a = bytes(6)
        ad_0 = bytes([0x03, 0xFF, 0x00, 0x00])
        ad_f = bytes([0x03, 0xFF, 0xFF, 0xFF])
        pdu = bytes([0x00, len(adv_a) + len(ad_0) + len(ad_f)]) + adv_a + ad_0 + ad_f
        frame = dissect_advertising_pdu(pdu)
        cids = [rec.company_id for rec in frame.manufacturer_data]
        assert 0x0000 in cids
        assert 0xFFFF in cids


# ==============================================================================
# Feature 16: Service UUID Extractor Boundaries (5 tests)
# ==============================================================================


class TestFeature16ServiceUuidBoundaries:
    """Feature 16 Boundary: odd-length UUID lists, truncated 128-bit records, empty payloads."""

    def test_f16_odd_length_16bit_uuids_malformed(self) -> None:
        adv_a = bytes(6)
        # 3 bytes value: 1 valid 16-bit UUID (0x180D) + 1 trailing dangling byte (0x55)
        ad_payload = bytes([0x04, 0x03, 0x0D, 0x18, 0x55])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert 0x180D in frame.service_uuids_16
        assert frame.is_malformed is True

    def test_f16_odd_length_32bit_uuids_malformed(self) -> None:
        adv_a = bytes(6)
        # 5 bytes value: 1 valid 32-bit UUID + 1 trailing byte
        ad_payload = bytes([0x06, 0x05, 0x78, 0x56, 0x34, 0x12, 0x99])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert 0x12345678 in frame.service_uuids_32
        assert frame.is_malformed is True

    def test_f16_truncated_128bit_uuids_malformed(self) -> None:
        adv_a = bytes(6)
        # 15 bytes value (needs 16 bytes for 128-bit UUID)
        ad_payload = bytes([0x10, 0x07]) + bytes(15)
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.service_uuids_128) == 0
        assert frame.is_malformed is True

    def test_f16_service_data_16bit_empty_payload(self) -> None:
        adv_a = bytes(6)
        # AD type 0x16 with 2 bytes (UUID 0x180F only, no payload bytes)
        ad_payload = bytes([0x03, 0x16, 0x0F, 0x18])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert "0x180F" in frame.service_data
        assert frame.service_data["0x180F"] == b""

    def test_f16_service_data_128bit_truncated(self) -> None:
        adv_a = bytes(6)
        # AD type 0x21 with 10 bytes (< 16 bytes for UUID)
        ad_payload = bytes([0x0B, 0x21]) + bytes(10)
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.is_malformed is True


# ==============================================================================
# Feature 17: Address Classification Boundaries (5 tests)
# ==============================================================================


class TestFeature17AddressClassificationBoundaries:
    """Feature 17 Boundary: formats with -, without :, invalid lengths, and MSB values."""

    def test_f17_addr_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            classify_address(bytes(5))
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            classify_address(bytes(7))

    def test_f17_addr_invalid_string_format_raises(self) -> None:
        with pytest.raises(ValueError, match="expected 12 hexadecimal characters"):
            classify_address("invalid-mac-str")

    def test_f17_addr_hyphen_delimiter_parsing(self) -> None:
        mac_str = "C0-11-22-22-11-C0"
        addr_type = classify_address(mac_str, is_random=True)
        assert addr_type == BleAddressType.RANDOM_STATIC

    def test_f17_addr_no_delimiter_parsing(self) -> None:
        mac_str = "c011222211c0"
        addr_type = classify_address(mac_str, is_random=True)
        assert addr_type == BleAddressType.RANDOM_STATIC

    def test_f17_addr_boundary_all_zeros_and_all_ones(self) -> None:
        # All zeros with is_random=True is classified as NRPA
        assert classify_address("00:00:00:00:00:00", is_random=True) == BleAddressType.NRPA
        # All ones with is_random=True (0xFF top bits 11b) is classified as RANDOM_STATIC
        assert classify_address("FF:FF:FF:FF:FF:FF", is_random=True) == BleAddressType.RANDOM_STATIC


# ==============================================================================
# Feature 18: PCAP Boundaries (5 tests)
# ==============================================================================


class TestFeature18PcapBoundaries:
    """Feature 18 Boundary: RSSI clamping, microsecond rollover across 2^32, empty PCAP."""

    def test_f18_rssi_boundary_clamping(self) -> None:
        assert normalize_rssi(-128) == -128
        assert normalize_rssi(0) == 0
        assert normalize_rssi(127) == 127

    def test_f18_rssi_out_of_bounds_clamped(self) -> None:
        assert normalize_rssi(-200) == -128
        assert normalize_rssi(300) == 127

    def test_f18_timestamp_rollover_unwrapping(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "rollover.pcap"
        with PcapBleWriter(pcap_file, base_epoch=1000.0) as writer:
            pdu = bytes([0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            # Timestamp right before 2^32 rollover
            writer.write_packet(ts_usec=4_294_960_000, aa=0x8E89BED6, chan=37, rssi=-60, packet=pdu)
            # Timestamp wrapped after 2^32 rollover
            writer.write_packet(ts_usec=1_000, aa=0x8E89BED6, chan=37, rssi=-60, packet=pdu)

        with PcapBleReader(pcap_file) as reader:
            pkts = list(reader)
            assert len(pkts) == 2
            # Second packet's calculated epoch must be strictly greater than first packet's epoch
            assert pkts[1].ts_epoch > pkts[0].ts_epoch

    def test_f18_empty_pcap_read_zero_packets(self, tmp_path: Path) -> None:
        empty_pcap = tmp_path / "empty.pcap"
        with PcapBleWriter(empty_pcap):
            pass
        with PcapBleReader(empty_pcap) as reader:
            assert list(reader) == []

    def test_f18_writer_double_close(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "double_close.pcap"
        writer = PcapBleWriter(pcap_file)
        writer.close()
        writer.close()  # Must be idempotent and not raise
        assert pcap_file.exists()


# ==============================================================================
# Feature 19: Telemetry Boundaries (5 tests)
# ==============================================================================


class TestFeature19TelemetryBoundaries:
    """Feature 19 Boundary: zero packet sessions, extreme RSSI, and latency threshold."""

    def test_f19_empty_telemetry_export_json(self, tmp_path: Path) -> None:
        session = TelemetrySession(topology="Topology A")
        out_json = tmp_path / "empty.json"
        session.export_json(out_json)
        data = json.loads(out_json.read_text(encoding="utf-8"))
        assert data["metadata"]["total_packets"] == 0
        assert data["metadata"]["unique_devices_count"] == 0
        assert data["devices"] == []

    def test_f19_empty_telemetry_export_csv(self, tmp_path: Path) -> None:
        session = TelemetrySession(topology="Topology A")
        out_csv = tmp_path / "empty.csv"
        session.export_csv(out_csv)
        lines = [line.strip() for line in out_csv.read_text(encoding="utf-8").splitlines() if line.strip()]
        # Only header line
        assert len(lines) == 1
        assert "mac_address" in lines[0]

    def test_f19_telemetry_rssi_min_max_extremes(self) -> None:
        session = TelemetrySession(topology="TestTopology")
        adv_a = bytes.fromhex("112233445566")
        pdu = bytes([0x00, 0x06]) + adv_a
        session.record_packet(dissect_advertising_pdu(pdu, chan=37, rssi=-128))
        session.record_packet(dissect_advertising_pdu(pdu, chan=37, rssi=127))
        dev = session.devices["11:22:33:44:55:66"]
        assert dev.rssi_min == -128
        assert dev.rssi_max == 127

    def test_f19_correlator_latency_boundary_match(self) -> None:
        correlator = StimulusResponseCorrelator(max_latency_usec=1_000_000)
        stim_mac = bytes.fromhex("c011222211c0")
        resp_mac = bytes.fromhex("112233445566")
        correlator.register_stimulus(
            adv_a=stim_mac,
            beacon_type="iBeacon",
            start_time_usec=1000,
            duration_usec=0,
        )

        # Response exactly at 1,000,000 us latency (ts = 1000 + 1,000,000 = 1,001,000)
        scan_req = build_scan_req(scan_a=resp_mac, adv_a=stim_mac)
        frame = dissect_advertising_pdu(scan_req, ts_usec=1_001_000)
        match = correlator.process_frame(frame)
        assert match is not None

    def test_f19_correlator_latency_exceeded_no_match(self) -> None:
        correlator = StimulusResponseCorrelator(max_latency_usec=1_000_000)
        stim_mac = bytes.fromhex("c011222211c0")
        resp_mac = bytes.fromhex("112233445566")
        correlator.register_stimulus(
            adv_a=stim_mac,
            beacon_type="iBeacon",
            start_time_usec=1000,
            duration_usec=0,
        )

        # Response at 1,000,001 us latency (ts = 1000 + 1,000,001 = 1,001,001)
        scan_req = build_scan_req(scan_a=resp_mac, adv_a=stim_mac)
        frame = dissect_advertising_pdu(scan_req, ts_usec=1_001_001)
        match = correlator.process_frame(frame)
        assert match is None


# ==============================================================================
# Feature 20: CLI Boundaries (5 tests)
# ==============================================================================


class TestFeature20CliBoundaries:
    """Feature 20 Boundary: interval range (20..65535 ms), duration zero, error exit codes."""

    def test_f20_cli_duration_zero(self) -> None:
        # duration 0.0 must complete cleanly and return 0
        ret = main(["topology-a", "--mock", "--duration-sec", "0.0"])
        assert ret == 0

    def test_f20_cli_interval_min_valid(self) -> None:
        # 20 ms is the minimum valid advertising interval
        ret = main(["topology-a", "--mock", "--duration-sec", "0.01", "--interval-ms", "20"])
        assert ret == 0

    def test_f20_cli_interval_max_valid(self) -> None:
        # 65535 ms is the maximum valid uint16 interval
        ret = main(["topology-a", "--mock", "--duration-sec", "0.01", "--interval-ms", "65535"])
        assert ret == 0

    def test_f20_cli_interval_below_min_rejected(self) -> None:
        # 19 ms is below minimum valid interval -> error code 2
        ret = main(["topology-a", "--mock", "--duration-sec", "0.1", "--interval-ms", "19"])
        assert ret == 2

    def test_f20_cli_interval_above_max_rejected(self) -> None:
        # 65536 ms is above maximum valid uint16 interval -> error code 2
        ret = main(["topology-a", "--mock", "--duration-sec", "0.1", "--interval-ms", "65536"])
        assert ret == 2
