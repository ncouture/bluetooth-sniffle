"""Tier 1: Feature Isolation Tests (Milestone 5).

Verifies all 20 core features of the Bluetooth-Sniffle testbed in isolation
per TEST_INFRA.md and PoPETs 2025-0103. Exactly 5 tests per feature (100 tests total).
"""

from __future__ import annotations

import json
import struct
import time
from pathlib import Path
from uuid import UUID

import pytest

from bluetooth_sniffle.cli import create_parser, main
from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.protocol.beacons import (
    ALTBEACON_CODE,
    APPLE_COMPANY_ID,
    RADIUS_NETWORKS_ID,
    BurstCycleHelper,
    BurstProfile,
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
)
from bluetooth_sniffle.protocol.probing import (
    build_scan_req,
    build_scan_rsp,
)
from bluetooth_sniffle.protocol.wire import (
    COMMAND_SETCHANAAPHY,
    MEASUREMENT_VERSION,
    MESSAGE_BLEFRAME,
    MarkerMessage,
    MeasurementMessage,
    PacketMessage,
    StateMessage,
    decode_msg,
    encode_cmd,
    encode_msg,
)
from bluetooth_sniffle.sniff.correlation import (
    CorrelationMatch,
    StimulusResponseCorrelator,
)
from bluetooth_sniffle.sniff.dissector import (
    BleAddressType,
    EddystoneTlmInfo,
    EddystoneUidInfo,
    EddystoneUrlInfo,
    GaenInfo,
    classify_address,
    dissect_advertising_pdu,
)
from bluetooth_sniffle.sniff.pcap import (
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    PCAP_MAGIC_USEC,
    PcapBleReader,
    PcapBleWriter,
    crc_ble_reverse,
)
from bluetooth_sniffle.sniff.telemetry import TelemetrySession
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator

# ==============================================================================
# Feature 1: Apple iBeacon Encoder (5 tests)
# ==============================================================================


class TestFeature01AppleIBeaconEncoder:
    """Feature 1: Bit-for-bit AD structure for Apple iBeacon."""

    def test_f01_ibeacon_standard_structure(self) -> None:
        raw = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=2,
            tx_power=-59,
        )
        assert len(raw) == 30
        assert raw[0:3] == bytes([0x02, 0x01, 0x06])
        assert raw[3:5] == bytes([0x1A, 0xFF])
        assert struct.unpack("<H", raw[5:7])[0] == APPLE_COMPANY_ID
        assert raw[7:9] == bytes([0x02, 0x15])
        assert raw[9:25] == UUID("e2c56db5-dffb-48d2-b060-d0f5a71096e0").bytes
        assert struct.unpack(">HH", raw[25:29]) == (1, 2)
        assert struct.unpack("b", raw[29:30])[0] == -59

    def test_f01_ibeacon_endianness_major_minor(self) -> None:
        raw = build_ibeacon(
            uuid=UUID("11223344-5566-7788-99aa-bbccddeeff00"),
            major=0x1234,
            minor=0x5678,
            tx_power=-60,
        )
        assert raw[25:27] == bytes([0x12, 0x34])
        assert raw[27:29] == bytes([0x56, 0x78])

    def test_f01_ibeacon_string_uuid(self) -> None:
        raw_str = build_ibeacon(
            uuid="00112233-4455-6677-8899-aabbccddeeff",
            major=10,
            minor=20,
            tx_power=-50,
        )
        raw_obj = build_ibeacon(
            uuid=UUID("00112233-4455-6677-8899-aabbccddeeff"),
            major=10,
            minor=20,
            tx_power=-50,
        )
        assert raw_str == raw_obj

    def test_f01_ibeacon_custom_flags(self) -> None:
        raw = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=1,
            tx_power=-59,
            flags=0x04,
        )
        assert raw[0:3] == bytes([0x02, 0x01, 0x04])

    def test_f01_ibeacon_negative_tx_power(self) -> None:
        raw_neg59 = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=1,
            tx_power=-59,
        )
        raw_neg100 = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=1,
            tx_power=-100,
        )
        assert raw_neg59[-1] == 0xC5
        assert raw_neg100[-1] == 0x9C


# ==============================================================================
# Feature 2: AltBeacon Encoder (5 tests)
# ==============================================================================


class TestFeature02AltBeaconEncoder:
    """Feature 2: Bit-for-bit AD structure for Radius Networks AltBeacon."""

    def test_f02_altbeacon_standard_structure(self) -> None:
        beacon_id = bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002")
        raw = build_altbeacon(
            mfg_id=RADIUS_NETWORKS_ID,
            beacon_id=beacon_id,
            ref_rssi=-59,
            mfg_reserved=0x00,
        )
        assert len(raw) == 31
        assert raw[0:3] == bytes([0x02, 0x01, 0x06])
        assert raw[3:5] == bytes([0x1B, 0xFF])
        assert struct.unpack("<H", raw[5:7])[0] == RADIUS_NETWORKS_ID
        assert struct.unpack(">H", raw[7:9])[0] == ALTBEACON_CODE
        assert raw[9:29] == beacon_id
        assert struct.unpack("b", raw[29:30])[0] == -59
        assert raw[30] == 0x00

    def test_f02_altbeacon_custom_manufacturer_id(self) -> None:
        beacon_id = bytes(range(20))
        raw = build_altbeacon(mfg_id=0x004C, beacon_id=beacon_id, ref_rssi=-65)
        assert struct.unpack("<H", raw[5:7])[0] == 0x004C

    def test_f02_altbeacon_beacon_id_length(self) -> None:
        beacon_id = bytes([0xAA] * 20)
        raw = build_altbeacon(mfg_id=0x0118, beacon_id=beacon_id, ref_rssi=-70)
        assert raw[9:29] == beacon_id

    def test_f02_altbeacon_mfg_reserved_byte(self) -> None:
        raw = build_altbeacon(
            mfg_id=0x0118,
            beacon_id=bytes(20),
            ref_rssi=-55,
            mfg_reserved=0xAB,
        )
        assert raw[30] == 0xAB

    def test_f02_altbeacon_flags_customization(self) -> None:
        raw = build_altbeacon(
            mfg_id=0x0118,
            beacon_id=bytes(20),
            ref_rssi=-55,
            flags=0x1A,
        )
        assert raw[0:3] == bytes([0x02, 0x01, 0x1A])


# ==============================================================================
# Feature 3: Eddystone-UID Encoder (5 tests)
# ==============================================================================


class TestFeature03EddystoneUidEncoder:
    """Feature 3: 0xFEAA Service Data with Eddystone-UID frame."""

    def test_f03_eddystone_uid_standard_structure(self) -> None:
        ns = bytes.fromhex("0102030405060708090a")
        inst = bytes.fromhex("010203040506")
        raw = build_eddystone_uid(namespace=ns, instance=inst, tx_power=-20)
        assert len(raw) == 31
        assert raw[0:3] == bytes([0x02, 0x01, 0x06])
        assert raw[3:7] == bytes([0x03, 0x03, 0xAA, 0xFE])
        assert raw[7:9] == bytes([0x17, 0x16])
        assert raw[9:11] == bytes([0xAA, 0xFE])
        assert raw[11] == 0x00  # UID frame type
        assert struct.unpack("b", raw[12:13])[0] == -20
        assert raw[13:23] == ns
        assert raw[23:29] == inst
        assert raw[29:31] == bytes([0x00, 0x00])

    def test_f03_eddystone_uid_lengths(self) -> None:
        ns = bytes([0x11] * 10)
        inst = bytes([0x22] * 6)
        raw = build_eddystone_uid(namespace=ns, instance=inst, tx_power=-10)
        assert len(raw) == 31

    def test_f03_eddystone_uid_tx_power_calibration(self) -> None:
        raw = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=0)
        assert raw[12] == 0x00
        raw_neg = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=-20)
        assert raw_neg[12] == 0xEC

    def test_f03_eddystone_uid_rfu_field(self) -> None:
        raw = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=-15)
        assert raw[29:31] == bytes([0x00, 0x00])

    def test_f03_eddystone_uid_dissector_roundtrip(self) -> None:
        ns = bytes.fromhex("aabbccddeeff00112233")
        inst = bytes.fromhex("445566778899")
        ad_payload = build_eddystone_uid(namespace=ns, instance=inst, tx_power=-20)
        pdu = bytes([0x02, len(ad_payload) + 6]) + bytes(6) + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-UID"
        assert isinstance(frame.beacon_info, EddystoneUidInfo)
        assert frame.beacon_info.namespace == ns
        assert frame.beacon_info.instance == inst
        assert frame.beacon_info.tx_power == -20


# ==============================================================================
# Feature 4: Eddystone-URL Encoder (5 tests)
# ==============================================================================


class TestFeature04EddystoneUrlEncoder:
    """Feature 4: 0xFEAA Service Data with Eddystone-URL frame."""

    def test_f04_eddystone_url_https_www_prefix(self) -> None:
        raw = build_eddystone_url(url="https://www.example.com", tx_power=-18)
        assert raw[11] == 0x10  # Frame type URL
        assert raw[13] == 0x01  # Scheme code 1 = https://www.

    def test_f04_eddystone_url_https_prefix(self) -> None:
        raw = build_eddystone_url(url="https://example.com/test", tx_power=-18)
        assert raw[13] == 0x03  # Scheme code 3 = https://

    def test_f04_eddystone_url_http_prefix(self) -> None:
        raw = build_eddystone_url(url="http://example.org", tx_power=-15)
        assert raw[13] == 0x02  # Scheme code 2 = http://

    def test_f04_eddystone_url_tld_suffix_expansion(self) -> None:
        raw = build_eddystone_url(url="https://petsymposium.org/", tx_power=-18)
        assert raw[-1] == 0x01  # ".org/" code

    def test_f04_eddystone_url_dissector_roundtrip(self) -> None:
        ad_payload = build_eddystone_url(url="https://petsymposium.org/", tx_power=-18)
        pdu = bytes([0x02, len(ad_payload) + 6]) + bytes(6) + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-URL"
        assert isinstance(frame.beacon_info, EddystoneUrlInfo)
        assert "petsymposium.org" in frame.beacon_info.url


# ==============================================================================
# Feature 5: Eddystone-TLM Encoder (5 tests)
# ==============================================================================


class TestFeature05EddystoneTlmEncoder:
    """Feature 5: 0xFEAA Service Data with Eddystone-TLM frame."""

    def test_f05_eddystone_tlm_version_zero(self) -> None:
        raw = build_eddystone_tlm(vbatt_mv=3300, temp_c=25.0, adv_cnt=1000, sec_cnt=10000)
        assert raw[11] == 0x20  # TLM frame type
        assert raw[12] == 0x00  # TLM version 0

    def test_f05_eddystone_tlm_battery_millivolts(self) -> None:
        raw = build_eddystone_tlm(vbatt_mv=3000, temp_c=20.0, adv_cnt=1, sec_cnt=10)
        vbatt = struct.unpack(">H", raw[13:15])[0]
        assert vbatt == 3000

    def test_f05_eddystone_tlm_temperature_fixed_point_8_8(self) -> None:
        raw = build_eddystone_tlm(vbatt_mv=3000, temp_c=22.5, adv_cnt=1, sec_cnt=10)
        assert raw[15] == 22
        assert raw[16] == 128  # 0.5 * 256 = 128

    def test_f05_eddystone_tlm_adv_and_sec_counters(self) -> None:
        raw = build_eddystone_tlm(vbatt_mv=3300, temp_c=25.0, adv_cnt=0x12345678, sec_cnt=0x09ABCDEF)
        adv_cnt, sec_cnt = struct.unpack(">II", raw[17:25])
        assert adv_cnt == 0x12345678
        assert sec_cnt == 0x09ABCDEF

    def test_f05_eddystone_tlm_dissector_roundtrip(self) -> None:
        ad_payload = build_eddystone_tlm(vbatt_mv=3300, temp_c=22.5, adv_cnt=500, sec_cnt=2500)
        pdu = bytes([0x02, len(ad_payload) + 6]) + bytes(6) + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-TLM"
        assert isinstance(frame.beacon_info, EddystoneTlmInfo)
        assert frame.beacon_info.vbatt_mv == 3300
        assert frame.beacon_info.temp_c == pytest.approx(22.5, abs=0.01)
        assert frame.beacon_info.adv_cnt == 500
        assert frame.beacon_info.sec_cnt == 2500


# ==============================================================================
# Feature 6: GAEN Encoder (5 tests)
# ==============================================================================


class TestFeature06GaenEncoder:
    """Feature 6: 0xFD6F Service Data for Google/Apple Exposure Notification."""

    def test_f06_gaen_standard_structure(self) -> None:
        rpi = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        aem = bytes.fromhex("11223344")
        raw = build_gaen(rpi=rpi, aem=aem)
        assert len(raw) == 31
        assert raw[0:3] == bytes([0x02, 0x01, 0x1A])
        assert raw[3:7] == bytes([0x03, 0x03, 0x6F, 0xFD])
        assert raw[7:9] == bytes([0x17, 0x16])
        assert raw[9:11] == bytes([0x6F, 0xFD])

    def test_f06_gaen_flags_setting(self) -> None:
        rpi = bytes(16)
        aem = bytes(4)
        raw = build_gaen(rpi=rpi, aem=aem, flags=0x06)
        assert raw[0:3] == bytes([0x02, 0x01, 0x06])

    def test_f06_gaen_rpi_exact_bytes(self) -> None:
        rpi = bytes(range(16))
        aem = bytes(4)
        raw = build_gaen(rpi=rpi, aem=aem)
        assert raw[11:27] == rpi

    def test_f06_gaen_aem_exact_bytes(self) -> None:
        rpi = bytes(16)
        aem = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        raw = build_gaen(rpi=rpi, aem=aem)
        assert raw[27:31] == aem

    def test_f06_gaen_dissector_roundtrip(self) -> None:
        rpi = bytes.fromhex("00112233445566778899aabbccddeeff")
        aem = bytes.fromhex("cafebabe")
        ad_payload = build_gaen(rpi=rpi, aem=aem)
        pdu = bytes([0x02, len(ad_payload) + 6]) + bytes(6) + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "GAEN"
        assert isinstance(frame.beacon_info, GaenInfo)
        assert frame.beacon_info.rpi == rpi
        assert frame.beacon_info.aem == aem


# ==============================================================================
# Feature 7: Palindromic MAC Generator (5 tests)
# ==============================================================================


class TestFeature07PalindromicMacGenerator:
    """Feature 7: Palindromic MAC address generation and symmetry."""

    def test_f07_palindromic_mac_static_random(self) -> None:
        mac = generate_palindromic_mac("static", seed=b"test-seed-1")
        assert len(mac) == 6
        assert is_palindromic_mac(mac)
        assert (mac[0] & 0xC0) == 0xC0

    def test_f07_palindromic_mac_nrpa(self) -> None:
        mac = generate_palindromic_mac("nrpa", seed=b"test-seed-2")
        assert len(mac) == 6
        assert is_palindromic_mac(mac)
        assert (mac[0] & 0xC0) == 0x00

    def test_f07_palindromic_mac_rpa(self) -> None:
        mac = generate_palindromic_mac("rpa", seed=b"test-seed-3")
        assert len(mac) == 6
        assert is_palindromic_mac(mac)
        assert (mac[0] & 0xC0) == 0x40

    def test_f07_palindromic_mac_public(self) -> None:
        mac = generate_palindromic_mac("public", seed=b"test-seed-4")
        assert len(mac) == 6
        assert is_palindromic_mac(mac)
        assert (mac[0] & 0x01) == 0  # Individual/unicast

    def test_f07_palindromic_mac_seed_determinism(self) -> None:
        seed = b"reproducible-seed-99"
        mac1 = generate_palindromic_mac("static", seed=seed)
        mac2 = generate_palindromic_mac("static", seed=seed)
        assert mac1 == mac2


# ==============================================================================
# Feature 8: Active Probing Frame Builder (5 tests)
# ==============================================================================


class TestFeature08ActiveProbingFrameBuilder:
    """Feature 8: SCAN_REQ construction and eliciting SCAN_RSP."""

    def test_f08_scan_req_pdu_type_and_length(self) -> None:
        scan_a = bytes.fromhex("112233445566")
        adv_a = bytes.fromhex("665544332211")
        req = build_scan_req(scan_a=scan_a, adv_a=adv_a)
        assert len(req) == 14
        assert (req[0] & 0x0F) == 0x03  # SCAN_REQ
        assert req[1] == 12  # Payload length

    def test_f08_scan_req_address_flags(self) -> None:
        req = build_scan_req(bytes(6), bytes(6), scan_a_random=True, adv_a_random=False)
        tx_add = (req[0] >> 6) & 1
        rx_add = (req[0] >> 7) & 1
        assert tx_add == 1
        assert rx_add == 0

    def test_f08_scan_rsp_pdu_type_and_header(self) -> None:
        adv_a = bytes.fromhex("c011222211c0")
        rsp = build_scan_rsp(adv_a=adv_a, local_name="TestDevice")
        assert (rsp[0] & 0x0F) == 0x04  # SCAN_RSP
        assert rsp[2:8] == adv_a

    def test_f08_scan_rsp_complete_local_name(self) -> None:
        rsp = build_scan_rsp(adv_a=bytes(6), local_name="PoPETs-2025")
        name_bytes = b"PoPETs-2025"
        ad_len = len(name_bytes) + 1
        assert bytes([ad_len, 0x09]) + name_bytes in rsp

    def test_f08_scan_rsp_dissector_roundtrip(self) -> None:
        adv_a = bytes.fromhex("c033444433c0")
        rsp = build_scan_rsp(adv_a=adv_a, local_name="ProbedDevice-42")
        frame = dissect_advertising_pdu(rsp)
        assert frame.pdu_type == "SCAN_RSP"
        assert frame.device_name == "ProbedDevice-42"
        assert frame.adv_a == "C0:33:44:44:33:C0"


# ==============================================================================
# Feature 9: Burst Injection Engine (5 tests)
# ==============================================================================


class TestFeature09BurstInjectionEngine:
    """Feature 9: Parameterized transmission intervals and burst cycles."""

    def test_f09_generate_burst_cycle_count(self) -> None:
        p1 = BurstProfile(name="Profile1", adv_data=b"\x01")
        p2 = BurstProfile(name="Profile2", adv_data=b"\x02")
        helper = BurstCycleHelper()
        helper.add_profile(p1)
        helper.add_profile(p2)
        assert helper.next_profile() == p1
        assert helper.next_profile() == p2
        assert helper.next_profile() == p1

    def test_f09_burst_sequence_timing_intervals(self) -> None:
        count = BurstCycleHelper.estimate_packet_count(5.0, 100)
        assert count == 50
        duration = BurstCycleHelper.total_cycle_duration(5.0, 3.0)
        assert duration == 8.0

    def test_f09_burst_injection_stimuli_counter(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        assert topo.stimuli_count == 2
        topo.stop()

    def test_f09_burst_injection_mode_configuration(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        payload = bytes([0x02, 0x01, 0x06])
        topo.inject_beacon(adv_data=payload, interval_ms=100, mode=3)
        assert topo.stimuli_count == 1
        topo.stop()

    def test_f09_burst_injection_multiple_beacon_types(self) -> None:
        topo = TopologyAOrchestrator.create_mock()
        topo.start()
        b1 = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
        b2 = build_altbeacon(0x0118, bytes(20), -59)
        seq = [(b1, 0.01), (b2, 0.01)]
        topo.inject_burst_sequence(seq, interval_ms=50, mode=2)
        assert topo.stimuli_count == 2
        topo.stop()


# ==============================================================================
# Feature 10: Base64 Wire Protocol (5 tests)
# ==============================================================================


class TestFeature10Base64WireProtocol:
    """Feature 10: Base64+CRLF framing with word-count prefix."""

    def test_f10_wire_encode_cmd_basic(self) -> None:
        line = encode_cmd([COMMAND_SETCHANAAPHY, 37, 0])
        assert line.endswith(b"\r\n")
        assert len(line) > 2

    def test_f10_wire_decode_msg_packet(self) -> None:
        pdu = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        raw_pkt = PacketMessage.pack(body=pdu, ts=1000000, chan=37, rssi=-60)
        wire_line = encode_msg(MESSAGE_BLEFRAME, raw_pkt)
        word_cnt, msg_type, payload = decode_msg(wire_line)
        unpacked = PacketMessage(payload)
        assert unpacked.chan == 37
        assert unpacked.rssi == -60
        assert unpacked.body == pdu

    def test_f10_wire_marker_message_roundtrip(self) -> None:
        raw = MarkerMessage.pack(marker_data=b"\x12\x34", ts=500000)
        unpacked = MarkerMessage(raw)
        assert unpacked.marker_data == b"\x12\x34"
        assert unpacked.ts == 500000

    def test_f10_wire_state_message_roundtrip(self) -> None:
        raw = StateMessage.pack(3)
        unpacked = StateMessage(raw)
        assert unpacked.state == 3

    def test_f10_wire_measurement_message_unpack(self) -> None:
        raw = MeasurementMessage.pack_version(1, 8, 2, 1)
        meas = MeasurementMessage(raw)
        assert meas.measure_type == MEASUREMENT_VERSION
        assert meas.version == (1, 8, 2, 1)


# ==============================================================================
# Feature 11: Mock Serial & Virtual Radio (5 tests)
# ==============================================================================


class TestFeature11MockSerialAndVirtualRadio:
    """Feature 11: In-memory MockSerialInterface and VirtualRadioBus."""

    def test_f11_mock_serial_write_and_read_lines(self) -> None:
        serial = MockSerialInterface(port="mock://test", timeout=0.1)
        assert serial.is_open
        serial.inject_rx_bytes(b"TEST LINE\r\n")
        line = serial.readline()
        assert line == b"TEST LINE\r\n"
        serial.close()
        assert not serial.is_open

    def test_f11_virtual_radio_bus_delivery(self) -> None:
        bus = VirtualRadioBus()
        dev = MockSerialInterface(port="mock://rx", bus=bus, timeout=0.5)
        st = bus.get_state(dev)
        assert st is not None
        st.channel = 37
        bus.deliver_raw_packet(pdu=b"\x00\x06\x11\x22\x33\x44\x55\x66", chan=37, rssi=-55)
        line = dev.readline()
        assert line != b""
        _, mtype, body = decode_msg(line)
        assert mtype == MESSAGE_BLEFRAME
        pkt = PacketMessage(body)
        assert pkt.chan == 37
        assert pkt.rssi == -55

    def test_f11_virtual_radio_channel_filtering(self) -> None:
        bus = VirtualRadioBus()
        ctrl = SniffleDeviceController(port="mock://dev", mock=True, bus=bus)
        ctrl.open()
        ctrl.start_sniffing(chan=37, hop=False)
        bus.deliver_raw_packet(pdu=b"\x00\x06\x01\x02\x03\x04\x05\x06", chan=38, rssi=-60)
        pkt = ctrl.read_packet(timeout=0.05)
        assert pkt is None
        ctrl.close()

    def test_f11_mock_device_controller_start_sniffing(self) -> None:
        ctrl = SniffleDeviceController(port="mock://dev", mock=True)
        ctrl.open()
        ctrl.start_sniffing(chan=39)
        assert ctrl.channel == 39
        assert ctrl.is_sniffing
        ctrl.close()

    def test_f11_virtual_radio_bus_multi_receiver(self) -> None:
        bus = VirtualRadioBus()
        c1 = SniffleDeviceController(port="mock://c1", mock=True, bus=bus)
        c2 = SniffleDeviceController(port="mock://c2", mock=True, bus=bus)
        c1.open()
        c2.open()
        c1.start_sniffing(chan=37)
        c2.start_sniffing(chan=37)
        bus.deliver_raw_packet(pdu=b"\x02\x06\xaa\xbb\xcc\xdd\xee\xff", chan=37, rssi=-50)
        p1 = c1.read_packet(timeout=0.1)
        p2 = c2.read_packet(timeout=0.1)
        assert p1 is not None and p2 is not None
        c1.close()
        c2.close()


# ==============================================================================
# Feature 12: Dual-Device Topology A (Stim + Obs) (5 tests)
# ==============================================================================


class TestFeature12DualDeviceTopologyA:
    """Feature 12: Topology A (Stimulator + Observer) orchestration."""

    def test_f12_topology_a_create_mock_and_lifecycle(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=38)
        assert not topo.is_running
        topo.start()
        assert topo.is_running
        assert topo.observer_channel == 38
        topo.stop()
        assert not topo.is_running

    def test_f12_topology_a_inject_and_read_packet(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 10, 20, -59)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        assert payload in pkt.body
        topo.stop()

    def test_f12_topology_a_set_stimulus_mac(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        mac = bytes.fromhex("c011222211c0")
        topo.set_stimulus_mac(mac, is_random=True)
        payload = bytes([0x02, 0x01, 0x06])
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        assert mac in pkt.body
        topo.stop()

    def test_f12_topology_a_batch_read_packets(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        payload = bytes([0x02, 0x01, 0x06])
        for _ in range(3):
            topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)
        pkts = topo.get_captured_packets(timeout=0.2)
        assert len(pkts) >= 3
        topo.stop()

    def test_f12_topology_a_stats_reporting(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=39)
        topo.start()
        stats = topo.get_stats()
        assert stats["is_running"] is True
        assert stats["observer_channel"] == 39
        assert "stimuli_count" in stats
        topo.stop()


# ==============================================================================
# Feature 13: Dual-Device Topology B (Dual Obs) (5 tests)
# ==============================================================================


class TestFeature13DualDeviceTopologyB:
    """Feature 13: Topology B (Dual-Channel Sniffer) orchestration."""

    def test_f13_topology_b_create_mock_and_lifecycle(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        assert topo.is_running
        topo.stop()
        assert not topo.is_running

    def test_f13_topology_b_channel_assignment(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=39)
        topo.start()
        assert topo.device1.channel == 37
        assert topo.device2.channel == 39
        topo.stop()

    def test_f13_topology_b_merged_timestamp_stream(self) -> None:
        shared_bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=shared_bus, chan1=37, chan2=38) as topo:
            time.sleep(0.05)
            pdu1 = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            pdu2 = bytes([0x02, 0x06, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])
            shared_bus.deliver_raw_packet(pdu=pdu1, chan=37, rssi=-60)
            shared_bus.deliver_raw_packet(pdu=pdu2, chan=38, rssi=-65)

            merged = topo.get_merged_packets(max_count=10, timeout=0.5)
            assert len(merged) == 2
            assert {pkt.chan for pkt in merged} == {37, 38}
            timestamps = [pkt.ts for pkt in merged]
            assert timestamps == sorted(timestamps)
        topo.stop()

    def test_f13_topology_b_read_merged_packet_timeout(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        pkt = topo.read_merged_packet(timeout=0.01)
        assert pkt is None
        topo.stop()

    def test_f13_topology_b_stats_and_counts(self) -> None:
        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        stats = topo.get_stats()
        assert stats["chan1"] == 37
        assert stats["chan2"] == 38
        assert "merged_packets_total" in stats
        topo.stop()


# ==============================================================================
# Feature 14: BLE PDU Dissector & Local Name (5 tests)
# ==============================================================================


class TestFeature14BlePduDissectorAndLocalName:
    """Feature 14: PDU demuxing and Local Name extraction."""

    def test_f14_dissector_adv_ind_demux(self) -> None:
        # ADV_IND (type 0), length 15: AdvA (6B) + Complete Local Name "Test" (2B header + 4B) + Flags (3B)
        adv_a = bytes.fromhex("112233445566")
        ad_payload = bytes([0x02, 0x01, 0x06, 0x05, 0x09]) + b"Test"
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.pdu_type == "ADV_IND"
        assert frame.device_name == "Test"
        assert frame.complete_local_name == "Test"

    def test_f14_dissector_adv_nonconn_ind_demux(self) -> None:
        adv_a = bytes.fromhex("c011222211c0")
        ad_payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 2, -59)
        pdu = bytes([0x02, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.pdu_type == "ADV_NONCONN_IND"
        assert frame.beacon_type == "iBeacon"

    def test_f14_dissector_scan_req_demux(self) -> None:
        scan_a = bytes.fromhex("c011222211c0")
        adv_a = bytes.fromhex("c033444433c0")
        req = build_scan_req(scan_a, adv_a)
        frame = dissect_advertising_pdu(req)
        assert frame.pdu_type == "SCAN_REQ"
        assert frame.scan_a == "C0:11:22:22:11:C0"
        assert frame.adv_a == "C0:33:44:44:33:C0"

    def test_f14_dissector_shortened_local_name(self) -> None:
        adv_a = bytes(6)
        ad_payload = bytes([0x05, 0x08]) + b"Snif"
        pdu = bytes([0x02, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.shortened_local_name == "Snif"
        assert frame.device_name == "Snif"

    def test_f14_dissector_flags_and_tx_power(self) -> None:
        adv_a = bytes(6)
        ad_payload = bytes([0x02, 0x01, 0x1A, 0x02, 0x0A, 0xF5])  # flags 0x1A, tx_power -11 dBm (0xF5)
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.flags == 0x1A
        assert frame.tx_power_level == -11


# ==============================================================================
# Feature 15: MSD Extraction (Apple, MS, Google) (5 tests)
# ==============================================================================


class TestFeature15MsdExtraction:
    """Feature 15: Manufacturer-Specific Data dissection."""

    def test_f15_msd_apple_continuity_message(self) -> None:
        # Apple MSD with Continuity AirDrop (sub_type 0x05)
        adv_a = bytes(6)
        # Len 7: Type 0xFF, Apple CID 0x004C, sub_type 0x05, len 3, data
        msd_payload = bytes([0x4C, 0x00, 0x05, 0x03, 0x01, 0x02, 0x03])
        ad_payload = bytes([len(msd_payload) + 1, 0xFF]) + msd_payload
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) >= 1
        rec = frame.manufacturer_data[0]
        assert rec.company_id == APPLE_COMPANY_ID
        assert len(rec.apple_messages) >= 1
        assert rec.apple_messages[0].sub_type == 0x05

    def test_f15_msd_altbeacon_radius_networks(self) -> None:
        adv_a = bytes(6)
        payload = build_altbeacon(mfg_id=RADIUS_NETWORKS_ID, beacon_id=bytes(20), ref_rssi=-59)
        pdu = bytes([0x02, len(adv_a) + len(payload)]) + adv_a + payload
        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "AltBeacon"
        assert any(rec.company_id == RADIUS_NETWORKS_ID for rec in frame.manufacturer_data)

    def test_f15_msd_microsoft_cdp_extraction(self) -> None:
        adv_a = bytes(6)
        # MS CID 0x0006, scenario 0x01, dev_type 0x09, flags/salt/hash
        ms_data = bytes([0x06, 0x00, 0x01, 0x09, 0x00, 0x12, 0x34]) + bytes(16)
        ad_payload = bytes([len(ms_data) + 1, 0xFF]) + ms_data
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert any(rec.company_id == 0x0006 for rec in frame.manufacturer_data)

    def test_f15_msd_google_company_id(self) -> None:
        adv_a = bytes(6)
        msd_data = bytes([0xE0, 0x00, 0x01, 0x02, 0x03, 0x04])
        ad_payload = bytes([len(msd_data) + 1, 0xFF]) + msd_data
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert any(rec.company_id == 0x00E0 for rec in frame.manufacturer_data)

    def test_f15_msd_generic_company_record(self) -> None:
        adv_a = bytes(6)
        msd_data = bytes([0x34, 0x12, 0xAA, 0xBB])  # CID 0x1234
        ad_payload = bytes([len(msd_data) + 1, 0xFF]) + msd_data
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert any(rec.company_id == 0x1234 for rec in frame.manufacturer_data)


# ==============================================================================
# Feature 16: Service UUID Extractor (16/32/128) (5 tests)
# ==============================================================================


class TestFeature16ServiceUuidExtractor:
    """Feature 16: 16/32/128-bit UUIDs and Service Data extraction."""

    def test_f16_service_uuid_16bit_list(self) -> None:
        adv_a = bytes(6)
        # AD type 0x03 (Complete 16-bit UUIDs): 0x180D (Heart Rate), 0x180F (Battery)
        ad_payload = bytes([0x05, 0x03, 0x0D, 0x18, 0x0F, 0x18])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert 0x180D in frame.service_uuids_16
        assert 0x180F in frame.service_uuids_16

    def test_f16_service_uuid_32bit_list(self) -> None:
        adv_a = bytes(6)
        # AD type 0x05 (Complete 32-bit UUIDs): 0x12345678
        ad_payload = bytes([0x05, 0x05, 0x78, 0x56, 0x34, 0x12])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert 0x12345678 in frame.service_uuids_32

    def test_f16_service_uuid_128bit_list(self) -> None:
        adv_a = bytes(6)
        u128 = UUID("00112233-4455-6677-8899-aabbccddeeff")
        ad_payload = bytes([17, 0x07]) + u128.bytes
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert u128 in frame.service_uuids_128

    def test_f16_service_data_16bit(self) -> None:
        adv_a = bytes(6)
        # AD type 0x16: 16-bit UUID 0xFEAA + service data
        ad_payload = bytes([0x05, 0x16, 0xAA, 0xFE, 0x10, 0x20])
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert "0xFEAA" in frame.service_data
        assert frame.service_data["0xFEAA"] == bytes([0x10, 0x20])

    def test_f16_service_data_128bit(self) -> None:
        adv_a = bytes(6)
        u128 = UUID("12345678-1234-5678-1234-567812345678")
        sdata = bytes([0xCA, 0xFE])
        ad_payload = bytes([1 + 16 + len(sdata), 0x21]) + u128.bytes + sdata
        pdu = bytes([0x00, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload
        frame = dissect_advertising_pdu(pdu)
        assert str(u128) in frame.service_data
        assert frame.service_data[str(u128)] == sdata


# ==============================================================================
# Feature 17: Address Classification (5 tests)
# ==============================================================================


class TestFeature17AddressClassification:
    """Feature 17: Public, Static Random, NRPA, RPA address classification."""

    def test_f17_addr_class_public(self) -> None:
        mac = generate_palindromic_mac("public")
        assert classify_address(mac, is_random=False) == BleAddressType.PUBLIC

    def test_f17_addr_class_random_static(self) -> None:
        mac = generate_palindromic_mac("static")
        assert classify_address(mac, is_random=True) == BleAddressType.RANDOM_STATIC

    def test_f17_addr_class_nrpa(self) -> None:
        mac = generate_palindromic_mac("nrpa")
        assert classify_address(mac, is_random=True) == BleAddressType.NRPA

    def test_f17_addr_class_rpa(self) -> None:
        mac = generate_palindromic_mac("rpa")
        assert classify_address(mac, is_random=True) == BleAddressType.RPA

    def test_f17_addr_class_tx_add_inference(self) -> None:
        adv_a = bytes.fromhex("c011222211c0")
        # TxAdd = 1 (header bit 6)
        pdu_random = bytes([0x40, 0x06]) + adv_a
        frame_random = dissect_advertising_pdu(pdu_random)
        assert frame_random.adv_a_type == BleAddressType.RANDOM_STATIC.value

        # TxAdd = 0 (Public)
        pdu_public = bytes([0x00, 0x06]) + adv_a
        frame_public = dissect_advertising_pdu(pdu_public)
        assert frame_public.adv_a_type == BleAddressType.PUBLIC.value


# ==============================================================================
# Feature 18: PCAP DLT 256 Wireshark/Crackle Writer (5 tests)
# ==============================================================================


class TestFeature18PcapDlt256Writer:
    """Feature 18: DLT_BLUETOOTH_LE_LL_WITH_PHDR PCAP generation."""

    def test_f18_pcap_global_header_magic_and_dlt(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "test_hdr.pcap"
        with PcapBleWriter(pcap_path):
            pass
        data = pcap_path.read_bytes()
        assert len(data) == 24
        magic, _, _, _, _, _, dlt = struct.unpack("<IHHIIII", data)
        assert magic == PCAP_MAGIC_USEC
        assert dlt == DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def test_f18_pcap_packet_pseudo_header_format(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "test_phdr.pcap"
        with PcapBleWriter(pcap_path) as writer:
            pdu = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            writer.write_packet(ts_usec=1000, aa=0x8E89BED6, chan=37, rssi=-60, packet=pdu)

        raw = pcap_path.read_bytes()
        packet_data = raw[24:]  # Skip global header
        pcap_hdr = packet_data[:16]
        assert len(pcap_hdr) == 16
        pseudo_hdr = packet_data[16:26]
        rf_chan, signal, noise, aa_off, ref_aa, flags = struct.unpack("<BbbBIH", pseudo_hdr)
        assert rf_chan == 0  # BLE 37 -> RF 0
        assert signal == -60

    def test_f18_pcap_writer_reader_roundtrip(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "roundtrip.pcap"
        pdu = bytes([0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        with PcapBleWriter(pcap_path) as writer:
            writer.write_packet(ts_usec=2500000, aa=0x8E89BED6, chan=38, rssi=-55, packet=pdu)

        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 1
            assert pkts[0].rssi == -55
            assert pkts[0].rf_chan == 12  # BLE 38 -> RF 12
            assert pkts[0].body == pdu

    def test_f18_pcap_write_dissected_frame(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "frame_write.pcap"
        pdu = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        frame = dissect_advertising_pdu(pdu, chan=39, rssi=-70, ts_usec=500000)
        with PcapBleWriter(pcap_path) as writer:
            writer.write_dissected_frame(frame)

        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 1
            assert pkts[0].rssi == -70
            assert pkts[0].rf_chan == 39  # BLE 39 -> RF 39

    def test_f18_pcap_crc24_calculation(self) -> None:
        # Standard BLE CRC initialization: reversed 0x555555 is 0xAAAAAA
        data = bytes([0x02, 0x01, 0x06])
        crc = crc_ble_reverse(0xAAAAAA, data)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFFFF


# ==============================================================================
# Feature 19: JSON & CSV Telemetry + Correlation (5 tests)
# ==============================================================================


class TestFeature19JsonCsvTelemetryAndCorrelation:
    """Feature 19: Telemetry aggregation, exporters, and stimulus correlation."""

    def test_f19_telemetry_record_packet_counters(self) -> None:
        session = TelemetrySession(topology="TestTopology")
        pdu = bytes([0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        frame = dissect_advertising_pdu(pdu)
        session.record_packet(frame)
        summary = session.get_summary()
        assert summary["metadata"]["total_packets"] == 1
        assert summary["metadata"]["unique_devices_count"] == 1

    def test_f19_telemetry_device_summary_aggregation(self) -> None:
        session = TelemetrySession(topology="TestTopology")
        adv_a = bytes.fromhex("112233445566")
        pdu1 = bytes([0x00, 0x06]) + adv_a
        pdu2 = bytes([0x00, 0x06]) + adv_a
        session.record_packet(dissect_advertising_pdu(pdu1, chan=37, rssi=-50))
        session.record_packet(dissect_advertising_pdu(pdu2, chan=38, rssi=-70))
        assert "11:22:33:44:55:66" in session.devices
        dev = session.devices["11:22:33:44:55:66"]
        assert dev.packet_count == 2
        assert dev.rssi_min == -70
        assert dev.rssi_max == -50
        assert dev.channels_seen == {37, 38}

    def test_f19_telemetry_export_json_validity(self, tmp_path: Path) -> None:
        session = TelemetrySession(topology="Topology A")
        pdu = bytes([0x02, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        session.record_packet(dissect_advertising_pdu(pdu))
        out_json = tmp_path / "telemetry.json"
        session.export_json(out_json)
        assert out_json.exists()
        parsed = json.loads(out_json.read_text(encoding="utf-8"))
        assert "metadata" in parsed
        assert "devices" in parsed
        assert parsed["metadata"]["total_packets"] == 1

    def test_f19_telemetry_export_csv_validity(self, tmp_path: Path) -> None:
        session = TelemetrySession(topology="Topology A")
        pdu = bytes([0x02, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        session.record_packet(dissect_advertising_pdu(pdu))
        out_csv = tmp_path / "report.csv"
        session.export_csv(out_csv)
        assert out_csv.exists()
        content = out_csv.read_text(encoding="utf-8")
        assert "mac_address" in content
        assert "AA:BB:CC:DD:EE:FF" in content

    def test_f19_correlator_stimulus_response_match(self) -> None:
        correlator = StimulusResponseCorrelator()
        stim_mac = bytes.fromhex("c011222211c0")
        resp_mac = bytes.fromhex("112233445566")
        correlator.register_stimulus(
            adv_a=stim_mac,
            beacon_type="iBeacon",
            burst_id=1,
            channel=37,
            start_time_usec=1000,
        )
        scan_req = build_scan_req(scan_a=resp_mac, adv_a=stim_mac)
        frame = dissect_advertising_pdu(scan_req, chan=37, rssi=-60, ts_usec=1500)
        match = correlator.process_frame(frame)
        assert match is not None
        assert isinstance(match, CorrelationMatch)
        assert match.stimulus_adv_a == "C0:11:22:22:11:C0"
        assert match.responder_mac == "11:22:33:44:55:66"


# ==============================================================================
# Feature 20: CLI & Hardware Loopback Verification (5 tests)
# ==============================================================================


class TestFeature20CliAndHardwareLoopbackVerification:
    """Feature 20: Unified CLI application and hardware loopback subcommands."""

    def test_f20_cli_parser_subcommands(self) -> None:
        parser = create_parser()
        args_a = parser.parse_args(["topology-a", "--mock"])
        assert args_a.command == "topology-a"
        args_b = parser.parse_args(["topology-b", "--mock"])
        assert args_b.command == "topology-b"
        args_sim = parser.parse_args(["mock-simulate"])
        assert args_sim.command == "mock-simulate"
        args_hw = parser.parse_args(["verify-hardware", "--mock"])
        assert args_hw.command == "verify-hardware"

    def test_f20_cli_mock_simulate_execution(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "mock_sim.pcap"
        json_file = tmp_path / "mock_sim.json"
        csv_file = tmp_path / "mock_sim.csv"
        ret = main([
            "mock-simulate",
            "--pcap", str(pcap_file),
            "--json", str(json_file),
            "--csv", str(csv_file),
            "--duration-sec", "0.2",
            "--interval-ms", "30",
        ])
        assert ret == 0
        assert pcap_file.exists()
        assert json_file.exists()
        assert csv_file.exists()

    def test_f20_cli_verify_hardware_mock_execution(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "hw_verify.pcap"
        ret = main([
            "verify-hardware",
            "--mock",
            "--pcap", str(pcap_file),
            "--burst-duration-sec", "0.05",
            "--interval-ms", "25",
        ])
        assert ret == 0
        assert pcap_file.exists()

    def test_f20_cli_invalid_argument_error_code(self) -> None:
        # Negative duration must return code 2
        ret = main(["topology-a", "--mock", "--duration-sec", "-1.0"])
        assert ret == 2
        # Same channels in topology-b must return code 2
        ret_b = main(["topology-b", "--mock", "--chan1", "37", "--chan2", "37"])
        assert ret_b == 2

    def test_f20_cli_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        ret = main(["--version"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "bluetooth-sniffle 0.1.0" in captured.out or "bluetooth-sniffle 0.1.0" in captured.err
