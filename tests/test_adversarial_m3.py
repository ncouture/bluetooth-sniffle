"""Adversarial stress and edge-case challenge suite for Milestone 3.

Covers:
  1. Dissector Fuzzing & Crash Resilience:
     - 10,000 random-byte payloads (lengths 2..255) asserting zero unhandled exceptions
     - Structured mutations and bit-flips across all 6 ground-truth beacons + probing frames
     - Truncated PDU payloads for all 8 Link Layer PDU types (0x00 to 0x07)
     - Huge length bytes (0x3F, 0xFF, AD length 255) and zero-length padding termination
     - Deeply chained AD structures (200+ structures) and repeated types
     - Corrupted local names: invalid UTF-8 sequences, null bytes, surrogate codes
     - Corrupted Manufacturer Data (Apple Continuity sub-messages, truncated iBeacon, AltBeacon, MS-CDP)
     - Corrupted Service UUIDs and Service Data (odd-length 16-bit, non-multiple 32/128-bit, Eddystone/GAEN)
     - Short PDU length boundary (< 2 bytes) asserting ValueError API contract
  2. Address Classification Exhaustive Verification:
     - Exhaustive sweep of all 256 MSB combinations across Public, Random Static, NRPA, RPA, and RFU
     - Inferred address classification (is_random=None)
     - Edge-case MACs (all zeros, all ones, IEEE multicast bit)
     - Palindromic MAC classification invariance
     - Malformed MAC string and byte length rejection
  3. Correlation Engine Stress & Timestamp Wrap:
     - 1,000 rapid burst registrations
     - High packet rate flood (10,000 frames) asserting match accuracy and throughput
     - Latency boundary conditions: exact jitter cutoff (-clock_tolerance_usec) and post-burst expiration
     - Modulo-32 microsecond timestamp wrap boundaries (pre-wrap stimulus, post-wrap response, boundary 2^32-1 to 0)
     - Disambiguation of multiple bursts sharing identical MAC address
     - Reproduction of modulo-32 wrap eviction defect in evict_expired
"""

from __future__ import annotations

import random
import struct
import time
from uuid import UUID

import pytest

from bluetooth_sniffle.protocol.mac import (
    generate_palindromic_mac,
)
from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.sniff.correlation import (
    StimulusResponseCorrelator,
)
from bluetooth_sniffle.sniff.dissector import (
    BleAddressType,
    DissectedBleFrame,
    classify_address,
    decode_altbeacon_msd,
    decode_apple_msd,
    decode_eddystone_service_data,
    decode_gaen_service_data,
    decode_local_name,
    decode_microsoft_msd,
    dissect_advertising_pdu,
    dissect_packet,
    parse_ad_structures,
)


class TestDissectorFuzzingAdversarial:
    """Fuzzing and adversarial input challenge for the BLE PDU dissector."""

    def test_fuzz_random_bytes_no_unhandled_crashes(self) -> None:
        """Fuzz dissect_advertising_pdu with 10,000 randomized byte sequences.

        Asserts that no unhandled exceptions crash the dissector on any payload
        with length >= 2 bytes.
        """
        rng = random.Random(0xDEADBEEF)
        crashes: list[tuple[int, str, str]] = []

        for i in range(10_000):
            length = rng.randint(2, 255)
            payload = rng.randbytes(length)
            try:
                frame = dissect_advertising_pdu(payload, chan=37, rssi=-60, ts_usec=i)
                assert frame is not None
                assert isinstance(frame.is_malformed, bool)
            except Exception as ex:
                crashes.append((i, type(ex).__name__, str(ex)))

        assert not crashes, f"Dissector crashed on {len(crashes)} fuzzed inputs: {crashes[:5]}"

    def test_fuzz_mutated_ground_truth_packets(self, ground_truth_vectors: dict[str, str]) -> None:
        """Mutates known valid packet vectors with bit-flips and byte replacements."""
        crashes: list[tuple[str, int, str]] = []

        # Build raw test frames
        adv_a = bytes.fromhex("c011222211c0")
        test_pdus = {
            "iBeacon": bytes([0x42, 30]) + adv_a + bytes.fromhex(ground_truth_vectors["iBeacon"]),
            "AltBeacon": bytes([0x42, 31]) + adv_a + bytes.fromhex(ground_truth_vectors["AltBeacon"]),
            "Eddystone-UID": bytes([0x42, 31]) + adv_a + bytes.fromhex(ground_truth_vectors["Eddystone-UID"]),
            "Eddystone-URL": bytes([0x42, 26]) + adv_a + bytes.fromhex(ground_truth_vectors["Eddystone-URL"]),
            "Eddystone-TLM": bytes([0x42, 25]) + adv_a + bytes.fromhex(ground_truth_vectors["Eddystone-TLM"]),
            "GAEN": bytes([0x42, 31]) + adv_a + bytes.fromhex(ground_truth_vectors["GAEN"]),
            "SCAN_REQ": bytes.fromhex(ground_truth_vectors["SCAN_REQ"]),
            "SCAN_RSP": bytes.fromhex(ground_truth_vectors["SCAN_RSP"]),
        }

        # Truncation sweep at every possible byte boundary
        for name, pdu in test_pdus.items():
            for cut in range(2, len(pdu) + 1):
                try:
                    frame = dissect_advertising_pdu(pdu[:cut])
                    assert frame is not None
                except Exception as ex:
                    crashes.append((f"{name}_trunc_{cut}", cut, str(ex)))

        # Single byte mutation across all offsets with boundary bytes
        boundary_bytes = [0x00, 0x01, 0x3F, 0x7F, 0x80, 0xC0, 0xFE, 0xFF]
        for name, pdu in test_pdus.items():
            for off in range(len(pdu)):
                for b in boundary_bytes:
                    mutated = bytearray(pdu)
                    mutated[off] = b
                    try:
                        frame = dissect_advertising_pdu(bytes(mutated))
                        assert frame is not None
                    except Exception as ex:
                        crashes.append((f"{name}_mut_{off}_{b}", off, str(ex)))

        assert not crashes, f"Dissector crashed on mutations: {crashes[:5]}"

    def test_truncated_pdus_every_pdu_type(self) -> None:
        """Tests truncated payloads across all 8 PDU types (0x00 to 0x07).

        Asserts that truncation sets is_malformed=True and populates error_details,
        without raising unhandled exceptions.
        """
        for pdu_type_id in range(8):
            # Header claims 30 bytes, but only provide 0 to 15 payload bytes
            for payload_len in range(0, 16):
                raw = bytes([pdu_type_id, 30]) + (b"\xAA" * payload_len)
                frame = dissect_advertising_pdu(raw)
                assert frame.pdu_type_id == pdu_type_id
                assert frame.is_malformed, f"PDU type {pdu_type_id} with {payload_len}B payload was not marked malformed"
                assert frame.error_details is not None
                assert "Truncated PDU" in frame.error_details or "Payload too short" in frame.error_details

    def test_huge_length_bytes_and_boundaries(self) -> None:
        """Tests maximum length byte in Link Layer header and AD structures."""
        # 6-bit length max is 63 (0x3F)
        adv_a = bytes.fromhex("112233445566")
        pdu_max = bytes([0x40, 0x3F]) + adv_a + (b"\x00" * 57)
        frame = dissect_advertising_pdu(pdu_max)
        assert frame.length == 0x3F
        assert not frame.is_malformed

        # Header length 0xFF (masked to 0x3F)
        pdu_ff = bytes([0x40, 0xFF]) + adv_a + (b"\x00" * 57)
        frame_ff = dissect_advertising_pdu(pdu_ff)
        assert frame_ff.length == 0x3F

        # AD structure claiming length 255 with only 4 bytes remaining
        ad_huge = bytes([0x40, 12]) + adv_a + bytes([0xFF, 0x09]) + b"Test"
        frame_huge = dissect_advertising_pdu(ad_huge)
        assert frame_huge.is_malformed
        assert any(ad.is_malformed for ad in frame_huge.ad_structures)
        assert "Truncated AD structure" in (frame_huge.error_details or "")

    def test_zero_length_and_empty_ad_structures(self) -> None:
        """Tests zero-length AD structures and trailing zero padding."""
        adv_a = bytes.fromhex("112233445566")

        # AD structure length 0 acts as standard zero-padding terminator
        pdu_pad = bytes([0x40, 10]) + adv_a + b"\x00\x00\x00\x00"
        frame_pad = dissect_advertising_pdu(pdu_pad)
        assert len(frame_pad.ad_structures) == 0
        assert not frame_pad.is_malformed

        # AD structure length 1 (type only, 0-byte value) for all standard types
        all_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x16, 0x20, 0x21, 0xFF]
        for t in all_types:
            pdu_len1 = bytes([0x40, 8]) + adv_a + bytes([1, t])
            frame = dissect_advertising_pdu(pdu_len1)
            assert len(frame.ad_structures) == 1
            assert frame.ad_structures[0].ad_type == t
            assert frame.ad_structures[0].value == b""

    def test_deeply_chained_ad_structures(self) -> None:
        """Tests parsing a large chain of consecutive AD structures (200 structures)."""
        # 200 flags structures (length 2, type 1, value 6)
        chain = b"".join(bytes([2, 0x01, 0x06]) for _ in range(200))
        # Length in header is 6 bits (masked to 63 in PDU, but parse_ad_structures can handle larger buffers)
        ads, malformed, err = parse_ad_structures(chain)
        assert len(ads) == 200
        assert not malformed
        assert err is None
        assert all(ad.ad_type == 0x01 and ad.value == b"\x06" for ad in ads)

    def test_dissect_packet_truncated_radio_body(self) -> None:
        """Verifies dissect_packet safely handles radio frames truncated to < 2 bytes."""
        # 0-byte radio body
        raw_hdr_0 = struct.pack("<LHHbB", 1000, 0, 0, -60, 37)
        pkt_0 = PacketMessage(raw_hdr_0)
        res_0 = dissect_packet(pkt_0)
        assert res_0.is_malformed is True
        assert "Truncated" in (res_0.error_details or "")

        # 1-byte radio body
        raw_hdr_1 = struct.pack("<LHHbB", 1000, 0, 1, -60, 37) + b"\x00"
        pkt_1 = PacketMessage(raw_hdr_1)
        res_1 = dissect_packet(pkt_1)
        assert res_1.is_malformed is True
        assert "Truncated" in (res_1.error_details or "")

    def test_corrupted_local_name_utf8_fallback(self) -> None:
        """Tests local name decoding across varied invalid UTF-8 sequences."""
        invalid_utf8_cases = [
            b"\xFF\xFE\xFD",                   # Invalid leading bytes
            b"\xC0\xAF",                       # Overlong ASCII slash (security hazard)
            b"\xED\xA0\x80",                   # UTF-16 surrogate half
            b"\xF4\x90\x80\x80",               # Beyond Unicode range (> 0x10FFFF)
            b"Hello\x80World",                 # Invalid continuation byte in ASCII
            b"\xC2",                           # Incomplete 2-byte sequence
        ]
        for bad in invalid_utf8_cases:
            decoded = decode_local_name(bad)
            assert decoded == f"<hex:{bad.hex()}>"

        # Embedded null byte is valid in UTF-8
        null_name = b"Device\x00Name"
        assert decode_local_name(null_name) == "Device\x00Name"

        # Valid UTF-8 unicode
        assert decode_local_name("🔥Beacon🔥".encode("utf-8")) == "🔥Beacon🔥"

    def test_corrupted_apple_msd_continuity(self) -> None:
        """Tests malformed Apple MSD payloads with truncated and zero-length sub-messages."""
        # 1. Truncated Continuity sub-message
        # Type 0x05 (AirDrop), claims 10 bytes, only 2 provided
        bad_airdrop = bytes([0x05, 10, 0x01, 0x02])
        msgs, beacon = decode_apple_msd(bad_airdrop)
        assert len(msgs) == 1
        assert msgs[0].sub_type == 0x05
        assert msgs[0].sub_type_name == "AirDrop"
        assert msgs[0].data == bytes([0x01, 0x02])

        # 2. Zero-length sub-message (length byte = 0)
        zero_sub = bytes([0x10, 0x00, 0x08, 0x01, 0xAA])
        msgs_zero, _ = decode_apple_msd(zero_sub)
        assert len(msgs_zero) == 2
        assert msgs_zero[0].sub_type == 0x10
        assert msgs_zero[0].data == b""
        assert msgs_zero[1].sub_type == 0x08
        assert msgs_zero[1].data == b"\xAA"

        # 3. iBeacon signature (0x02, 0x15) but payload < 23 bytes
        truncated_ibeacon = bytes([0x02, 0x15, 0x01, 0x02, 0x03])
        msgs_ib, ib_info = decode_apple_msd(truncated_ibeacon)
        assert ib_info is None  # Does not crash, returns None
        assert len(msgs_ib) == 1

        # 4. Odd single byte
        msgs_single, _ = decode_apple_msd(b"\x02")
        assert len(msgs_single) == 0

    def test_corrupted_microsoft_msd(self) -> None:
        """Tests Microsoft CDP parser with varied corrupt and truncated inputs."""
        # Less than 25 bytes returns None
        assert decode_microsoft_msd(b"\x00" * 24) is None
        assert decode_microsoft_msd(b"") is None

        # 25-byte minimal MS-CDP payload
        min_payload = bytes([
            0x01,        # Scenario
            0x01,        # Device type: Xbox One
            0x25,        # Flags (bit 5 = bt_dev_id)
            0x02,        # Status
            0x11, 0x22, 0x33, 0x44,  # Salt
        ]) + b"\xBB" * 17  # Hash (17 bytes)
        cdp = decode_microsoft_msd(min_payload)
        assert cdp is not None
        assert cdp.scenario_type == 0x01
        assert cdp.device_type_name == "Xbox One"
        assert cdp.bt_addr_dev_id is True
        assert cdp.salt == 0x44332211
        assert cdp.device_hash == b"\xBB" * 17

    def test_corrupted_altbeacon_msd(self) -> None:
        """Tests AltBeacon MSD decoding against invalid lengths and beacon codes."""
        # Length < 24 returns None
        assert decode_altbeacon_msd(0x0118, b"\xBE\xAC" + (b"\x00" * 20)) is None

        # Invalid beacon code != 0xBEAC returns None
        bad_code = bytes([0x12, 0x34]) + (b"\xAA" * 20) + bytes([0xC5, 0x00])
        assert decode_altbeacon_msd(0x0118, bad_code) is None

        # Valid 24-byte AltBeacon payload
        valid = bytes([0xBE, 0xAC]) + (b"\xCC" * 20) + bytes([0xD0, 0x42])
        alt = decode_altbeacon_msd(0x0118, valid)
        assert alt is not None
        assert alt.mfg_id == 0x0118
        assert alt.beacon_code == 0xBEAC
        assert alt.ref_rssi == -48  # 0xD0 as signed int8
        assert alt.mfg_reserved == 0x42

    def test_corrupted_service_uuids_and_data(self) -> None:
        """Tests odd-length 16-bit, 32-bit, and 128-bit UUID lists."""
        adv_a = bytes.fromhex("112233445566")

        # 16-bit UUID with odd length (4 bytes: type 0x03 + 3 value bytes -> 1 UUID + 1 orphan byte)
        pdu_16 = bytes([0x40, 6 + 1 + 4]) + adv_a + bytes([4, 0x03, 0x34, 0x12, 0xFF])
        f16 = dissect_advertising_pdu(pdu_16)
        assert f16.is_malformed
        assert f16.service_uuids_16 == [0x1234]

        # 32-bit UUID with 6 bytes (type 0x05 + 5 value bytes -> 1 UUID + 1 orphan byte)
        pdu_32 = bytes([0x40, 6 + 1 + 6]) + adv_a + bytes([6, 0x05, 0x78, 0x56, 0x34, 0x12, 0xAA])
        f32 = dissect_advertising_pdu(pdu_32)
        assert f32.is_malformed
        assert f32.service_uuids_32 == [0x12345678]

        # 128-bit UUID with 18 bytes (type 0x07 + 17 value bytes -> 1 UUID + 1 orphan byte)
        u128_raw = b"\x01" * 16
        pdu_128 = bytes([0x40, 6 + 1 + 18]) + adv_a + bytes([18, 0x07]) + u128_raw + b"\xBB"
        f128 = dissect_advertising_pdu(pdu_128)
        assert f128.is_malformed
        assert f128.service_uuids_128 == [UUID(bytes=u128_raw)]

    def test_eddystone_corrupted_url_and_uid(self) -> None:
        """Tests Eddystone service data parser against corrupted frame types and lengths."""
        # UID with length < 18 returns None
        assert decode_eddystone_service_data(bytes([0x00, 0xEE]) + (b"\x01" * 15)) is None

        # URL with unknown scheme code (> 0x03) falls back to <scheme:xx>
        raw_url = bytes([0x10, 0xF0, 0x99, 0x61, 0x62, 0x63])
        info = decode_eddystone_service_data(raw_url)
        assert info is not None
        assert info.url.startswith("<scheme:99>abc")

        # URL with non-printable characters falls back to <0xXX> (0x0E is not in expansions and < 32)
        raw_non_ascii = bytes([0x10, 0xF0, 0x03, 0x61, 0x0E, 0x62])
        info_na = decode_eddystone_service_data(raw_non_ascii)
        assert info_na is not None
        assert "<0x0e>" in info_na.url

        # Empty data returns None
        assert decode_eddystone_service_data(b"") is None

    def test_gaen_corrupted_length(self) -> None:
        """GAEN service data < 20 bytes returns None."""
        assert decode_gaen_service_data(b"\x00" * 19) is None
        assert decode_gaen_service_data(b"") is None
        valid_gaen = decode_gaen_service_data(b"\xAA" * 16 + b"\xBB" * 4)
        assert valid_gaen is not None
        assert valid_gaen.rpi == b"\xAA" * 16
        assert valid_gaen.aem == b"\xBB" * 4

    def test_short_pdu_raises_value_error(self) -> None:
        """Asserts that raw PDU < 2 bytes raises ValueError per API contract."""
        with pytest.raises(ValueError, match="at least 2 bytes"):
            dissect_advertising_pdu(b"")
        with pytest.raises(ValueError, match="at least 2 bytes"):
            dissect_advertising_pdu(b"\x01")


class TestAddressClassificationAdversarial:
    """Adversarial stress testing of address classification across all 4 types and bit patterns."""

    def test_exhaustive_sweep_256_msb_combinations(self) -> None:
        """Exhaustively sweeps all 256 MSB combinations of MAC byte 5.

        Verifies:
          - is_random=False forces Public classification regardless of bits.
          - is_random=True routes 11b -> Random Static, 00b -> NRPA, 01b -> RPA, 10b -> RFU.
          - is_random=None (inferred) routes 11b -> Random Static, 00b -> NRPA, 01b -> RPA, 10b -> Public.
        """
        for b5 in range(256):
            mac = bytes([0x11, 0x22, 0x33, 0x44, 0x55, b5])
            top2 = b5 >> 6

            # 1. Explicit is_random=False
            assert classify_address(mac, is_random=False) == BleAddressType.PUBLIC

            # 2. Explicit is_random=True
            res_rand = classify_address(mac, is_random=True)
            if top2 == 0b11:
                assert res_rand == BleAddressType.RANDOM_STATIC
            elif top2 == 0b00:
                assert res_rand == BleAddressType.NRPA
            elif top2 == 0b01:
                assert res_rand == BleAddressType.RPA
            elif top2 == 0b10:
                assert res_rand == BleAddressType.RFU

            # 3. Inferred is_random=None
            res_inf = classify_address(mac, is_random=None)
            if top2 == 0b11:
                assert res_inf == BleAddressType.RANDOM_STATIC
            elif top2 == 0b00:
                assert res_inf == BleAddressType.NRPA
            elif top2 == 0b01:
                assert res_inf == BleAddressType.RPA
            elif top2 == 0b10:
                assert res_inf == BleAddressType.PUBLIC

    def test_edge_case_mac_addresses(self) -> None:
        """Tests boundary MAC addresses: all zeros, all ones, and multicast bits."""
        all_zeros = bytes.fromhex("000000000000")
        assert classify_address(all_zeros, is_random=False) == BleAddressType.PUBLIC
        assert classify_address(all_zeros, is_random=True) == BleAddressType.NRPA

        all_ones = bytes.fromhex("ffffffffffff")
        assert classify_address(all_ones, is_random=False) == BleAddressType.PUBLIC
        assert classify_address(all_ones, is_random=True) == BleAddressType.RANDOM_STATIC

        # Multicast / Group bit set on Byte 0 (IEEE 802)
        multicast = bytes.fromhex("01005e000001")
        assert classify_address(multicast, is_random=False) == BleAddressType.PUBLIC

    def test_palindromic_mac_classifications(self) -> None:
        """Verifies palindromic MAC address generator conforms to classification rules."""
        for p_type, expected in [
            ("static", BleAddressType.RANDOM_STATIC),
            ("nrpa", BleAddressType.NRPA),
            ("rpa", BleAddressType.RPA),
        ]:
            pmac = generate_palindromic_mac(p_type)
            assert classify_address(pmac, is_random=True) == expected
            assert classify_address(pmac, is_random=None) == expected

        # Public palindromic MAC has top 2 bits set to 10b
        pmac_pub = generate_palindromic_mac("public")
        assert classify_address(pmac_pub, is_random=False) == BleAddressType.PUBLIC
        assert classify_address(pmac_pub, is_random=None) == BleAddressType.PUBLIC

    def test_invalid_mac_inputs_raise_value_error(self) -> None:
        """Rejects bad lengths and corrupted hex strings."""
        for bad_len in [b"", b"\x00", b"\x00" * 5, b"\x00" * 7, b"\x00" * 12]:
            with pytest.raises(ValueError, match="6 bytes"):
                classify_address(bad_len)

        for bad_str in ["", "11:22:33", "11:22:33:44:55:66:77", "not-a-mac", "ZZ:11:22:33:44:55"]:
            with pytest.raises(ValueError):
                classify_address(bad_str)


class TestCorrelationEngineAdversarial:
    """Adversarial stress testing of StimulusResponseCorrelator."""

    def test_rapid_burst_registration_and_indexing(self) -> None:
        """Registers 1,000 rapid stimulus bursts and verifies indexing integrity."""
        correlator = StimulusResponseCorrelator()

        for i in range(1_000):
            mac = f"C0:11:22:22:{i >> 8:02X}:{i & 0xFF:02X}"
            stim = correlator.register_stimulus(
                adv_a=mac,
                beacon_type="iBeacon" if i % 2 == 0 else "AltBeacon",
                burst_id=i,
                start_time_usec=i * 50_000,
                duration_usec=20_000,
            )
            assert stim.burst_id == i

        assert len(correlator._stimuli) == 1_000
        assert len(correlator._stimuli_by_id) == 1_000
        assert len(correlator._stimuli_by_mac) == 1_000

    def test_high_throughput_packet_flood(self) -> None:
        """Floods 10,000 Link Layer frames through the correlation engine.

        Measures processing throughput and asserts 100% correlation fidelity.
        """
        correlator = StimulusResponseCorrelator()

        # Register 100 stimuli
        for i in range(100):
            correlator.register_stimulus(
                adv_a=f"C0:11:22:22:11:{i:02X}",
                beacon_type="iBeacon",
                burst_id=i,
                start_time_usec=i * 1_000_000,
                duration_usec=500_000,
            )

        # Generate 10,000 matching SCAN_REQ frames (100 per stimulus)
        frames = []
        for i in range(10_000):
            stim_idx = i % 100
            stim_mac = f"C0:11:22:22:11:{stim_idx:02X}"
            ts = (stim_idx * 1_000_000) + (i * 20)  # arrive within 500ms
            f = DissectedBleFrame(
                pdu_type="SCAN_REQ",
                pdu_type_id=0x03,
                tx_add=1,
                rx_add=1,
                length=12,
                scan_a="40:AA:BB:CC:DD:01",
                scan_a_type="RPA",
                adv_a=stim_mac,
                timestamp_usec=ts,
            )
            frames.append(f)

        t0 = time.perf_counter()
        matches = correlator.process_frames(frames)
        elapsed = time.perf_counter() - t0

        assert len(matches) == 10_000
        throughput = len(frames) / elapsed
        assert throughput > 50_000, f"Correlation throughput too low: {throughput:.0f} frames/s"

        summary = correlator.get_summary()
        assert summary.total_stimuli == 100
        assert summary.total_responses == 10_000
        assert summary.correlated_stimuli_count == 100
        assert summary.response_rate_percent == 100.0

    def test_latency_window_boundaries_and_jitter(self) -> None:
        """Pinpoints exact microsecond boundary thresholds for correlation matching."""
        tolerance_usec = 200_000
        max_lat_usec = 5_000_000
        duration_usec = 1_000_000
        start_usec = 10_000_000

        correlator = StimulusResponseCorrelator(
            max_latency_usec=max_lat_usec,
            clock_tolerance_usec=tolerance_usec,
        )
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=start_usec,
            duration_usec=duration_usec,
        )

        def make_req(ts: int) -> DissectedBleFrame:
            return DissectedBleFrame(
                pdu_type="SCAN_REQ",
                pdu_type_id=0x03,
                tx_add=1,
                rx_add=1,
                length=12,
                scan_a="40:AA:BB:CC:DD:40",
                adv_a="C0:11:22:22:11:C0",
                timestamp_usec=ts,
            )

        # 1. Exact negative jitter boundary: start - tolerance matches with 0 latency
        match_jitter_exact = correlator.process_frame(make_req(start_usec - tolerance_usec))
        assert match_jitter_exact is not None
        assert match_jitter_exact.latency_usec == 0

        # 2. Beyond jitter boundary: start - tolerance - 1 is rejected
        match_jitter_fail = correlator.process_frame(make_req(start_usec - tolerance_usec - 1))
        assert match_jitter_fail is None

        # 3. Exact post-burst latency boundary: start + duration + max_latency matches
        max_valid_ts = start_usec + duration_usec + max_lat_usec
        match_max_exact = correlator.process_frame(make_req(max_valid_ts))
        assert match_max_exact is not None
        assert match_max_exact.latency_usec == duration_usec + max_lat_usec

        # 4. Beyond latency window: start + duration + max_latency + 1 is rejected
        match_expired = correlator.process_frame(make_req(max_valid_ts + 1))
        assert match_expired is None

    def test_modulo_32_timestamp_wraparound_boundaries(self) -> None:
        """Tests correlation across the 32-bit (2^32 = 4,294,967,296) timestamp boundary."""
        correlator = StimulusResponseCorrelator(
            max_latency_usec=5_000_000,
            clock_tolerance_usec=200_000,
        )

        # Stimulus starts 10,000 us before 2^32 wrap
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=4_294_957_296,  # 2^32 - 10,000
            duration_usec=5_000_000,
        )

        def make_req(ts: int) -> DissectedBleFrame:
            return DissectedBleFrame(
                pdu_type="SCAN_REQ",
                pdu_type_id=0x03,
                tx_add=1,
                rx_add=1,
                length=12,
                scan_a="40:AA:BB:CC:DD:40",
                adv_a="C0:11:22:22:11:C0",
                timestamp_usec=ts,
            )

        # Response arrives 20,000 us AFTER wrap (total elapsed: 30,000 us)
        match = correlator.process_frame(make_req(20_000))
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.latency_usec == 30_000
        assert match.latency_ms == 30.0

        # Boundary: response arrives at 0 (10,000 us after stim)
        match_zero = correlator.process_frame(make_req(0))
        assert match_zero is not None
        assert match_zero.latency_usec == 10_000

        # Jitter: response arrives 50,000 us before stimulus (pre-wrap timestamp)
        match_pre = correlator.process_frame(make_req(4_294_957_296 - 50_000))
        assert match_pre is not None
        assert match_pre.latency_usec == 0

    def test_disambiguation_multiple_bursts_same_mac(self) -> None:
        """Iterates in reverse to prefer the most recent stimulus burst."""
        correlator = StimulusResponseCorrelator(max_latency_usec=2_000_000)

        # Burst 1 at 1s, duration 5s (active 1s..8s)
        s1 = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            burst_id=1,
            start_time_usec=1_000_000,
            duration_usec=5_000_000,
        )
        # Burst 2 at 10s, duration 5s (active 10s..17s)
        s2 = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            burst_id=2,
            start_time_usec=10_000_000,
            duration_usec=5_000_000,
        )

        def make_req(ts: int) -> DissectedBleFrame:
            return DissectedBleFrame(
                pdu_type="SCAN_REQ",
                pdu_type_id=0x03,
                tx_add=1,
                rx_add=1,
                length=12,
                scan_a="40:AA:BB:CC:DD:40",
                adv_a="C0:11:22:22:11:C0",
                timestamp_usec=ts,
            )

        # Probe during Burst 2 matches s2
        m2 = correlator.process_frame(make_req(11_000_000))
        assert m2 is not None
        assert m2.stimulus_id == s2.stimulus_id
        assert m2.latency_ms == 1000.0

        # Probe during Burst 1 window matches s1 (s2 is in the future relative to 4s)
        m1 = correlator.process_frame(make_req(4_000_000))
        assert m1 is not None
        assert m1.stimulus_id == s1.stimulus_id
        assert m1.latency_ms == 3000.0

    def test_evict_expired_modulo32_wrap_bug(self) -> None:
        """Demonstrates defect in evict_expired when current_time_usec wraps past 2^32.

        When current_time_usec < retention_usec, cutoff is negative, causing:
            s.start_time_usec >= cutoff
        to evaluate True for all stimuli, retaining expired records from before wrap.
        """
        # Retention is 10 seconds (10_000_000 us)
        correlator = StimulusResponseCorrelator(history_retention_sec=10.0)

        # Old stimulus registered at 4,000,000,000 us (4000s into previous epoch)
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:01",
            start_time_usec=4_000_000_000,
        )

        # Current time wrapped to 5_000_000 us (5s into new epoch).
        # Elapsed time is ~299 seconds, far exceeding 10s retention!
        evicted = correlator.evict_expired(current_time_usec=5_000_000)

        # The expired stimulus MUST be evicted (evicted == 1, len(_stimuli) == 0)
        assert evicted == 1, f"Expected 1 evicted stimulus, but {evicted} were evicted"
        assert len(correlator._stimuli) == 0
