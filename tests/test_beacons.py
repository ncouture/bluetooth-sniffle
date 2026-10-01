"""Comprehensive Unit Tests for BLE Beacon Synthesis (PoPETs 2025-0103).

Asserts bit-for-bit exact compliance with:
  - 6 ground-truth test vectors (iBeacon, AltBeacon, Eddystone-UID/URL/TLM, GAEN)
  - Boundary and edge case handling (temperatures, counters, URL expansions, length <= 31)
  - Interoperability with the reference Sniffle AD decoder
  - BurstCycleHelper schedule and timing models
"""

import sys
from uuid import UUID

import pytest

from bluetooth_sniffle.protocol.beacons import (
    AD_TYPE_FLAGS,
    BurstCycleHelper,
    BurstProfile,
    build_altbeacon,
    build_eddystone_tlm,
    build_eddystone_uid,
    build_eddystone_url,
    build_flags,
    build_gaen,
    build_ibeacon,
)

# Optional reference Sniffle decoder check
if "/home/self/git/Sniffle/Sniffle/python_cli" not in sys.path:
    sys.path.insert(0, "/home/self/git/Sniffle/Sniffle/python_cli")

try:
    from sniffle.advdata.ad_types import (
        FlagsRecord,
        ManufacturerSpecificDataRecord,
        ServiceData16Record,
        ServiceList16Record,
    )
    from sniffle.advdata.decoder import decode_adv_data
    from sniffle.advdata.msd_apple import AppleMSDRecord
    SNIFFLE_AVAILABLE = True
except ImportError:
    SNIFFLE_AVAILABLE = False


# ============================================================================
# Section 1: Ground-Truth Test Vectors (explorer_survey_2/handoff.md §4.1)
# ============================================================================

class TestGroundTruthVectors:
    """Verifies that each beacon builder matches the ground-truth vectors bit-for-bit."""

    def test_vector_1_ibeacon_exact_match(self, ground_truth_vectors):
        """Vector 1: Apple iBeacon (30 bytes)."""
        uuid_str = "e2c56db5-dffb-48d2-b060-d0f5a71096e0"
        major = 1
        minor = 2
        tx_power = -59
        flags = 0x06

        packet = build_ibeacon(uuid=uuid_str, major=major, minor=minor, tx_power=tx_power, flags=flags)
        expected_hex = ground_truth_vectors["iBeacon"]

        assert packet.hex() == expected_hex
        assert len(packet) == 30
        assert len(packet) <= 31

    def test_vector_2_altbeacon_exact_match(self, ground_truth_vectors):
        """Vector 2: AltBeacon (31 bytes)."""
        mfg_id = 0x0118
        beacon_id = bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002")
        ref_rssi = -59
        mfg_reserved = 0x00
        flags = 0x06

        packet = build_altbeacon(
            mfg_id=mfg_id,
            beacon_id=beacon_id,
            ref_rssi=ref_rssi,
            mfg_reserved=mfg_reserved,
            flags=flags,
        )
        expected_hex = ground_truth_vectors["AltBeacon"]

        assert packet.hex() == expected_hex
        assert len(packet) == 31
        assert len(packet) <= 31

    def test_vector_3_eddystone_uid_exact_match(self, ground_truth_vectors):
        """Vector 3: Google Eddystone-UID (31 bytes)."""
        namespace = bytes.fromhex("0102030405060708090a")
        instance = bytes.fromhex("010203040506")
        tx_power = -20
        flags = 0x06

        packet = build_eddystone_uid(
            namespace=namespace,
            instance=instance,
            tx_power=tx_power,
            flags=flags,
        )
        expected_hex = ground_truth_vectors["Eddystone-UID"]

        assert packet.hex() == expected_hex
        assert len(packet) == 31
        assert len(packet) <= 31

    def test_vector_4_eddystone_url_exact_match(self, ground_truth_vectors):
        """Vector 4: Google Eddystone-URL (26 bytes)."""
        url = "https://example.com/test"
        tx_power = -18
        flags = 0x06

        packet = build_eddystone_url(url=url, tx_power=tx_power, flags=flags)
        expected_hex = ground_truth_vectors["Eddystone-URL"]

        assert packet.hex() == expected_hex
        assert len(packet) == 26
        assert len(packet) <= 31

    def test_vector_5_eddystone_tlm_exact_match(self, ground_truth_vectors):
        """Vector 5: Google Eddystone-TLM (25 bytes)."""
        vbatt_mv = 3000
        temp_c = 20.5
        adv_cnt = 1000
        sec_cnt = 10000
        flags = 0x06

        packet = build_eddystone_tlm(
            vbatt_mv=vbatt_mv,
            temp_c=temp_c,
            adv_cnt=adv_cnt,
            sec_cnt=sec_cnt,
            flags=flags,
        )
        expected_hex = ground_truth_vectors["Eddystone-TLM"]

        assert packet.hex() == expected_hex
        assert len(packet) == 25
        assert len(packet) <= 31

    def test_vector_6_gaen_exact_match(self, ground_truth_vectors):
        """Vector 6: Google/Apple Exposure Notification GAEN (31 bytes)."""
        rpi = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        aem = bytes.fromhex("11223344")
        flags = 0x1A

        packet = build_gaen(rpi=rpi, aem=aem, flags=flags)
        expected_hex = ground_truth_vectors["GAEN"]

        assert packet.hex() == expected_hex
        assert len(packet) == 31
        assert len(packet) <= 31


# ============================================================================
# Section 2: Reference Sniffle AD Decoder Interoperability
# ============================================================================

@pytest.mark.skipif(not SNIFFLE_AVAILABLE, reason="Reference Sniffle library not installed")
class TestSniffleDecoderInteroperability:
    """Verifies that generated frames parse correctly with reference Sniffle decoder."""

    def test_ibeacon_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["iBeacon"])
        recs = decode_adv_data(raw)
        assert len(recs) == 2
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], AppleMSDRecord)
        assert recs[1].company == 0x004C
        assert len(recs[1].messages) == 1
        msg = recs[1].messages[0]
        assert str(msg.prox_uuid) == "e2c56db5-dffb-48d2-b060-d0f5a71096e0"
        assert msg.meas_power == (-59,)

    def test_altbeacon_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["AltBeacon"])
        recs = decode_adv_data(raw)
        assert len(recs) == 2
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], ManufacturerSpecificDataRecord)
        assert recs[1].company == 0x0118

    def test_eddystone_uid_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["Eddystone-UID"])
        recs = decode_adv_data(raw)
        assert len(recs) == 3
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], ServiceList16Record)
        assert 0xFEAA in recs[1].services
        assert isinstance(recs[2], ServiceData16Record)
        assert recs[2].service == 0xFEAA

    def test_eddystone_url_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["Eddystone-URL"])
        recs = decode_adv_data(raw)
        assert len(recs) == 3
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], ServiceList16Record)
        assert 0xFEAA in recs[1].services
        assert isinstance(recs[2], ServiceData16Record)
        assert recs[2].service == 0xFEAA

    def test_eddystone_tlm_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["Eddystone-TLM"])
        recs = decode_adv_data(raw)
        assert len(recs) == 3
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], ServiceList16Record)
        assert 0xFEAA in recs[1].services
        assert isinstance(recs[2], ServiceData16Record)
        assert recs[2].service == 0xFEAA

    def test_gaen_sniffle_decoding(self, ground_truth_vectors):
        raw = bytes.fromhex(ground_truth_vectors["GAEN"])
        recs = decode_adv_data(raw)
        assert len(recs) == 3
        assert isinstance(recs[0], FlagsRecord)
        assert isinstance(recs[1], ServiceList16Record)
        assert 0xFD6F in recs[1].services
        assert isinstance(recs[2], ServiceData16Record)
        assert recs[2].service == 0xFD6F


# ============================================================================
# Section 3: Boundary Conditions & Parameter Variations
# ============================================================================

class TestBeaconBoundariesAndVariations:
    """Tests extreme parameters, type conversions, and boundary checks."""

    # --- Flags ---
    def test_build_flags_valid_and_invalid(self):
        f = build_flags(0x06)
        assert f == bytes([0x02, AD_TYPE_FLAGS, 0x06])

        with pytest.raises(ValueError, match="Flags must be 0..255"):
            build_flags(-1)
        with pytest.raises(ValueError, match="Flags must be 0..255"):
            build_flags(256)

    # --- iBeacon ---
    def test_ibeacon_uuid_types(self):
        u_obj = UUID("12345678-1234-5678-1234-567812345678")
        p1 = build_ibeacon(u_obj, 10, 20)
        p2 = build_ibeacon(str(u_obj), 10, 20)
        p3 = build_ibeacon(u_obj.bytes, 10, 20)
        assert p1 == p2 == p3
        assert len(p1) == 30

    def test_ibeacon_boundary_values(self):
        # Min/max major and minor
        p_min = build_ibeacon(UUID(int=0), major=0, minor=0, tx_power=-128)
        assert len(p_min) == 30
        assert p_min[25:27] == b"\x00\x00"
        assert p_min[27:29] == b"\x00\x00"
        assert p_min[29] == 0x80  # -128 in int8

        p_max = build_ibeacon(UUID(int=1), major=0xFFFF, minor=0xFFFF, tx_power=127)
        assert len(p_max) == 30
        assert p_max[25:27] == b"\xFF\xFF"
        assert p_max[27:29] == b"\xFF\xFF"
        assert p_max[29] == 0x7F  # 127 in int8

    def test_ibeacon_invalid_inputs(self):
        with pytest.raises(ValueError, match="Major must be 0..65535"):
            build_ibeacon(UUID(int=0), major=0x10000, minor=1)
        with pytest.raises(ValueError, match="Major must be 0..65535"):
            build_ibeacon(UUID(int=0), major=-1, minor=1)
        with pytest.raises(ValueError, match="Minor must be 0..65535"):
            build_ibeacon(UUID(int=0), major=1, minor=-1)
        with pytest.raises(ValueError, match="Minor must be 0..65535"):
            build_ibeacon(UUID(int=0), major=1, minor=0x10000)
        with pytest.raises(ValueError, match="tx_power must be -128..127"):
            build_ibeacon(UUID(int=0), major=1, minor=1, tx_power=128)
        with pytest.raises(ValueError, match="tx_power must be -128..127"):
            build_ibeacon(UUID(int=0), major=1, minor=1, tx_power=-129)
        with pytest.raises(ValueError, match="Proximity UUID bytes must be 16 bytes"):
            build_ibeacon(b"\x00" * 15, major=1, minor=1)
        with pytest.raises(TypeError, match="Unsupported UUID type"):
            build_ibeacon(12345, major=1, minor=1)  # Invalid type

    # --- AltBeacon ---
    def test_altbeacon_variations(self):
        p_hex_id = build_altbeacon(beacon_id="00" * 20, ref_rssi=-50)
        p_bytes_id = build_altbeacon(beacon_id=b"\x00" * 20, ref_rssi=-50)
        assert p_hex_id == p_bytes_id
        assert len(p_hex_id) == 31

    def test_altbeacon_invalid_inputs(self):
        with pytest.raises(ValueError, match="AltBeacon ID must be exactly 20 bytes"):
            build_altbeacon(beacon_id=b"\x00" * 19)
        with pytest.raises(ValueError, match="mfg_id must be 0..65535"):
            build_altbeacon(mfg_id=0x10000)
        with pytest.raises(ValueError, match="ref_rssi must be -128..127"):
            build_altbeacon(ref_rssi=-129)
        with pytest.raises(ValueError, match="mfg_reserved must be 0..255"):
            build_altbeacon(mfg_reserved=256)

    # --- Eddystone-UID ---
    def test_eddystone_uid_variations(self):
        ns = "aa" * 10
        inst = "bb" * 6
        p = build_eddystone_uid(namespace=ns, instance=inst, tx_power=0)
        assert len(p) == 31
        # Check namespace and instance placement
        assert p[13:23] == bytes.fromhex(ns)
        assert p[23:29] == bytes.fromhex(inst)
        assert p[29:31] == b"\x00\x00"  # RFU

    def test_eddystone_uid_invalid_inputs(self):
        with pytest.raises(ValueError, match="namespace must be 10 bytes"):
            build_eddystone_uid(namespace=b"\x00" * 9, instance=b"\x00" * 6)
        with pytest.raises(ValueError, match="instance must be 6 bytes"):
            build_eddystone_uid(namespace=b"\x00" * 10, instance=b"\x00" * 7)
        with pytest.raises(ValueError, match="tx_power must be -128..127"):
            build_eddystone_uid(namespace=b"\x00" * 10, instance=b"\x00" * 6, tx_power=128)

    # --- Eddystone-URL ---
    def test_eddystone_url_scheme_prefixes(self):
        schemes = [
            ("http://www.google.com", 0x00),
            ("https://www.google.com", 0x01),
            ("http://google.com", 0x02),
            ("https://google.com", 0x03),
        ]
        for url, expected_code in schemes:
            pkt = build_eddystone_url(url)
            assert len(pkt) <= 31
            # Byte 13 is the URL scheme code
            assert pkt[13] == expected_code

    def test_eddystone_url_expansions(self):
        expansions = [
            ("https://test.com/", 0x00),
            ("https://test.org/", 0x01),
            ("https://test.edu/", 0x02),
            ("https://test.net/", 0x03),
            ("https://test.info/", 0x04),
            ("https://test.biz/", 0x05),
            ("https://test.gov/", 0x06),
            ("https://test.com", 0x07),
            ("https://test.org", 0x08),
            ("https://test.edu", 0x09),
            ("https://test.net", 0x0A),
            ("https://test.info", 0x0B),
            ("https://test.biz", 0x0C),
            ("https://test.gov", 0x0D),
        ]
        for url, expected_exp in expansions:
            pkt = build_eddystone_url(url)
            assert len(pkt) <= 31
            assert expected_exp in pkt[14:]

    def test_eddystone_url_length_limit(self):
        # 17 bytes maximum encoded remainder
        # "https://" (3B scheme) + 17 characters = 20B URL -> total 31B
        valid_url = "https://" + "a" * 17
        pkt = build_eddystone_url(valid_url)
        assert len(pkt) == 31

        # Exceeding 17 bytes encoded remainder should raise ValueError
        too_long_url = "https://" + "a" * 18
        with pytest.raises(ValueError, match="exceeds maximum allowable 31 bytes"):
            build_eddystone_url(too_long_url)

    def test_eddystone_url_invalid_prefix(self):
        with pytest.raises(ValueError, match="does not start with a valid Eddystone-URL scheme prefix"):
            build_eddystone_url("ftp://example.com")

    def test_eddystone_url_invalid_tx_power(self):
        with pytest.raises(ValueError, match="tx_power must be -128..127"):
            build_eddystone_url("https://example.com", tx_power=128)
        with pytest.raises(ValueError, match="tx_power must be -128..127"):
            build_eddystone_url("https://example.com", tx_power=-129)

    def test_eddystone_url_non_ascii(self):
        with pytest.raises(ValueError, match="Non-ASCII character"):
            build_eddystone_url("https://example.com/über")

    # --- Eddystone-TLM ---
    def test_eddystone_tlm_temperatures(self):
        # 0.0 °C
        p0 = build_eddystone_tlm(3000, 0.0, 1, 1)
        assert p0[15:17] == b"\x00\x00"

        # -20.5 °C -> 8.8 fixed point: -5248 -> 0xEB80
        p_neg = build_eddystone_tlm(3000, -20.5, 1, 1)
        assert p_neg[15:17] == b"\xeb\x80"

        # Unsupported temperature (None) -> 0x8000
        p_none = build_eddystone_tlm(3000, None, 1, 1)
        assert p_none[15:17] == b"\x80\x00"

        # Unsupported temperature (-128.0) -> 0x8000
        p_unsupported = build_eddystone_tlm(3000, -128.0, 1, 1)
        assert p_unsupported[15:17] == b"\x80\x00"

    def test_eddystone_tlm_extreme_temperatures(self):
        # Max temp ~ 127.996
        p_max = build_eddystone_tlm(3000, 127.99, 1, 1)
        assert len(p_max) == 25

        with pytest.raises(ValueError, match="temp_c must be within -128.0 to 127.996"):
            build_eddystone_tlm(3000, 130.0, 1, 1)
        with pytest.raises(ValueError, match="temp_c must be within -128.0 to 127.996"):
            build_eddystone_tlm(3000, -129.0, 1, 1)

    def test_eddystone_tlm_counter_limits(self):
        p_max_cnt = build_eddystone_tlm(0xFFFF, 25.0, 0xFFFFFFFF, 0xFFFFFFFF)
        assert len(p_max_cnt) == 25
        assert p_max_cnt[17:21] == b"\xff\xff\xff\xff"
        assert p_max_cnt[21:25] == b"\xff\xff\xff\xff"

        with pytest.raises(ValueError, match="vbatt_mv must be 0..65535"):
            build_eddystone_tlm(0x10000, 25.0, 1, 1)
        with pytest.raises(ValueError, match="adv_cnt must be 0..4294967295"):
            build_eddystone_tlm(3000, 25.0, 0x100000000, 1)
        with pytest.raises(ValueError, match="sec_cnt must be 0..4294967295"):
            build_eddystone_tlm(3000, 25.0, 1, 0x100000000)

    # --- GAEN ---
    def test_gaen_variations(self):
        p = build_gaen("01" * 16, "02" * 4, flags=0x06)
        assert len(p) == 31
        assert p[2] == 0x06  # Custom flags

    def test_gaen_invalid_inputs(self):
        with pytest.raises(ValueError, match="RPI must be exactly 16 bytes"):
            build_gaen(b"\x00" * 15, b"\x00" * 4)
        with pytest.raises(ValueError, match="AEM must be exactly 4 bytes"):
            build_gaen(b"\x00" * 16, b"\x00" * 3)


# ============================================================================
# Section 4: BurstCycleHelper & Timing Models
# ============================================================================

class TestBurstCycleHelper:
    """Tests stimulation engine timing calculations and profile rotation."""

    def test_packet_count_estimation(self):
        # 5.0 seconds at 100ms interval -> 50 packets
        count = BurstCycleHelper.estimate_packet_count(5.0, 100)
        assert count == 50

        # 10.0 seconds at 200ms interval -> 50 packets
        count2 = BurstCycleHelper.estimate_packet_count(10.0, 200)
        assert count2 == 50

        # 1.0 second at 20ms interval -> 50 packets
        count3 = BurstCycleHelper.estimate_packet_count(1.0, 20)
        assert count3 == 50

    def test_cycle_duration_calculation(self):
        dur = BurstCycleHelper.total_cycle_duration(5.0, 5.0)
        assert dur == 10.0

    def test_invalid_timing_parameters(self):
        with pytest.raises(ValueError, match="interval_ms must be positive"):
            BurstCycleHelper.estimate_packet_count(5.0, 0)
        with pytest.raises(ValueError, match="interval_ms must be positive"):
            BurstCycleHelper.estimate_packet_count(5.0, -100)
        with pytest.raises(ValueError, match="burst_duration_s cannot be negative"):
            BurstCycleHelper.estimate_packet_count(-1.0, 100)
        with pytest.raises(ValueError, match="Durations cannot be negative"):
            BurstCycleHelper.total_cycle_duration(-1.0, 5.0)
        with pytest.raises(ValueError, match="Durations cannot be negative"):
            BurstCycleHelper.total_cycle_duration(5.0, -1.0)

    def test_profile_rotation_cycle(self):
        p1 = BurstProfile(name="Profile1", adv_data=b"\x01")
        p2 = BurstProfile(name="Profile2", adv_data=b"\x02")
        p3 = BurstProfile(name="Profile3", adv_data=b"\x03")

        helper = BurstCycleHelper()
        helper.add_profile(p1)
        helper.add_profile(p2)
        helper.add_profile(p3)
        assert helper.current_profile == p1

        # Test rotation: 1 -> 2 -> 3 -> 1
        assert helper.next_profile() == p1
        assert helper.next_profile() == p2
        assert helper.next_profile() == p3
        assert helper.next_profile() == p1

        # Reset
        helper.reset()
        assert helper.next_profile() == p1

    def test_empty_profile_schedule_raises(self):
        helper = BurstCycleHelper()
        assert helper.current_profile is None
        with pytest.raises(ValueError, match="No burst profiles configured"):
            helper.next_profile()
