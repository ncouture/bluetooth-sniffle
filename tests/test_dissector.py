"""Unit tests for BLE Link Layer PDU Dissector and Identifier Extractor."""

import struct
from uuid import UUID

import pytest

from bluetooth_sniffle.protocol.mac import (
    generate_palindromic_mac,
    mac_to_str,
    str_to_mac,
)
from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.sniff.dissector import (
    BleAddressType,
    IBeaconInfo,
    classify_address,
    decode_local_name,
    dissect_advertising_pdu,
    dissect_packet,
    parse_ad_structures,
)


class TestPduDemuxing:
    """Tests demuxing of Link Layer advertising channel PDUs."""

    def test_demux_adv_ind(self):
        """ADV_IND (0x00) with Complete Local Name."""
        adv_a = bytes.fromhex("112233445566")
        name_ad = b"\x0b\x09TestDevice"
        payload = adv_a + name_ad
        raw_pdu = bytes([0x40, len(payload)]) + payload  # TxAdd = 1 (Random)

        frame = dissect_advertising_pdu(raw_pdu, chan=37, rssi=-65, ts_usec=1000)
        assert frame.pdu_type == "ADV_IND"
        assert frame.pdu_type_id == 0x00
        assert frame.adv_a == "11:22:33:44:55:66"
        assert frame.adv_a_raw == adv_a
        assert frame.device_name == "TestDevice"
        assert frame.complete_local_name == "TestDevice"
        assert frame.channel == 37
        assert frame.chan == 37
        assert frame.rssi == -65
        assert frame.timestamp_usec == 1000
        assert not frame.is_malformed

    def test_demux_adv_direct_ind(self):
        """ADV_DIRECT_IND (0x01) with AdvA and TargetA."""
        adv_a = bytes.fromhex("c011222211c0")
        target_a = bytes.fromhex("554433221100")
        raw_pdu = bytes([0xC1, 12]) + adv_a + target_a  # TxAdd=1, RxAdd=1

        frame = dissect_advertising_pdu(raw_pdu)
        assert frame.pdu_type == "ADV_DIRECT_IND"
        assert frame.adv_a == "C0:11:22:22:11:C0"
        assert frame.target_a == "55:44:33:22:11:00"
        assert frame.adv_a_type == "Random Static"
        assert frame.target_a_type == "NRPA"
        assert not frame.is_malformed

    def test_demux_adv_nonconn_ind(self):
        """ADV_NONCONN_IND (0x02) non-connectable beacon."""
        adv_a = bytes.fromhex("665544332211")
        flags_ad = b"\x02\x01\x06"
        raw_pdu = bytes([0x02, len(adv_a) + len(flags_ad)]) + adv_a + flags_ad

        frame = dissect_advertising_pdu(raw_pdu)
        assert frame.pdu_type == "ADV_NONCONN_IND"
        assert frame.adv_a == "66:55:44:33:22:11"
        assert frame.adv_a_type == "Public"
        assert frame.flags == 0x06
        assert not frame.is_malformed

    def test_demux_scan_req_vector_8(self, ground_truth_vectors):
        """Vector 8: SCAN_REQ exact match and attribute assertions."""
        raw_pdu = bytes.fromhex(ground_truth_vectors["SCAN_REQ"])
        frame = dissect_advertising_pdu(raw_pdu, chan=38, rssi=-50, ts_usec=2000000)

        assert frame.pdu_type == "SCAN_REQ"
        assert frame.pdu_type_id == 0x03
        assert frame.scan_a == "C0:11:22:22:11:C0"
        assert frame.scan_a_raw == bytes.fromhex("c011222211c0")
        assert frame.adv_a == "C0:33:44:44:33:C0"
        assert frame.adv_a_raw == bytes.fromhex("c033444433c0")
        assert frame.tx_add == 1
        assert frame.rx_add == 1
        assert frame.scan_a_type == "Random Static"
        assert frame.adv_a_type == "Random Static"
        assert frame.channel == 38
        assert frame.rssi == -50
        assert frame.timestamp_usec == 2000000
        assert not frame.is_malformed

    def test_demux_scan_rsp_vector_9(self, ground_truth_vectors):
        """Vector 9: SCAN_RSP exact match with device name and 128-bit UUID."""
        raw_pdu = bytes.fromhex(ground_truth_vectors["SCAN_RSP"])
        frame = dissect_advertising_pdu(raw_pdu)

        assert frame.pdu_type == "SCAN_RSP"
        assert frame.pdu_type_id == 0x04
        assert frame.adv_a == "C0:33:44:44:33:C0"
        assert frame.adv_a_type == "Random Static"
        assert frame.device_name == "PoPETs-01"
        assert frame.complete_local_name == "PoPETs-01"
        assert frame.service_uuids_128 == [UUID("00010203-0405-0607-0809-0a0b0c0d0e0f")]
        assert not frame.is_malformed

    def test_demux_connect_ind(self):
        """CONNECT_IND (0x05) with 22-byte LLData parameters."""
        init_a = bytes.fromhex("112233445566")
        adv_a = bytes.fromhex("665544332211")
        # LLData: AA(4B), CRCInit(3B), WinSize(1B), WinOffset(2B), Interval(2B),
        # Latency(2B), Timeout(2B), ChM(5B), Hop+SCA(1B)
        lldata = (
            struct.pack("<I", 0x12345678)  # AA
            + bytes([0x55, 0x55, 0x55])   # CRCInit
            + bytes([2])                   # WinSize
            + struct.pack("<HHHH", 6, 24, 0, 100)  # WinOffset, Interval, Latency, Timeout
            + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F])  # ChM
            + bytes([0x27])  # Hop=7, SCA=1 (0x20 | 0x07)
        )
        raw_pdu = bytes([0x05, len(init_a) + len(adv_a) + len(lldata)]) + init_a + adv_a + lldata

        frame = dissect_advertising_pdu(raw_pdu)
        assert frame.pdu_type == "CONNECT_IND"
        assert frame.init_a == "11:22:33:44:55:66"
        assert frame.adv_a == "66:55:44:33:22:11"
        assert frame.conn_params is not None
        assert frame.conn_params.aa_conn == 0x12345678
        assert frame.conn_params.crc_init == 0x555555
        assert frame.conn_params.win_size == 2
        assert frame.conn_params.win_offset == 6
        assert frame.conn_params.interval == 24
        assert frame.conn_params.latency == 0
        assert frame.conn_params.timeout == 100
        assert frame.conn_params.chm == bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F])
        assert frame.conn_params.hop == 7
        assert frame.conn_params.sca == 1

    def test_demux_adv_scan_ind(self):
        """ADV_SCAN_IND (0x06) scannable undirected advertising."""
        adv_a = bytes.fromhex("aabbccddeeff")
        short_name = b"\x05\x08Test"
        raw_pdu = bytes([0x06, 6 + len(short_name)]) + adv_a + short_name

        frame = dissect_advertising_pdu(raw_pdu)
        assert frame.pdu_type == "ADV_SCAN_IND"
        assert frame.adv_a == "AA:BB:CC:DD:EE:FF"
        assert frame.device_name == "Test"
        assert frame.shortened_local_name == "Test"

    def test_demux_adv_ext_ind(self):
        """ADV_EXT_IND (0x07) extended advertising indication."""
        adv_a = bytes.fromhex("123456789abc")
        raw_pdu = bytes([0x07, 6]) + adv_a

        frame = dissect_advertising_pdu(raw_pdu)
        assert frame.pdu_type == "ADV_EXT_IND"
        assert frame.adv_a == "12:34:56:78:9A:BC"


class TestAddressClassification:
    """Tests address type classification according to Bluetooth Core Spec."""

    def test_classify_public(self):
        """TxAdd=0 forces Public address regardless of bit patterns."""
        mac = bytes.fromhex("c011222211c0")
        assert classify_address(mac, is_random=False) == BleAddressType.PUBLIC

    def test_classify_random_static(self):
        """MSB bits 11b -> Random Static."""
        mac = bytes.fromhex("c011222211c0")
        assert classify_address(mac, is_random=True) == BleAddressType.RANDOM_STATIC

    def test_classify_nrpa(self):
        """MSB bits 00b -> NRPA."""
        mac = bytes.fromhex("112233445500")  # mac[5] is 0x00
        assert classify_address(mac, is_random=True) == BleAddressType.NRPA

    def test_classify_rpa(self):
        """MSB bits 01b -> RPA."""
        mac = bytes.fromhex("112233445540")  # mac[5] is 0x40 (01000000b)
        assert classify_address(mac, is_random=True) == BleAddressType.RPA

    def test_palindromic_mac_symmetry(self):
        """Palindromic MACs maintain identical string and byte symmetry."""
        p_mac = generate_palindromic_mac(address_type="static")
        mac_str = mac_to_str(p_mac)
        assert str_to_mac(mac_str) == p_mac
        assert classify_address(p_mac, is_random=True) == BleAddressType.RANDOM_STATIC


class TestBeaconDecodingGroundTruth:
    """Tests decoding and deep reverse-extraction against all Milestone 1 beacons."""

    def test_vector_1_ibeacon(self, ground_truth_vectors):
        """Vector 1: Apple iBeacon reverse extraction."""
        ad_payload = bytes.fromhex(ground_truth_vectors["iBeacon"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "iBeacon"
        assert isinstance(frame.beacon_info, IBeaconInfo)
        assert frame.beacon_info.uuid == UUID("e2c56db5-dffb-48d2-b060-d0f5a71096e0")
        assert frame.beacon_info.major == 1
        assert frame.beacon_info.minor == 2
        assert frame.beacon_info.tx_power == -59
        assert len(frame.manufacturer_data) == 1
        assert frame.manufacturer_data[0].company_id == 0x004C

    def test_vector_2_altbeacon(self, ground_truth_vectors):
        """Vector 2: AltBeacon reverse extraction."""
        ad_payload = bytes.fromhex(ground_truth_vectors["AltBeacon"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "AltBeacon"
        assert frame.beacon_info is not None
        assert frame.beacon_info.mfg_id == 0x0118
        assert frame.beacon_info.beacon_code == 0xBEAC
        assert frame.beacon_info.ref_rssi == -59
        assert frame.beacon_info.beacon_id == bytes.fromhex(
            "e2c56db5dffb48d2b060d0f5a71096e000010002"
        )

    def test_vector_3_eddystone_uid(self, ground_truth_vectors):
        """Vector 3: Google Eddystone-UID reverse extraction."""
        ad_payload = bytes.fromhex(ground_truth_vectors["Eddystone-UID"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-UID"
        assert frame.beacon_info is not None
        assert frame.beacon_info.namespace == bytes.fromhex("0102030405060708090a")
        assert frame.beacon_info.instance == bytes.fromhex("010203040506")
        assert frame.beacon_info.tx_power == -20
        assert 0xFEAA in frame.service_uuids_16
        assert "0xFEAA" in frame.service_data

    def test_vector_4_eddystone_url(self, ground_truth_vectors):
        """Vector 4: Google Eddystone-URL reverse extraction and URL expansion."""
        ad_payload = bytes.fromhex(ground_truth_vectors["Eddystone-URL"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-URL"
        assert frame.beacon_info is not None
        assert frame.beacon_info.url == "https://example.com/test"
        assert frame.beacon_info.tx_power == -18

    def test_vector_5_eddystone_tlm(self, ground_truth_vectors):
        """Vector 5: Google Eddystone-TLM telemetry unpacking."""
        ad_payload = bytes.fromhex(ground_truth_vectors["Eddystone-TLM"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-TLM"
        assert frame.beacon_info is not None
        assert frame.beacon_info.vbatt_mv == 3000
        assert frame.beacon_info.temp_c == 20.5
        assert frame.beacon_info.adv_cnt == 1000
        assert frame.beacon_info.sec_cnt == 10000

    def test_vector_6_gaen(self, ground_truth_vectors):
        """Vector 6: GAEN (0xFD6F) RPI and AEM extraction."""
        ad_payload = bytes.fromhex(ground_truth_vectors["GAEN"])
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, len(adv_a) + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "GAEN"
        assert frame.beacon_info is not None
        assert frame.beacon_info.rpi == bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        assert frame.beacon_info.aem == bytes.fromhex("11223344")
        assert 0xFD6F in frame.service_uuids_16
        assert "0xFD6F" in frame.service_data


class TestDissectorEdgeCases:
    """Tests resilience against malformed, truncated, and noisy frames."""

    def test_empty_or_too_short_pdu_raises(self):
        """PDU shorter than 2 bytes raises ValueError."""
        with pytest.raises(ValueError, match="at least 2 bytes"):
            dissect_advertising_pdu(b"")
        with pytest.raises(ValueError, match="at least 2 bytes"):
            dissect_advertising_pdu(b"\x00")

    def test_truncated_pdu_marked_malformed(self):
        """Header length exceeds buffer bytes."""
        # Type 0 (ADV_IND), claims 20 bytes, but only 4 bytes follow
        pdu = bytes([0x00, 20, 0x11, 0x22, 0x33, 0x44])
        frame = dissect_advertising_pdu(pdu)
        assert frame.is_malformed
        assert "Truncated PDU payload" in (frame.error_details or "")

    def test_ad_padding_zero_terminator(self):
        """Zero padding terminates AD iteration cleanly."""
        data = b"\x02\x01\x06\x00\x00\x00"
        ads, malformed, err = parse_ad_structures(data)
        assert not malformed
        assert len(ads) == 1
        assert ads[0].ad_type == 0x01

    def test_corrupted_local_name_utf8_fallback(self):
        """Invalid UTF-8 bytes gracefully fall back to hex formatting."""
        bad_bytes = b"\xff\xfe\xfd"
        name = decode_local_name(bad_bytes)
        assert name == "<hex:fffefd>"

    def test_truncated_ad_structure(self):
        """AD structure claiming length beyond buffer sets is_malformed."""
        bad_ad = b"\x08\x09Hello"  # claims 8 bytes, only 6 available
        ads, malformed, err = parse_ad_structures(bad_ad)
        assert malformed
        assert len(ads) == 1
        assert ads[0].is_malformed

    def test_packet_message_wrapper(self):
        """dissect_packet integrates seamlessly with PacketMessage."""
        adv_a = bytes.fromhex("112233445566")
        body = bytes([0x02, 6]) + adv_a
        # Unpack format in wire.py: ts (uint32 LE), l_field (uint16 LE), event (uint16 LE), rssi (int8), chan_phy (uint8)
        raw_hdr = struct.pack("<LHHbB", 987654, len(body), 0, -72, 39)
        pkt = PacketMessage(raw_hdr + body)
        frame = dissect_packet(pkt)
        assert frame.pdu_type == "ADV_NONCONN_IND"
        assert frame.adv_a == "11:22:33:44:55:66"
        assert frame.channel == 39
        assert frame.rssi == -72
        assert frame.timestamp_usec == 987654

    def test_microsoft_cdp_decoding(self):
        """MS-CDP 27-byte beacon structure decoding."""
        # 0x0006 Company ID, 25B payload
        mfg_data = bytes([
            0x01,  # Scenario
            0x09,  # Device Type: Windows 10 Desktop
            0x00,  # Flags
            0x01,  # Status
            0x10, 0x20, 0x30, 0x40,  # Salt
        ]) + b"\xAA" * 19  # Device Hash

        ad_payload = bytes([len(mfg_data) + 3, 0xFF, 0x06, 0x00]) + mfg_data
        adv_a = bytes.fromhex("112233445566")
        pdu = bytes([0x02, 6 + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        rec = frame.manufacturer_data[0]
        assert rec.company_id == 0x0006
        assert rec.microsoft_cdp is not None
        assert rec.microsoft_cdp.device_type_name == "Windows 10 Desktop"
        assert rec.microsoft_cdp.salt == 0x40302010

    def test_apple_continuity_submessages(self):
        """Apple Continuity payload containing AirDrop and Nearby Info sub-messages."""
        # 0x05 AirDrop: sub-type 0x05, len 3, data \x01\x02\x03
        # 0x10 Nearby Info: sub-type 0x10, len 2, data \x0A\x0B
        apple_payload = bytes([0x05, 0x03, 0x01, 0x02, 0x03, 0x10, 0x02, 0x0A, 0x0B])
        ad_payload = bytes([len(apple_payload) + 3, 0xFF, 0x4C, 0x00]) + apple_payload
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, 6 + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert len(frame.manufacturer_data) == 1
        mfg = frame.manufacturer_data[0]
        assert mfg.company_id == 0x004C
        assert len(mfg.apple_messages) == 2
        assert mfg.apple_messages[0].sub_type_name == "AirDrop"
        assert mfg.apple_messages[1].sub_type_name == "Nearby Info"

    def test_service_data_32_and_128_bit(self):
        """Service Data with 32-bit UUID (0x20) and 128-bit UUID (0x21)."""
        sd32 = bytes([0x06, 0x20, 0x78, 0x56, 0x34, 0x12, 0xAA])  # 32-bit UUID 0x12345678, payload 0xAA
        sd128_uuid = UUID("12345678-1234-5678-1234-567812345678")
        sd128 = bytes([1 + 16 + 2, 0x21]) + sd128_uuid.bytes + b"\xBB\xCC"
        adv_a = bytes.fromhex("112233445566")
        pdu = bytes([0x02, 6 + len(sd32) + len(sd128)]) + adv_a + sd32 + sd128

        frame = dissect_advertising_pdu(pdu)
        assert "0x12345678" in frame.service_data
        assert frame.service_data["0x12345678"] == b"\xAA"
        assert str(sd128_uuid) in frame.service_data
        assert frame.service_data[str(sd128_uuid)] == b"\xBB\xCC"

    def test_eddystone_uncalibrated_temp(self):
        """Eddystone-TLM with temperature field 0x8000 (-128.0) yields temp_c None."""
        # 0x20 TLM, version 0, VBATT 3000mV, Temp 0x8000, AdvCnt 100, SecCnt 200
        tlm_bytes = bytes([
            0x20, 0x00,
            0x0B, 0xB8,
            0x80, 0x00,  # 0x8000
            0x00, 0x00, 0x00, 0x64,
            0x00, 0x00, 0x00, 0xC8,
        ])
        ad_payload = bytes([len(tlm_bytes) + 3, 0x16, 0xAA, 0xFE]) + tlm_bytes
        adv_a = bytes.fromhex("c011222211c0")
        pdu = bytes([0x42, 6 + len(ad_payload)]) + adv_a + ad_payload

        frame = dissect_advertising_pdu(pdu)
        assert frame.beacon_type == "Eddystone-TLM"
        assert frame.beacon_info is not None
        assert frame.beacon_info.temp_c is None

    def test_tx_power_level_ad(self):
        """Tx Power Level (0x0A) extracted as signed int8."""
        tx_power_ad = bytes([0x02, 0x0A, 0xF6])  # 0xF6 = -10 dBm
        adv_a = bytes.fromhex("112233445566")
        pdu = bytes([0x02, 6 + len(tx_power_ad)]) + adv_a + tx_power_ad

        frame = dissect_advertising_pdu(pdu)
        assert frame.tx_power_level == -10
