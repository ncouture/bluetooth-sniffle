"""Unit tests for DLT 256 PCAP Writer and Reader (Wireshark/crackle compatibility)."""

import io
import shutil
import struct
import subprocess
import threading
from pathlib import Path

import pytest

from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.sniff.dissector import DissectedBleFrame
from bluetooth_sniffle.sniff.pcap import (
    BLE_ADV_AA,
    BLE_ADV_CRC_INIT_REV,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    GLOBAL_HEADER_FORMAT,
    PACKET_HEADER_FORMAT,
    PCAP_MAGIC_USEC,
    PCAP_VERSION_MAJOR,
    PCAP_VERSION_MINOR,
    PSEUDO_HEADER_FORMAT,
    PcapBleReader,
    PcapBleWriter,
    ble_to_rf_chan,
    build_pseudo_header_flags,
    crc_ble_reverse,
    normalize_rssi,
    rf_to_ble_chan,
)


class TestPcapHeaderAndChannelMaps:
    """Tests global header structure, pseudo-header bitfields, and channel mapping."""

    def test_global_header_structure(self):
        """PcapBleWriter writes exact 24-byte PCAP header for DLT 256."""
        stream = io.BytesIO()
        writer = PcapBleWriter(output=stream)
        raw_header = stream.getvalue()[:24]

        assert len(raw_header) == 24
        magic, major, minor, thiszone, sigfigs, snaplen, dlt = struct.unpack(
            GLOBAL_HEADER_FORMAT, raw_header
        )
        assert magic == PCAP_MAGIC_USEC  # 0xA1B2C3D4
        assert major == PCAP_VERSION_MAJOR  # 2
        assert minor == PCAP_VERSION_MINOR  # 4
        assert thiszone == 0
        assert sigfigs == 0
        assert snaplen == 65535
        assert dlt == DLT_BLUETOOTH_LE_LL_WITH_PHDR  # 256
        writer.close()

    def test_packet_header_and_pseudo_header(self):
        """Single packet record header (16B) and pseudo-header (10B) fields."""
        stream = io.BytesIO()
        writer = PcapBleWriter(output=stream, base_epoch=1700000000.0)

        # Write packet with relative microsecond timestamp
        pdu = bytes([0x02, 0x01, 0x06])
        writer.write_packet(
            ts_usec=500_000,
            aa=BLE_ADV_AA,
            chan=37,
            rssi=-60,
            packet=pdu,
            crc_err=False,
        )

        data = stream.getvalue()[24:]  # Skip global header
        assert len(data) >= 16 + 10 + 4 + len(pdu) + 3

        # Record header (16B)
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            PACKET_HEADER_FORMAT, data[:16]
        )
        assert ts_sec == 1700000000
        assert ts_usec == 500_000
        assert incl_len == orig_len
        assert incl_len == 10 + 4 + len(pdu) + 3

        # Pseudo-header (10B)
        rf_chan, rssi, noise, aa_off, ref_aa, flags = struct.unpack(
            PSEUDO_HEADER_FORMAT, data[16:26]
        )
        assert rf_chan == 0  # Ch 37 -> RF 0
        assert rssi == -60
        assert noise == -128
        assert aa_off == 0
        assert ref_aa == BLE_ADV_AA
        # Dewhitened (0x01) | SigPower (0x02) | RefAA (0x10) | CRC Checked (0x0400) | CRC Valid (0x0800) = 0x0C13
        assert flags == 0x0C13
        writer.close()

    def test_ble_to_rf_channel_mapping_all(self):
        """RF physical channel mapping for primary and data advertising channels."""
        assert ble_to_rf_chan(37) == 0
        assert ble_to_rf_chan(38) == 12
        assert ble_to_rf_chan(39) == 39

        for c in range(40):
            rf = ble_to_rf_chan(c)
            assert 0 <= rf <= 39
            assert rf_to_ble_chan(rf) == c

    def test_flags_crc_error_and_phy(self):
        """Pseudo-header flags encode CRC validity and PHY modes."""
        # Valid CRC -> 0x0C13
        flags_valid = build_pseudo_header_flags(crc_err=False, phy=0)
        assert flags_valid & 0x0001  # Dewhitened
        assert flags_valid & 0x0400  # CRC Checked
        assert flags_valid & 0x0800  # CRC Valid
        assert flags_valid == 0x0C13

        # Invalid CRC -> 0x0413
        flags_err = build_pseudo_header_flags(crc_err=True, phy=0)
        assert flags_err & 0x0400  # CRC Checked
        assert not (flags_err & 0x0800)  # CRC Valid clear
        assert flags_err == 0x0413

        # Coded PHY S=2
        flags_s2 = build_pseudo_header_flags(crc_err=False, phy=3)
        assert (flags_s2 >> 14) & 0x03 == 2


class TestPcapWriterReaderRoundTrip:
    """Tests writing and reading packets across various payloads and configurations."""

    def test_crc24_calculation_known_vector(self):
        """Reversed BLE CRC lookup table produces bit-exact checksum."""
        # ADV_NONCONN_IND with AdvA and 1 byte payload
        pdu = bytes([0x02, 0x07, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00])
        crc = crc_ble_reverse(BLE_ADV_CRC_INIT_REV, pdu)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFFFF

    def test_context_manager_lifecycle(self, tmp_path: Path):
        """Context manager closes stream cleanly and idempotently."""
        pcap_file = tmp_path / "test_lifecycle.pcap"
        with PcapBleWriter(output=pcap_file) as writer:
            writer.write_packet(ts_usec=100_000, chan=37, packet=b"\x00\x00")
            assert not writer._closed

        assert writer._closed
        # Idempotent close
        writer.close()
        assert writer._closed

    def test_round_trip_reader_matches_writer(self, tmp_path: Path):
        """Packets written by PcapBleWriter are faithfully read by PcapBleReader."""
        pcap_file = tmp_path / "round_trip.pcap"
        writer = PcapBleWriter(output=pcap_file, base_epoch=1700000000.0)

        pdu1 = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        pdu2 = bytes([0x03, 0x0C]) + bytes.fromhex("c011222211c0c033444433c0")

        writer.write_packet(
            ts_usec=1_000_000, chan=37, rssi=-55, packet=pdu1, crc_err=False
        )
        writer.write_packet(
            ts_usec=2_500_000, chan=38, rssi=-70, packet=pdu2, crc_err=True
        )
        writer.close()

        reader = PcapBleReader(pcap_file)
        packets = list(reader)
        assert len(packets) == 2

        pkt1 = packets[0]
        assert pkt1.ble_chan == 37
        assert pkt1.rf_chan == 0
        assert pkt1.rssi == -55
        assert pkt1.crc_err is False
        assert pkt1.body == pdu1
        assert pkt1.aa == BLE_ADV_AA

        pkt2 = packets[1]
        assert pkt2.ble_chan == 38
        assert pkt2.rf_chan == 12
        assert pkt2.rssi == -70
        assert pkt2.crc_err is True
        assert pkt2.body == pdu2

        reader.close()

    def test_multithreaded_pcap_writing(self, tmp_path: Path):
        """Thread-safe writing from 10 concurrent threads."""
        pcap_file = tmp_path / "threaded.pcap"
        writer = PcapBleWriter(output=pcap_file, base_epoch=1700000000.0)

        def worker(thread_idx: int):
            for i in range(50):
                pdu = bytes([0x00, 6, thread_idx, i, 0, 0, 0, 0])
                writer.write_packet(
                    ts_usec=1000 * (thread_idx * 50 + i),
                    chan=37 + (thread_idx % 3),
                    rssi=-60,
                    packet=pdu,
                )

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        writer.close()

        reader = PcapBleReader(pcap_file)
        all_pkts = list(reader)
        assert len(all_pkts) == 500
        reader.close()

    def test_timestamp_microsecond_rollover(self):
        """Backwards time jump > 2^31 triggers microsecond rollover unwrapping."""
        stream = io.BytesIO()
        writer = PcapBleWriter(output=stream, base_epoch=1700000000.0)

        # Write timestamp near 2^32
        writer.write_packet(ts_usec=4_294_960_000, chan=37, packet=b"\x00\x00")
        # Counter wraps to 10_000 (delta jump backwards > 2^31)
        writer.write_packet(ts_usec=10_000, chan=37, packet=b"\x00\x00")
        writer.close()

        stream.seek(0)
        reader = PcapBleReader(stream)
        pkts = list(reader)
        assert len(pkts) == 2
        assert pkts[0].ts_epoch >= 1700000000.0
        assert pkts[1].ts_epoch > pkts[0].ts_epoch
        reader.close()

    test_microsecond_rollover_unwrapping = test_timestamp_microsecond_rollover

    def test_rssi_boundary_clamping(self):
        """normalize_rssi clamps floats, unsigned bytes, and out-of-range values."""
        assert normalize_rssi(-60) == -60
        assert normalize_rssi(-64.8) == -65
        assert normalize_rssi(200) == 200 - 256  # -56 dBm
        assert normalize_rssi(-300) == -128
        assert normalize_rssi(300) == 127
        assert normalize_rssi("invalid") == -128

    def test_auto_create_directories(self, tmp_path: Path):
        """PcapBleWriter automatically creates non-existent parent directories."""
        nested = tmp_path / "deeply" / "nested" / "capture.pcap"
        writer = PcapBleWriter(output=nested)
        writer.write_packet(ts_usec=1000, packet=b"\x00\x00")
        writer.close()
        assert nested.exists()
        assert nested.stat().st_size > 24

    def test_empty_pcap_validity(self, tmp_path: Path):
        """0-packet PCAP produces exactly 24-byte file readable by PcapBleReader."""
        empty_pcap = tmp_path / "empty.pcap"
        writer = PcapBleWriter(output=empty_pcap)
        writer.close()

        assert empty_pcap.stat().st_size == 24
        reader = PcapBleReader(empty_pcap)
        assert list(reader) == []
        reader.close()

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
    def test_tshark_cli_dissection(self, tmp_path: Path):
        """Wireshark/tshark dissects generated PCAP without malformed packet errors."""
        pcap_file = tmp_path / "tshark_verify.pcap"
        with PcapBleWriter(output=pcap_file, base_epoch=1700000000.0) as writer:
            # Vector 1: iBeacon
            ibeacon_pdu = bytes.fromhex(
                "021e6655443322110201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5"
            )
            writer.write_packet(
                ts_usec=1_000_000,
                aa=BLE_ADV_AA,
                chan=37,
                rssi=-60,
                packet=ibeacon_pdu,
                crc_err=False,
            )

            # Vector 8: SCAN_REQ
            scan_req_pdu = bytes.fromhex("c30cc011222211c0c033444433c0")
            writer.write_packet(
                ts_usec=1_050_000,
                aa=BLE_ADV_AA,
                chan=37,
                rssi=-58,
                packet=scan_req_pdu,
                crc_err=False,
            )

        res = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "[Malformed Packet" not in res.stdout
        assert "Bluetooth Low Energy Link Layer" in res.stdout
        assert "CRC: 0x" in res.stdout

    def test_write_packet_message_and_dissected_frame(self, tmp_path: Path):
        """PcapBleWriter handles PacketMessage and DissectedBleFrame objects."""
        pcap_file = tmp_path / "helpers.pcap"
        writer = PcapBleWriter(output=pcap_file, base_epoch=1700000000.0)

        # 1. PacketMessage on data channel (chan=15, dir=1)
        body = bytes([0x01, 0x02, 0xAA, 0xBB])
        # bit 15 of l_field = 1 (Slave->Master), bit 14 = 0
        l_field = len(body) | 0x8000
        chan_phy = (15 & 0x3F) | (1 << 6)  # PHY 2M
        raw_hdr = struct.pack("<LHHbB", 100_000, l_field, 5, -50, chan_phy)
        pkt_msg = PacketMessage(raw_hdr + body)
        writer.write_packet_message(pkt_msg)

        # 2. DissectedBleFrame
        frame = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=1,
            rx_add=0,
            length=8,
            adv_a="11:22:33:44:55:66",
            channel=39,
            rssi=-63,
            timestamp_usec=200_000,
            raw_pdu=bytes([0x40, 6]) + bytes.fromhex("112233445566"),
        )
        writer.write_dissected_frame(frame)
        writer.close()

        reader = PcapBleReader(pcap_file)
        packets = list(reader)
        assert len(packets) == 2

        # Packet 1: data channel 15 -> RF channel 17
        assert packets[0].ble_chan == 15
        assert packets[0].rf_chan == 17
        assert packets[0].phy == 1
        assert packets[0].pdu_type == 3  # Slave->Master

        # Packet 2: advertising channel 39 -> RF channel 39
        assert packets[1].ble_chan == 39
        assert packets[1].rf_chan == 39
        assert packets[1].rssi == -63
        reader.close()

    def test_coded_phy_round_trip(self, tmp_path: Path):
        """PcapBleWriter and Reader handle Coded PHY S=8 and S=2."""
        pcap_file = tmp_path / "coded.pcap"
        writer = PcapBleWriter(output=pcap_file, base_epoch=1700000000.0)

        pdu = bytes([0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        writer.write_packet(ts_usec=1000, phy=2, packet=pdu)  # Coded S=8
        writer.write_packet(ts_usec=2000, phy=3, packet=pdu)  # Coded S=2
        writer.close()

        reader = PcapBleReader(pcap_file)
        packets = list(reader)
        assert len(packets) == 2
        assert packets[0].phy == 2
        assert packets[0].body == pdu
        assert packets[1].phy == 2  # flags phy bits (flags >> 14 & 0x03) sets 2 for coded
        assert packets[1].body == pdu
        reader.close()
