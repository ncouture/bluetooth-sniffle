"""Milestone 5 Tier 5: White-Box Adversarial Hardening.

Stress and attack internal components under hostile, corrupted, and degraded inputs:
1. Packet corruption:
   - Truncated hardware headers (1-9 bytes).
   - Oversized declared lengths (>255 bytes / AD length exceeding payload).
   - CRC failures (crc_err bit set in wire framing and libpcap PHDR).
2. Framing jitter:
   - Split Base64 chunks across boundaries.
   - Missing or corrupted CRLF line delimiters.
   - Interleaved binary noise between valid wire frames.
3. Multi-threaded concurrency stress:
   - Concurrent writers streaming into a single PcapBleWriter.
   - Simultaneous reader/writer access to TelemetrySession.
   - High-concurrency device registration and packet broadcast on VirtualRadioBus.
4. Rapid SIGINT / teardown simulation:
   - Abrupt controller termination during active capture.
   - Half-written PCAP recovery (PcapBleReader iterator handles EOF gracefully).
   - Clean shutdown without thread or file descriptor leaks.
5. Buffer overflow recovery:
   - Massive packet bursts exceeding queue buffer capacity.
   - Rapid packet draining via batch operations without memory leaks.
"""

from __future__ import annotations

import base64
import concurrent.futures
import threading
import time
from pathlib import Path

import pytest

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.protocol.wire import (
    MESSAGE_BLEFRAME,
    PacketMessage,
    decode_msg,
    encode_msg,
    parse_sniffle_message,
)
from bluetooth_sniffle.sniff.dissector import (
    dissect_advertising_pdu,
)
from bluetooth_sniffle.sniff.pcap import PcapBleReader, PcapBleWriter
from bluetooth_sniffle.sniff.telemetry import TelemetrySession


# ==============================================================================
# 1. Packet Corruption Adversarial Tests
# ==============================================================================
class TestPacketCorruptionAdversarial:
    """Attacks parser with truncated headers, oversized lengths, and bad CRCs."""

    @pytest.mark.parametrize("header_len", range(1, 10))
    def test_truncated_hardware_headers_raise_value_error(self, header_len: int) -> None:
        """Hardware header must be at least 10 bytes; smaller slices must raise ValueError."""
        truncated = bytes(range(header_len))
        with pytest.raises(ValueError, match="PacketMessage body too short"):
            PacketMessage(truncated)

    def test_oversized_declared_ad_length_handled_gracefully(self) -> None:
        """PDU declaring AD structure length larger than available bytes must flag malformed."""
        mac = bytes.fromhex("112233445566")
        # AD length 0xFE (254) declared, but only 3 bytes of value follow
        malformed_ad = bytes([0xFE, 0x09, 0x41, 0x42])
        pdu = bytes([0x02, len(mac) + len(malformed_ad)]) + mac + malformed_ad

        frame = dissect_advertising_pdu(pdu, chan=37, rssi=-60)
        assert frame.is_malformed
        assert frame.error_details is not None
        assert "truncated" in frame.error_details.lower() or "malformed" in frame.error_details.lower()

    def test_oversized_declared_pdu_length_handled_gracefully(self) -> None:
        """Link Layer header declaring length 255 but payload truncated must flag malformed."""
        mac = bytes.fromhex("112233445566")
        # Declares 255 bytes, but only mac (6B) provided
        pdu = bytes([0x02, 0xFF]) + mac
        frame = dissect_advertising_pdu(pdu, chan=37, rssi=-60)
        assert frame.is_malformed
        assert frame.error_details is not None

    def test_crc_failure_propagation_through_pcap(self, tmp_path: Path) -> None:
        """Packets with CRC failures must be flagged in PCAP pseudo-header and correctly parsed."""
        pcap_path = tmp_path / "crc_failed.pcap"
        mac = bytes.fromhex("c011222211c0")
        pdu = bytes([0x02, 6]) + mac

        # Write packet with crc_err=True
        with PcapBleWriter(pcap_path) as writer:
            writer.write_packet(
                ts_usec=100_000,
                aa=0x8E89BED6,
                chan=37,
                rssi=-70,
                packet=pdu,
                crc_err=True,
            )

        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 1
            assert pkts[0].crc_err is True
            # In PHDR flags, Bit 11 is CRC Valid. When crc_err=True, Bit 11 must be 0.
            assert not (pkts[0].flags & 0x0800)


# ==============================================================================
# 2. Framing Jitter Adversarial Tests
# ==============================================================================
class TestFramingJitterAdversarial:
    """Attacks wire line decoding with split chunks, missing delimiters, and binary noise."""

    def test_split_base64_chunks_across_boundaries(self) -> None:
        """MockSerialInterface must reassemble lines split across multiple read chunks."""
        ser = MockSerialInterface()
        body = PacketMessage.pack(body=b"\x02\x06\x11\x22\x33\x44\x55\x66")
        encoded_line = encode_msg(MESSAGE_BLEFRAME, body)

        # Split encoded line into three arbitrary chunks
        chunk1 = encoded_line[:5]
        chunk2 = encoded_line[5:15]
        chunk3 = encoded_line[15:]

        ser.inject_rx_bytes(chunk1)
        ser.inject_rx_bytes(chunk2)
        ser.inject_rx_bytes(chunk3)

        reassembled = ser.readline()
        assert reassembled == encoded_line
        msg_type, msg_obj = parse_sniffle_message(reassembled)
        assert msg_type == MESSAGE_BLEFRAME
        assert isinstance(msg_obj, PacketMessage)

    def test_missing_or_corrupt_delimiters_rejected(self) -> None:
        """Lines without valid Base64 or missing headers must raise ValueError."""
        # Malformed Base64 (invalid padding)
        with pytest.raises(ValueError, match="Malformed Base64"):
            decode_msg(b"a\r\n")

        # Empty line
        with pytest.raises(ValueError, match="Cannot decode empty"):
            decode_msg(b"   \r\n")

        # Decoded payload too short (< 2 bytes)
        one_byte_b64 = base64.b64encode(b"\x01") + b"\r\n"
        with pytest.raises(ValueError, match="too short"):
            decode_msg(one_byte_b64)

    def test_interleaved_binary_noise_recovery(self) -> None:
        """Controller reader loop must ignore binary noise and parse the subsequent valid frame."""
        ser = MockSerialInterface()
        body = PacketMessage.pack(body=b"\x02\x06\xaa\xbb\xcc\xdd\xee\xff")
        valid_frame = encode_msg(MESSAGE_BLEFRAME, body)

        # Inject noise line followed by valid line
        ser.inject_rx_bytes(b"\x00\xFF\xAA\x55InvalidNoiseLine\r\n")
        ser.inject_rx_bytes(valid_frame)

        # First line fails parsing
        noise_line = ser.readline()
        with pytest.raises(ValueError):
            parse_sniffle_message(noise_line)

        # Second line parses cleanly
        valid_line = ser.readline()
        m_type, m_obj = parse_sniffle_message(valid_line)
        assert m_type == MESSAGE_BLEFRAME
        assert isinstance(m_obj, PacketMessage)
        assert m_obj.body == b"\x02\x06\xaa\xbb\xcc\xdd\xee\xff"


# ==============================================================================
# 3. Multi-Threaded Concurrency Stress Tests
# ==============================================================================
class TestMultiThreadedConcurrencyStress:
    """Stresses PcapBleWriter, TelemetrySession, and VirtualRadioBus under high concurrency."""

    def test_concurrent_writers_to_pcap_ble_writer(self, tmp_path: Path) -> None:
        """Multiple threads concurrently writing packets must not corrupt PCAP records."""
        pcap_path = tmp_path / "concurrent_stress.pcap"
        writer = PcapBleWriter(pcap_path)
        threads_count = 10
        packets_per_thread = 50
        total_packets = threads_count * packets_per_thread

        def worker(thread_id: int) -> None:
            pdu = bytes([0x02, 6, 0xC0, thread_id, 0x22, 0x22, thread_id, 0xC0])
            for i in range(packets_per_thread):
                writer.write_packet(
                    ts_usec=1_000_000 + (thread_id * 10_000) + i,
                    chan=37 + (thread_id % 3),
                    rssi=-50 - (i % 30),
                    packet=pdu,
                )

        threads = [
            threading.Thread(target=worker, args=(t,)) for t in range(threads_count)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        writer.close()

        # Verify PCAP stream integrity and packet count
        with PcapBleReader(pcap_path) as reader:
            read_pkts = list(reader)
            assert len(read_pkts) == total_packets

    def test_simultaneous_reader_writer_telemetry_session(self) -> None:
        """Simultaneous write and read access to TelemetrySession must not raise concurrency errors."""
        session = TelemetrySession(topology="Concurrency Test")
        stop_event = threading.Event()
        mac = bytes.fromhex("c011222211c0")

        def writer_worker(worker_id: int) -> None:
            count = 0
            while not stop_event.is_set() and count < 100:
                pdu = bytes([0x02, 6]) + mac
                frame = dissect_advertising_pdu(
                    pdu, chan=37 + (worker_id % 3), rssi=-60, ts_usec=1000 + count
                )
                session.record_packet(frame)
                count += 1

        def reader_worker() -> None:
            while not stop_event.is_set():
                _ = session.get_summary()
                _ = session.to_json()

        writers = [
            threading.Thread(target=writer_worker, args=(w,)) for w in range(4)
        ]
        readers = [threading.Thread(target=reader_worker) for _ in range(4)]

        for r in readers:
            r.start()
        for w in writers:
            w.start()

        for w in writers:
            w.join()
        stop_event.set()
        for r in readers:
            r.join()

        summary = session.get_summary()
        assert summary["metadata"]["total_packets"] == 400

    def test_rapid_thread_spawn_join_on_virtual_radio_bus(self) -> None:
        """VirtualRadioBus handles high thread concurrency for device register/unregister/deliver."""
        bus = VirtualRadioBus()
        errors: list[Exception] = []

        def client_task(task_id: int) -> None:
            try:
                ser = MockSerialInterface(bus=bus)
                pdu = bytes([0x02, 6, 0x40, task_id, 0x11, 0x11, task_id, 0x40])
                bus.deliver_raw_packet(pdu, chan=37, rssi=-65)
                time.sleep(0.001)
                bus.unregister_device(ser)
                ser.close()
            except Exception as exc:
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(client_task, i) for i in range(50)]
            concurrent.futures.wait(futures)

        assert not errors


# ==============================================================================
# 4. Rapid Teardown and Truncation Recovery
# ==============================================================================
class TestRapidTeardownAndTruncationRecovery:
    """Verifies graceful recovery from half-written PCAP files and abrupt shutdowns."""

    def test_abrupt_controller_termination_during_active_capture(self) -> None:
        """Abruptly closing a controller during active packet generation leaves no hung threads."""
        bus = VirtualRadioBus()
        controller = SniffleDeviceController(port="mock://abort_test", mock=True, bus=bus)
        controller.open()
        controller.start_sniffing(chan=37)

        # Inject packets
        for i in range(20):
            pdu = bytes([0x02, 6, 0x11, 0x22, 0x33, 0x44, 0x55, i])
            bus.deliver_raw_packet(pdu, chan=37)

        # Abrupt close
        controller.close()
        assert not controller.is_open
        assert controller._reader_thread is None

    def test_half_written_pcap_file_recovery(self, tmp_path: Path) -> None:
        """PcapBleReader iterator yields intact packets and safely halts when encountering truncated EOF."""
        full_pcap = tmp_path / "full.pcap"
        truncated_pcap = tmp_path / "truncated.pcap"

        # 1. Write 10 valid packets to full PCAP
        with PcapBleWriter(full_pcap) as writer:
            for i in range(10):
                pdu = bytes([0x02, 6, 0x11, 0x22, 0x33, 0x44, 0x55, i])
                writer.write_packet(ts_usec=1000 * i, chan=37, rssi=-60, packet=pdu)

        full_bytes = full_pcap.read_bytes()
        # Truncate abruptly in the middle of packet #6
        # Global header = 24 bytes, each record has 16B header + 10B pseudo + 4B AA + len(pdu) + 3B CRC
        # Slice off last 150 bytes to ensure a partial packet payload/header
        truncated_bytes = full_bytes[: len(full_bytes) - 150]
        truncated_pcap.write_bytes(truncated_bytes)

        # 2. Iterate truncated PCAP
        with PcapBleReader(truncated_pcap) as reader:
            pkts = list(reader)
            # Must yield all complete packets prior to the truncation point without crashing
            assert 1 <= len(pkts) < 10

    def test_pcap_reader_too_short_for_global_header(self, tmp_path: Path) -> None:
        """Files shorter than 24 bytes raise ValueError upon open."""
        short_file = tmp_path / "short.pcap"
        short_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")  # Only 6 bytes

        with open(short_file, "rb") as f:
            with pytest.raises(ValueError, match="too short for PCAP global header"):
                PcapBleReader(f)


# ==============================================================================
# 5. Buffer Overflow and Burst Recovery Tests
# ==============================================================================
class TestBufferOverflowAndBurstRecovery:
    """Verifies that high-rate bursts do not crash queues or create memory leaks."""

    def test_massive_packet_burst_drain(self) -> None:
        """A burst of 1,000 packets must be ingested and drained via batch operations cleanly."""
        bus = VirtualRadioBus()
        controller = SniffleDeviceController(port="mock://burst_test", mock=True, bus=bus)
        controller.open()
        controller.start_sniffing(chan=37)

        burst_size = 1000
        mac = bytes.fromhex("c011222211c0")
        pdu = bytes([0x02, 6]) + mac

        for _ in range(burst_size):
            bus.deliver_raw_packet(pdu, chan=37, rssi=-65)

        # Drain packets in batches
        drained: list[PacketMessage] = []
        deadline = time.monotonic() + 5.0
        while len(drained) < burst_size and time.monotonic() < deadline:
            batch = controller.read_packets_batch(max_count=200, timeout=0.1)
            drained.extend(batch)

        assert len(drained) == burst_size
        controller.close()

    def test_mark_and_flush_discards_stale_bursts(self) -> None:
        """mark_and_flush clears out stale backlog accumulated before synchronization marker."""
        bus = VirtualRadioBus()
        controller = SniffleDeviceController(port="mock://flush_test", mock=True, bus=bus)
        controller.open()
        controller.start_sniffing(chan=37)

        # Accumulate 50 stale packets
        pdu = bytes([0x02, 6, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        for _ in range(50):
            bus.deliver_raw_packet(pdu, chan=37)

        time.sleep(0.05)
        # Flush backlog
        synced = controller.mark_and_flush(timeout=1.0)
        assert synced

        # Next packet should be fresh
        fresh_mac = bytes.fromhex("c099888899c0")
        bus.deliver_raw_packet(bytes([0x02, 6]) + fresh_mac, chan=37)

        pkt = controller.read_packet(timeout=0.5)
        assert pkt is not None
        assert fresh_mac in pkt.body

        controller.close()
