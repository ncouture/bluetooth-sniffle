"""Adversarial stress and empirical challenge suite for Milestone 3 PCAP and Telemetry.

Mission coverage:
  1. Empirically verify PCAP DLT 256 compliance:
     - Generate PCAP files with diverse BLE packets (adv packets, scan requests,
       connect requests, data packets, crc errors).
     - Verify with /usr/bin/tshark (-r <pcap> -V) to confirm zero dissector errors.
  2. Stress test multithreaded concurrent writes to PcapBleWriter (20 threads concurrent).
  3. Stress test microsecond rollover across multi-hour timestamp intervals:
     - Boundary at 1000 seconds (10^9 usec) causing 56-year timestamp jump to 1970.
     - 32-bit hardware counter rollover (2^32 usec ≈ 4294.96s) across multi-hour intervals.
  4. Stress test TelemetrySession JSON and CSV export under high concurrency and disk races.
  5. Stress test TelemetrySession statistics and ISO timestamps across multi-hour rollovers.
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from bluetooth_sniffle.protocol.beacons import (
    build_altbeacon,
    build_eddystone_tlm,
    build_eddystone_uid,
    build_eddystone_url,
    build_gaen,
    build_ibeacon,
)
from bluetooth_sniffle.protocol.probing import build_scan_req, build_scan_rsp
from bluetooth_sniffle.sniff.dissector import DissectedBleFrame
from bluetooth_sniffle.sniff.pcap import (
    PcapBleReader,
    PcapBleWriter,
)
from bluetooth_sniffle.sniff.telemetry import (
    TelemetrySession,
    _ts_to_iso,
)

TSHARK_BIN = shutil.which("tshark") or "/usr/bin/tshark"


def _make_adv_pdu(pdu_type: int, adv_addr: bytes, payload: bytes) -> bytes:
    hdr = pdu_type & 0x0F
    length = len(adv_addr) + len(payload)
    return bytes([hdr, length]) + adv_addr + payload


class TestPcapDlt256TsharkCompliance:
    """Empirical DLT 256 verification using /usr/bin/tshark dissector."""

    @pytest.mark.skipif(not Path(TSHARK_BIN).exists(), reason="tshark not available")
    def test_tshark_all_packet_types_zero_malformed(self, tmp_path: Path) -> None:
        """Wireshark/tshark dissects 11 distinct BLE packet types with zero malformed frame errors."""
        pcap_path = tmp_path / "all_packet_types.pcap"
        adv_a = bytes.fromhex("112233445566")
        scan_a = bytes.fromhex("AABBCCDDEEFF")

        with PcapBleWriter(output=pcap_path, base_epoch=1700000000.0) as writer:
            # 1. Apple iBeacon in ADV_NONCONN_IND (pdu_type 2)
            ib = build_ibeacon(uuid.UUID("e2c56db5-dffb-48d2-b060-d0f5a71096e0"), 1, 2, -59)
            writer.write_packet(ts_usec=100_000, chan=37, packet=_make_adv_pdu(2, adv_a, ib))

            # 2. AltBeacon in ADV_NONCONN_IND
            ab = build_altbeacon(0x0118, bytes(20), -65)
            writer.write_packet(ts_usec=200_000, chan=38, packet=_make_adv_pdu(2, adv_a, ab))

            # 3. Google Eddystone-UID
            ed_uid = build_eddystone_uid(bytes(10), bytes(6), -20)
            writer.write_packet(ts_usec=300_000, chan=39, packet=_make_adv_pdu(2, adv_a, ed_uid))

            # 4. Google Eddystone-URL
            ed_url = build_eddystone_url("https://example.com", -20)
            writer.write_packet(ts_usec=400_000, chan=37, packet=_make_adv_pdu(2, adv_a, ed_url))

            # 5. Google Eddystone-TLM
            ed_tlm = build_eddystone_tlm(3000, 22.5, 12345, 67890)
            writer.write_packet(ts_usec=500_000, chan=38, packet=_make_adv_pdu(2, adv_a, ed_tlm))

            # 6. GAEN (Exposure Notification)
            gaen = build_gaen(bytes(16), bytes(4))
            writer.write_packet(ts_usec=600_000, chan=39, packet=_make_adv_pdu(2, adv_a, gaen))

            # 7. SCAN_REQ
            s_req = build_scan_req(scan_a, adv_a)
            writer.write_packet(ts_usec=700_000, chan=37, packet=s_req)

            # 8. SCAN_RSP
            s_rsp = build_scan_rsp(adv_a, local_name="SniffleEmpirical")
            writer.write_packet(ts_usec=800_000, chan=38, packet=s_rsp)

            # 9. CONNECT_IND (34-byte payload)
            conn_ind = bytes([0x05, 34]) + scan_a + adv_a + bytes(22)
            writer.write_packet(ts_usec=900_000, chan=39, packet=conn_ind)

            # 10. LE Data Packet (Data channel 1, Central->Peripheral)
            data_pdu = bytes([0x02, 4, 0x00, 0x00, 0x04, 0x00])
            writer.write_packet(
                ts_usec=950_000,
                chan=1,
                aa=0x12345678,
                packet=data_pdu,
                pdu_type=2,
            )

            # 11. CRC error packet
            writer.write_packet(ts_usec=980_000, chan=37, packet=s_req, crc_err=True)

        # Run tshark dissector in verbose mode
        proc = subprocess.run(
            [TSHARK_BIN, "-r", str(pcap_path), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert proc.returncode == 0, f"tshark failed with stderr: {proc.stderr}"
        assert "[Malformed Packet" not in proc.stdout
        assert "Bluetooth Low Energy Link Layer" in proc.stdout
        # Assert each of the 11 frames was dissected
        for frame_num in range(1, 12):
            assert f"Frame {frame_num}:" in proc.stdout

    @pytest.mark.skipif(not Path(TSHARK_BIN).exists(), reason="tshark not available")
    def test_tshark_crc_error_and_valid_crc_distinction(self, tmp_path: Path) -> None:
        """tshark explicitly tags Frame 2 with [Incorrect CRC] and Frame 1 with no warning."""
        pcap_path = tmp_path / "crc_check.pcap"
        pdu = bytes([0x00, 9, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x02, 0x01, 0x06])

        with PcapBleWriter(output=pcap_path, base_epoch=1700000000.0) as writer:
            # Frame 1: Valid CRC
            writer.write_packet(ts_usec=1000, chan=37, packet=pdu, crc_err=False)
            # Frame 2: Invalid CRC
            writer.write_packet(ts_usec=2000, chan=37, packet=pdu, crc_err=True)

        proc = subprocess.run(
            [TSHARK_BIN, "-r", str(pcap_path), "-O", "btle"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert proc.returncode == 0
        assert "Incorrect CRC" in proc.stdout
        # Frame 1 should not have Incorrect CRC
        parts = proc.stdout.split("Frame 2:")
        assert "Incorrect CRC" not in parts[0]
        assert "Incorrect CRC" in parts[1]


class TestPcapConcurrencyStress:
    """Stress test multithreaded concurrent writes to PcapBleWriter."""

    def test_twenty_threads_concurrent_writing(self, tmp_path: Path) -> None:
        """20 threads writing 200 packets each (4,000 total) to a single PcapBleWriter."""
        pcap_path = tmp_path / "concurrent_20_threads.pcap"
        writer = PcapBleWriter(output=pcap_path, base_epoch=1700000000.0)

        num_threads = 20
        pkts_per_thread = 200
        errors: list[Exception] = []

        def worker(thread_idx: int) -> None:
            for i in range(pkts_per_thread):
                try:
                    ts = 1000 * (thread_idx * pkts_per_thread + i)
                    mac = bytes([0x11, 0x22, 0x33, 0x44, thread_idx, i % 256])
                    pdu = bytes([0x02, 9]) + mac + bytes([0x02, 0x01, 0x06])
                    writer.write_packet(
                        ts_usec=ts,
                        chan=37 + (i % 3),
                        rssi=-50 - (i % 30),
                        packet=pdu,
                        crc_err=(i % 25 == 0),
                    )
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(t,)) for t in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        writer.close()

        assert len(errors) == 0, f"Thread write errors: {errors}"
        assert writer.packet_count == num_threads * pkts_per_thread

        # Verify with PcapBleReader
        reader = PcapBleReader(pcap_path)
        read_pkts = list(reader)
        reader.close()
        assert len(read_pkts) == 4000

        # Verify with tshark
        if Path(TSHARK_BIN).exists():
            proc = subprocess.run(
                [TSHARK_BIN, "-r", str(pcap_path), "-c", "50", "-V"],
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0
            assert "[Malformed Packet" not in proc.stdout


class TestPcapMicrosecondRollover:
    """Stress test microsecond rollover across multi-hour timestamp intervals."""

    def test_sixteen_minute_threshold_discontinuity(self, tmp_path: Path) -> None:
        """CHALLENGE: Relative microsecond timestamps > 1,000s (10^9 usec) must NOT drop to 1970.

        Bug: pcap.py line 238 checks `if unwrapped_usec < 1_000_000_000:` to decide whether
        to add base_epoch. 10^9 microseconds is only 1,000 seconds (16.6 minutes).
        When capture runs past 1,000 seconds, timestamps drop 56 years into the past (1970).
        """
        pcap_path = tmp_path / "threshold_challenge.pcap"
        base_epoch = 1775000000.0  # Modern epoch in 2026

        with PcapBleWriter(output=pcap_path, base_epoch=base_epoch) as writer:
            # Packet 0 at 900s (15 min) -> < 10^9 usec
            writer.write_packet(ts_usec=900_000_000, chan=37, packet=b"\x02\x01\x06")
            # Packet 1 at 1200s (20 min) -> > 10^9 usec
            writer.write_packet(ts_usec=1_200_000_000, chan=37, packet=b"\x02\x01\x06")

        reader = PcapBleReader(pcap_path)
        pkts = list(reader)
        reader.close()

        assert len(pkts) == 2
        # Packet 0 should be at base_epoch + 900
        assert pkts[0].ts_epoch == pytest.approx(base_epoch + 900.0, abs=1.0)

        # Packet 1 MUST be at base_epoch + 1200 (around 2026), NOT 1200.0 (1970-01-01)
        assert pkts[1].ts_epoch > 1_000_000_000.0, (
            f"PCAP timestamp dropped to 1970! ts_epoch={pkts[1].ts_epoch}, expected ~{base_epoch + 1200.0}"
        )
        assert pkts[1].ts_epoch == pytest.approx(base_epoch + 1200.0, abs=1.0)

    test_pcap_timestamp_long_capture_drift = test_sixteen_minute_threshold_discontinuity

    def test_multi_hour_rollover_across_32bit_boundary(self, tmp_path: Path) -> None:
        """CHALLENGE: Multi-hour capture spanning 32-bit hardware rollover must maintain monotonic UTC timestamps.

        Hardware counter wraps around at 2^32 usec ≈ 4294.96 seconds (71.58 minutes).
        In a 3-hour capture (10,800s), timestamps must monotonically advance across all hours.
        """
        pcap_path = tmp_path / "multi_hour_challenge.pcap"
        base_epoch = 1775000000.0

        t_elapsed_seconds = [
            0,      # 0m
            600,    # 10m
            1200,   # 20m
            2400,   # 40m
            3600,   # 60m (1 hr)
            4200,   # 70m
            4800,   # 80m (after 1st 32-bit rollover at 4294.96s)
            6000,   # 100m
            7200,   # 120m (2 hr)
            9000,   # 150m (after 2nd 32-bit rollover at 8589.93s)
            10800,  # 180m (3 hr)
        ]

        with PcapBleWriter(output=pcap_path, base_epoch=base_epoch) as writer:
            for t_sec in t_elapsed_seconds:
                raw_hw_ts = (int(t_sec * 1_000_000)) % (1 << 32)
                writer.write_packet(ts_usec=raw_hw_ts, chan=37, packet=b"\x02\x01\x06")

        reader = PcapBleReader(pcap_path)
        pkts = list(reader)
        reader.close()

        assert len(pkts) == len(t_elapsed_seconds)
        for idx, (t_sec, pkt) in enumerate(zip(t_elapsed_seconds, pkts)):
            expected_epoch = base_epoch + t_sec
            assert pkt.ts_epoch > 1_000_000_000.0, (
                f"Pkt {idx} (t={t_sec}s) timestamp corrupted to 1970: ts_epoch={pkt.ts_epoch}"
            )
            assert pkt.ts_epoch == pytest.approx(expected_epoch, abs=2.0), (
                f"Pkt {idx} (t={t_sec}s) ts_epoch={pkt.ts_epoch} != expected={expected_epoch}"
            )


class TestTelemetryHighConcurrencyAndDiskRace:
    """Stress test TelemetrySession export under high concurrency and disk race conditions."""

    def test_concurrent_recording_and_atomic_export_races(self, tmp_path: Path) -> None:
        """10 producer threads, 5 JSON exporters, 5 CSV exporters, and 1 verifier thread concurrently."""
        json_path = tmp_path / "live_session.json"
        csv_devices_path = tmp_path / "live_devices.csv"
        csv_events_path = tmp_path / "live_events.csv"

        session = TelemetrySession(session_id="stress_session_01", base_epoch=1700000000.0)
        stop_event = threading.Event()
        errors: list[tuple[str, Exception]] = []

        def producer_worker(tid: int) -> None:
            seq = 0
            while not stop_event.is_set():
                seq += 1
                f = DissectedBleFrame(
                    pdu_type="ADV_IND",
                    pdu_type_id=0,
                    tx_add=0,
                    rx_add=0,
                    length=10,
                    adv_a=f"11:22:33:44:{(tid % 16):02X}:{(seq % 128):02X}",
                    channel=37 + (seq % 3),
                    rssi=-55 - (seq % 25),
                    timestamp_usec=seq * 1000,
                )
                session.record_packet(f)
                if seq % 10 == 0:
                    session.record_event({
                        "burst_id": seq,
                        "stimulus_mac": "C0:11:22:22:11:C0",
                        "stimulus_type": "iBeacon",
                        "response_pdu_type": "SCAN_REQ",
                        "responder_mac": f"40:AA:BB:CC:DD:{(tid % 16):02X}",
                        "delta_ms": 15.0 + (seq % 50),
                    })
                time.sleep(0.0001)

        def json_export_worker() -> None:
            while not stop_event.is_set():
                try:
                    session.export_json(json_path)
                except Exception as exc:
                    errors.append(("json_export", exc))
                time.sleep(0.001)

        def csv_devices_export_worker() -> None:
            while not stop_event.is_set():
                try:
                    session.export_devices_csv(csv_devices_path)
                except Exception as exc:
                    errors.append(("csv_devices_export", exc))
                time.sleep(0.001)

        def csv_events_export_worker() -> None:
            while not stop_event.is_set():
                try:
                    session.export_events_csv(csv_events_path)
                except Exception as exc:
                    errors.append(("csv_events_export", exc))
                time.sleep(0.001)

        def reader_verifier_worker() -> None:
            while not stop_event.is_set():
                if json_path.exists():
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            assert "metadata" in data
                            assert "devices" in data
                    except Exception as exc:
                        errors.append(("json_read_corruption", exc))
                if csv_devices_path.exists():
                    try:
                        with open(csv_devices_path, "r", encoding="utf-8") as f:
                            reader = csv.reader(f)
                            hdr = next(reader, None)
                            if hdr:
                                assert hdr[0] == "mac_address"
                    except Exception as exc:
                        errors.append(("csv_devices_read_corruption", exc))
                if csv_events_path.exists():
                    try:
                        with open(csv_events_path, "r", encoding="utf-8") as f:
                            reader = csv.reader(f)
                            hdr = next(reader, None)
                            if hdr:
                                assert hdr[0] == "burst_id"
                    except Exception as exc:
                        errors.append(("csv_events_read_corruption", exc))
                time.sleep(0.0005)

        threads: list[threading.Thread] = []
        for i in range(10):
            threads.append(threading.Thread(target=producer_worker, args=(i,)))
        for _ in range(3):
            threads.append(threading.Thread(target=json_export_worker))
        for _ in range(3):
            threads.append(threading.Thread(target=csv_devices_export_worker))
        for _ in range(3):
            threads.append(threading.Thread(target=csv_events_export_worker))
        threads.append(threading.Thread(target=reader_verifier_worker))

        for t in threads:
            t.start()

        time.sleep(1.5)
        stop_event.set()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Encountered concurrency/race errors: {errors}"
        assert session.total_packets > 0
        assert len(session.devices) > 0
        assert json_path.exists()
        assert csv_devices_path.exists()
        assert csv_events_path.exists()


class TestTelemetryMultiHourRollover:
    """Stress test TelemetrySession handling of multi-hour intervals and 32-bit rollover."""

    def test_telemetry_iso_timestamp_1000s_threshold(self) -> None:
        """CHALLENGE: _ts_to_iso must not convert timestamps >= 1,000s to 1970.

        Bug: telemetry.py line 25 checks `if usec < 1_000_000_000:` assuming 10^9 is seconds.
        In microseconds, 10^9 is 1,000s (16.6 min).
        """
        base_epoch = 1775000000.0  # 2026-03-31T23:33:20+00:00

        # At 900s (15 min):
        iso_900 = _ts_to_iso(900_000_000, base_epoch)
        assert iso_900.startswith("2026-")

        # At 1200s (20 min):
        iso_1200 = _ts_to_iso(1_200_000_000, base_epoch)
        assert iso_1200.startswith("2026-"), (
            f"_ts_to_iso converted 20-minute timestamp to 1970! Produced: {iso_1200}"
        )

    def test_telemetry_session_statistics_across_32bit_rollover(self) -> None:
        """CHALLENGE: TelemetrySession must maintain valid session statistics across 32-bit rollover.

        Hardware counter wraps at 2^32 usec ≈ 4294.96s (71.58 minutes).
        Packets at 10m (600s), 70m (4200s), and 80m (4800s, post-rollover raw ts = 505_032_704):
        - Device first_seen must stay 600_000_000 (not clobbered by 505_032_704).
        - Device last_seen must advance to post-rollover timestamp (~4800s).
        - Session start_timestamp_usec must stay 600_000_000.
        - Session duration must be 4200.0s (4800 - 600), not underreported or corrupted.
        """
        session = TelemetrySession(base_epoch=1775000000.0)

        # Packet 1 at 10 minutes (600s)
        f1 = DissectedBleFrame(
            pdu_type="ADV_IND", pdu_type_id=0, tx_add=0, rx_add=0, length=10,
            adv_a="11:22:33:44:55:66", channel=37, rssi=-60, timestamp_usec=600_000_000,
        )
        session.record_packet(f1)

        # Packet 2 at 70 minutes (4200s)
        f2 = DissectedBleFrame(
            pdu_type="ADV_IND", pdu_type_id=0, tx_add=0, rx_add=0, length=10,
            adv_a="11:22:33:44:55:66", channel=37, rssi=-60, timestamp_usec=4_200_000_000,
        )
        session.record_packet(f2)

        # Packet 3 at 80 minutes (4800s): wraps past 2^32 (4_294_967_296) -> 505_032_704 usec
        raw_hw_ts_80m = 4_800_000_000 % (1 << 32)  # 505_032_704
        f3 = DissectedBleFrame(
            pdu_type="ADV_IND", pdu_type_id=0, tx_add=0, rx_add=0, length=10,
            adv_a="11:22:33:44:55:66", channel=37, rssi=-60, timestamp_usec=raw_hw_ts_80m,
        )
        session.record_packet(f3)

        dev = session.devices["11:22:33:44:55:66"]
        summary = session.get_summary()

        # Check start timestamp wasn't clobbered by post-rollover packet
        assert session.start_timestamp_usec == 600_000_000, (
            f"session.start_timestamp_usec clobbered by post-rollover ts! Got: {session.start_timestamp_usec}"
        )

        # Check device first seen wasn't clobbered
        assert dev.first_seen_usec == 600_000_000, (
            f"dev.first_seen_usec clobbered by post-rollover ts! Got: {dev.first_seen_usec}"
        )

        # Check device last seen is after first seen
        assert summary["devices"][0]["first_seen_iso"] < summary["devices"][0]["last_seen_iso"], (
            f"Device last_seen_iso ({summary['devices'][0]['last_seen_iso']}) is before "
            f"first_seen_iso ({summary['devices'][0]['first_seen_iso']})!"
        )

        # Check session duration
        assert summary["metadata"]["duration_sec"] == pytest.approx(4200.0, abs=2.0), (
            f"Session duration corrupted! Got {summary['metadata']['duration_sec']}s, expected ~4200.0s"
        )

    test_telemetry_rollover_first_seen_corruption = test_telemetry_session_statistics_across_32bit_rollover
