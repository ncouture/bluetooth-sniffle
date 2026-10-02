"""Unit tests for Structured Session Telemetry (JSON/CSV exporters)."""

import csv
import json
import threading
from pathlib import Path

from bluetooth_sniffle.sniff.dissector import DissectedBleFrame
from bluetooth_sniffle.sniff.telemetry import (
    StimulusResponseEvent,
    TelemetrySession,
)


class TestTelemetrySessionAggregation:
    """Tests device tracking, packet counters, and signal metric aggregation."""

    def test_session_packet_recording_and_counters(self):
        session = TelemetrySession(session_id="test_sess_01", base_epoch=1700000000.0)

        f1 = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=0,
            rx_add=0,
            length=10,
            adv_a="11:22:33:44:55:66",
            channel=37,
            rssi=-60,
            timestamp_usec=100_000,
        )
        f2 = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=0,
            rx_add=0,
            length=10,
            adv_a="11:22:33:44:55:66",
            channel=38,
            rssi=-65,
            timestamp_usec=200_000,
        )
        f3 = DissectedBleFrame(
            pdu_type="ADV_NONCONN_IND",
            pdu_type_id=0x02,
            tx_add=1,
            rx_add=0,
            length=10,
            adv_a="AA:BB:CC:DD:EE:FF",
            channel=39,
            rssi=-70,
            timestamp_usec=300_000,
        )

        session.record_packet(f1)
        session.record_packet(f2)
        session.record_packet(f3)

        assert session.total_packets == 3
        assert session.channel_packet_counts[37] == 1
        assert session.channel_packet_counts[38] == 1
        assert session.channel_packet_counts[39] == 1
        assert len(session.devices) == 2
        assert session.start_timestamp_usec == 100_000
        assert session.end_timestamp_usec == 300_000

    def test_device_aggregation_multi_packet(self):
        session = TelemetrySession(base_epoch=1700000000.0)
        mac = "AA:BB:CC:DD:EE:01"

        rssis = [-70, -60, -50, -65, -55]
        for i, r in enumerate(rssis):
            f = DissectedBleFrame(
                pdu_type="ADV_IND",
                pdu_type_id=0x00,
                tx_add=1,
                rx_add=0,
                length=10,
                adv_a=mac,
                adv_a_type="Random Static",
                channel=37,
                rssi=r,
                timestamp_usec=1000 * (i + 1),
            )
            session.record_packet(f)

        dev = session.devices[mac]
        assert dev.packet_count == 5
        assert dev.rssi_min == -70
        assert dev.rssi_max == -50
        assert dev.rssi_avg == -60.0
        assert dev.address_type == "Random Static"
        assert dev.first_seen_usec == 1000
        assert dev.last_seen_usec == 5000

    def test_device_name_and_uuid_accumulation(self):
        session = TelemetrySession()
        mac = "AA:BB:CC:DD:EE:FF"

        # Frame 1: ADV_IND with no name, but with 16-bit UUID
        f1 = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=0,
            rx_add=0,
            length=10,
            adv_a=mac,
            service_uuids_16=[0xFEAA],
        )
        # Frame 2: SCAN_RSP with Complete Local Name
        f2 = DissectedBleFrame(
            pdu_type="SCAN_RSP",
            pdu_type_id=0x04,
            tx_add=0,
            rx_add=0,
            length=20,
            adv_a=mac,
            device_name="SniffleSensor",
        )

        session.record_packet(f1)
        session.record_packet(f2)

        dev = session.devices[mac]
        assert "SniffleSensor" in dev.observed_names
        assert "0xFEAA" in dev.service_uuids

    def test_scan_req_tracks_both_parties(self):
        session = TelemetrySession()
        scan_a = "40:AA:BB:CC:DD:40"
        adv_a = "C0:11:22:22:11:C0"

        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a=scan_a,
            scan_a_type="RPA",
            adv_a=adv_a,
            adv_a_type="Random Static",
            channel=37,
            rssi=-62,
            timestamp_usec=1_000_000,
        )

        session.record_packet(frame)
        assert scan_a in session.devices
        assert adv_a in session.devices
        assert session.devices[scan_a].address_type == "RPA"
        assert session.devices[adv_a].address_type == "Random Static"

    def test_stimulus_response_event_recording(self):
        session = TelemetrySession(base_epoch=1700000000.0)
        evt = StimulusResponseEvent(
            burst_id=1,
            stimulus_mac="C0:11:22:22:11:C0",
            stimulus_type="iBeacon",
            response_pdu_type="SCAN_REQ",
            responder_mac="40:AA:BB:CC:DD:40",
            responder_mac_type="RPA",
            delta_ms=250.0,
            chan=37,
            rssi=-62,
            timestamp_usec=1_250_000,
        )
        session.record_event(evt)
        assert len(session.stimulus_response_events) == 1

        summary = session.get_summary()
        assert len(summary["stimulus_response_events"]) == 1
        assert summary["stimulus_response_events"][0]["responder_mac"] == "40:AA:BB:CC:DD:40"


class TestTelemetryExporters:
    """Tests JSON and CSV file export, atomic writing, and schema correctness."""

    def test_json_export_schema_compliance(self, tmp_path: Path):
        session = TelemetrySession(session_id="test_json_sess", base_epoch=1700000000.0)
        frame = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=1,
            rx_add=0,
            length=15,
            adv_a="11:22:33:44:55:66",
            adv_a_type="Random Static",
            device_name="TestDevice",
            channel=37,
            rssi=-65,
            timestamp_usec=100_000,
        )
        session.record_packet(frame)
        session.record_event({
            "burst_id": 1,
            "stimulus_mac": "C0:11:22:22:11:C0",
            "stimulus_type": "iBeacon",
            "response_pdu_type": "SCAN_REQ",
            "responder_mac": "40:AA:BB:CC:DD:40",
            "responder_mac_type": "RPA",
            "delta_ms": 150.0,
            "timestamp_usec": 250_000,
        })

        out_json = tmp_path / "session.json"
        session.export_json(out_json)

        assert out_json.exists()
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "devices" in data
        assert "stimulus_response_events" in data
        assert data["metadata"]["session_id"] == "test_json_sess"
        assert data["metadata"]["total_packets"] == 1
        assert len(data["devices"]) == 1
        assert data["devices"][0]["mac_address"] == "11:22:33:44:55:66"
        assert len(data["stimulus_response_events"]) == 1

    def test_csv_devices_export_structure(self, tmp_path: Path):
        session = TelemetrySession(base_epoch=1700000000.0)
        frame = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=1,
            rx_add=0,
            length=15,
            adv_a="11:22:33:44:55:66",
            adv_a_type="Random Static",
            device_name="MySensor",
            channel=37,
            rssi=-50,
            timestamp_usec=100_000,
        )
        session.record_packet(frame)

        out_csv = tmp_path / "devices.csv"
        session.export_devices_csv(out_csv)

        assert out_csv.exists()
        with open(out_csv, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        assert len(reader) == 1
        row = reader[0]
        assert row["mac_address"] == "11:22:33:44:55:66"
        assert row["address_type"] == "Random Static"
        assert row["packet_count"] == "1"
        assert row["rssi_avg"] == "-50.0"
        assert row["observed_names"] == "MySensor"
        assert row["channels"] == "37"

    def test_csv_events_export_structure(self, tmp_path: Path):
        session = TelemetrySession(base_epoch=1700000000.0)
        session.record_event({
            "burst_id": 2,
            "stimulus_mac": "C0:11:22:22:11:C0",
            "stimulus_type": "AltBeacon",
            "response_pdu_type": "SCAN_REQ",
            "responder_mac": "40:AA:BB:CC:DD:50",
            "responder_mac_type": "RPA",
            "delta_ms": 320.5,
            "chan": 38,
            "rssi": -68,
            "timestamp_usec": 500_000,
        })

        out_csv = tmp_path / "events.csv"
        session.export_events_csv(out_csv)

        assert out_csv.exists()
        with open(out_csv, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        assert len(reader) == 1
        row = reader[0]
        assert row["burst_id"] == "2"
        assert row["stimulus_mac"] == "C0:11:22:22:11:C0"
        assert row["stimulus_type"] == "AltBeacon"
        assert row["responder_mac"] == "40:AA:BB:CC:DD:50"
        assert row["delta_ms"] == "320.5"

    def test_empty_session_export(self, tmp_path: Path):
        session = TelemetrySession()
        json_file = tmp_path / "empty.json"
        csv_file = tmp_path / "empty.csv"

        session.export_json(json_file)
        session.export_csv(csv_file)

        assert json_file.exists()
        with open(json_file, "r", encoding="utf-8") as f:
            j = json.load(f)
        assert j["metadata"]["total_packets"] == 0
        assert j["devices"] == []

        assert csv_file.exists()
        with open(csv_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        # Exactly 1 header line and 0 data rows
        assert len(lines) == 1

    def test_telemetry_thread_safety(self):
        session = TelemetrySession()

        def worker(thread_id: int):
            for i in range(50):
                f = DissectedBleFrame(
                    pdu_type="ADV_IND",
                    pdu_type_id=0x00,
                    tx_add=0,
                    rx_add=0,
                    length=10,
                    adv_a=f"11:22:33:44:55:{thread_id:02X}",
                    channel=37,
                    rssi=-60,
                    timestamp_usec=i * 1000,
                )
                session.record_packet(f)
                session.record_event({
                    "burst_id": thread_id,
                    "stimulus_mac": "C0:11:22:22:11:C0",
                    "responder_mac": f"40:AA:BB:CC:DD:{thread_id:02X}",
                })

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert session.total_packets == 500
        assert len(session.devices) == 10
        assert len(session.stimulus_response_events) == 500

    def test_connect_ind_tracks_init_a(self):
        session = TelemetrySession()
        frame = DissectedBleFrame(
            pdu_type="CONNECT_IND",
            pdu_type_id=0x05,
            tx_add=1,
            rx_add=0,
            length=34,
            init_a="55:66:77:88:99:AA",
            init_a_type="Random Static",
            adv_a="11:22:33:44:55:66",
            adv_a_type="Public",
            channel=37,
            rssi=-54,
            timestamp_usec=150_000,
        )
        session.record_packet(frame)
        assert "55:66:77:88:99:AA" in session.devices
        assert "11:22:33:44:55:66" in session.devices
        init_dev = session.devices["55:66:77:88:99:AA"]
        assert init_dev.address_type == "Random Static"
        assert init_dev.packet_count == 1
        assert init_dev.rssi_min == -54

    def test_export_csv_routing(self, tmp_path: Path):
        session = TelemetrySession()
        session.record_event({
            "burst_id": 1,
            "stimulus_mac": "C0:11:22:22:11:C0",
            "responder_mac": "40:AA:BB:CC:DD:40",
            "delta_ms": 12.3,
        })
        events_csv = tmp_path / "table_events.csv"
        session.export_csv(events_csv, table_type="events")
        assert events_csv.exists()
        with open(events_csv, "r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["responder_mac"] == "40:AA:BB:CC:DD:40"
