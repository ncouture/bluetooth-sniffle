"""Tier 3: Cross-Feature Combinations and Interaction Tests (Milestone 5).

Verifies multi-module interactions, pairwise feature combinations, cross-topological
capture, simultaneous dual-channel sniffing, and artifact cross-validation
per TEST_INFRA.md and PoPETs 2025-0103. (25 tests total).
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path

import pytest

from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.protocol.beacons import (
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
)
from bluetooth_sniffle.protocol.probing import (
    build_scan_req,
    build_scan_rsp,
)
from bluetooth_sniffle.sniff.correlation import StimulusResponseCorrelator
from bluetooth_sniffle.sniff.dissector import (
    BleAddressType,
    dissect_advertising_pdu,
)
from bluetooth_sniffle.sniff.pcap import PcapBleReader, PcapBleWriter
from bluetooth_sniffle.sniff.telemetry import TelemetrySession
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator

# ==============================================================================
# Group 1: Palindromic MACs with all 6 Beacon Types (Tests 1-6)
# ==============================================================================


class TestPalindromicMacBeaconCombinations:
    """Combines endianness-invariant palindromic MACs with all 6 beacon formats."""

    def test_comb_palindromic_static_with_ibeacon_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        pal_mac = generate_palindromic_mac("static", seed=b"static-ibeacon")
        assert is_palindromic_mac(pal_mac)
        topo.set_stimulus_mac(pal_mac, is_random=True)

        payload = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=101,
            minor=202,
            tx_power=-59,
        )
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "iBeacon"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert is_palindromic_mac(frame.adv_a)
        assert frame.adv_a_type == BleAddressType.RANDOM_STATIC.value
        topo.stop()

    def test_comb_palindromic_static_with_altbeacon_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        pal_mac = generate_palindromic_mac("static", seed=b"static-altbeacon")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        beacon_id = bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002")
        payload = build_altbeacon(mfg_id=0x0118, beacon_id=beacon_id, ref_rssi=-59)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "AltBeacon"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert is_palindromic_mac(frame.adv_a)
        topo.stop()

    def test_comb_palindromic_nrpa_with_eddystone_uid_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=38)
        topo.start()
        pal_mac = generate_palindromic_mac("nrpa", seed=b"nrpa-eddystone-uid")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        ns = bytes.fromhex("0102030405060708090a")
        inst = bytes.fromhex("112233445566")
        payload = build_eddystone_uid(namespace=ns, instance=inst, tx_power=-20)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "Eddystone-UID"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert frame.adv_a_type == BleAddressType.NRPA.value
        topo.stop()

    def test_comb_palindromic_nrpa_with_eddystone_url_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        pal_mac = generate_palindromic_mac("nrpa", seed=b"nrpa-eddystone-url")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        payload = build_eddystone_url("https://petsymposium.org/", tx_power=-18)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "Eddystone-URL"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert is_palindromic_mac(frame.adv_a)
        topo.stop()

    def test_comb_palindromic_rpa_with_eddystone_tlm_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=37)
        topo.start()
        pal_mac = generate_palindromic_mac("rpa", seed=b"rpa-eddystone-tlm")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        payload = build_eddystone_tlm(vbatt_mv=3300, temp_c=24.5, adv_cnt=50, sec_cnt=500)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "Eddystone-TLM"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert frame.adv_a_type == BleAddressType.RPA.value
        topo.stop()

    def test_comb_palindromic_public_with_gaen_roundtrip(self) -> None:
        topo = TopologyAOrchestrator.create_mock(observer_channel=39)
        topo.start()
        pal_mac = generate_palindromic_mac("public", seed=b"public-gaen")
        topo.set_stimulus_mac(pal_mac, is_random=False)

        rpi = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        aem = bytes.fromhex("11223344")
        payload = build_gaen(rpi=rpi, aem=aem)
        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        pkt = topo.read_packet(timeout=0.2)
        assert pkt is not None
        frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
        assert frame.beacon_type == "GAEN"
        assert frame.adv_a == mac_to_str(pal_mac)
        assert frame.adv_a_type == BleAddressType.PUBLIC.value
        topo.stop()


# ==============================================================================
# Group 2: Active Probing under Burst Cycles & Correlation (Tests 7-9)
# ==============================================================================


class TestActiveProbingAndBurstCorrelationCombinations:
    """Combines active probing elicitation with burst cycles and correlation."""

    def test_comb_active_probing_under_burst_cycles(self) -> None:
        shared_bus = VirtualRadioBus()
        topo = TopologyAOrchestrator.create_mock(bus=shared_bus, observer_channel=37)
        topo.start()

        correlator = StimulusResponseCorrelator(max_latency_usec=2_000_000)
        stim_mac = generate_palindromic_mac("static", seed=b"burst-probe-mac")
        topo.set_stimulus_mac(stim_mac, is_random=True)

        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
        correlator.register_stimulus(
            adv_a=stim_mac,
            beacon_type="iBeacon",
            burst_id=42,
            start_time_usec=1_000_000,
            duration_usec=500_000,
            channel=37,
        )

        topo.inject_beacon(adv_data=payload, interval_ms=50, mode=3)  # Scannable
        time.sleep(0.02)

        # Simulate mobile device responding with SCAN_REQ to this burst
        responder_mac = bytes.fromhex("445566778899")
        scan_req = build_scan_req(scan_a=responder_mac, adv_a=stim_mac)
        shared_bus.deliver_raw_packet(pdu=scan_req, chan=37, rssi=-65)

        # Observer captures the SCAN_REQ
        captured = topo.get_captured_packets(timeout=0.2)
        assert len(captured) >= 1

        matches = []
        for pkt in captured:
            frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
            match = correlator.process_frame(frame)
            if match:
                matches.append(match)

        assert len(matches) == 1
        m = matches[0]
        assert m.stimulus_id.startswith("stim_42")
        assert m.responder_mac == "44:55:66:77:88:99"
        topo.stop()

    def test_comb_active_probing_multiple_responders(self) -> None:
        correlator = StimulusResponseCorrelator(max_latency_usec=2_000_000)
        stim_mac = bytes.fromhex("c011222211c0")
        correlator.register_stimulus(adv_a=stim_mac, beacon_type="iBeacon", burst_id=1, start_time_usec=1000, duration_usec=0)

        responders = [bytes.fromhex(f"1122334455{i:02x}") for i in range(1, 6)]
        matches = []
        for r_mac in responders:
            req = build_scan_req(scan_a=r_mac, adv_a=stim_mac)
            frame = dissect_advertising_pdu(req, chan=37, rssi=-60, ts_usec=1050)
            m = correlator.process_frame(frame)
            if m:
                matches.append(m)

        assert len(matches) == 5
        summary = correlator.get_summary()
        assert summary.unique_responders_count == 5
        assert summary.total_responses == 5

    def test_comb_active_elicitation_scan_rsp_in_pcap_and_telemetry(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "elicitation.pcap"
        session = TelemetrySession(topology="Topology A Active Scan")
        adv_a = bytes.fromhex("c033444433c0")
        scan_a = bytes.fromhex("412233445566")

        # Step 1: SCAN_REQ
        req_pdu = build_scan_req(scan_a=scan_a, adv_a=adv_a)
        frame_req = dissect_advertising_pdu(req_pdu, chan=37, rssi=-65, ts_usec=1000)

        # Step 2: SCAN_RSP eliciting Complete Local Name
        rsp_pdu = build_scan_rsp(adv_a=adv_a, local_name="Elicited-Device-7")
        frame_rsp = dissect_advertising_pdu(rsp_pdu, chan=37, rssi=-60, ts_usec=1150)

        with PcapBleWriter(pcap_path) as writer:
            writer.write_dissected_frame(frame_req)
            writer.write_dissected_frame(frame_rsp)

        session.record_packet(frame_req)
        session.record_packet(frame_rsp)

        # Verify PCAP
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 2
            assert pkts[0].body[0] & 0x0F == 3  # SCAN_REQ
            assert pkts[1].body[0] & 0x0F == 4  # SCAN_RSP

        # Verify Telemetry
        assert "C0:33:44:44:33:C0" in session.devices
        dev = session.devices["C0:33:44:44:33:C0"]
        assert "Elicited-Device-7" in dev.observed_names


# ==============================================================================
# Group 3: Simultaneous Dual-Channel Multi-Vendor Capture (Tests 10-12)
# ==============================================================================


class TestDualChannelMultiVendorCombinations:
    """Topology B dual-channel capture with simultaneous multi-vendor transmissions."""

    def test_comb_dual_channel_simultaneous_apple_google_beacons(self) -> None:
        shared_bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=shared_bus, chan1=37, chan2=38) as topo:
            time.sleep(0.05)

            # Apple iBeacon on Ch 37
            adv_a_apple = bytes.fromhex("c011222211c0")
            payload_apple = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
            pdu_apple = bytes([0x02, len(adv_a_apple) + len(payload_apple)]) + adv_a_apple + payload_apple

            # Google Eddystone on Ch 38
            adv_a_google = bytes.fromhex("c022333322c0")
            payload_google = build_eddystone_uid(namespace=bytes(10), instance=bytes(6), tx_power=-20)
            pdu_google = bytes([0x02, len(adv_a_google) + len(payload_google)]) + adv_a_google + payload_google

            # Simultaneous delivery across channels
            shared_bus.deliver_raw_packet(pdu=pdu_apple, chan=37, rssi=-60)
            shared_bus.deliver_raw_packet(pdu=pdu_google, chan=38, rssi=-65)

            merged = topo.get_merged_packets(max_count=10, timeout=0.5)
            assert len(merged) == 2
            assert {pkt.chan for pkt in merged} == {37, 38}

            types_seen = set()
            for pkt in merged:
                frame = dissect_advertising_pdu(pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts)
                types_seen.add(frame.beacon_type)

            assert types_seen == {"iBeacon", "Eddystone-UID"}

    def test_comb_dual_channel_simultaneous_altbeacon_gaen(self) -> None:
        shared_bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=shared_bus, chan1=37, chan2=39) as topo:
            time.sleep(0.05)

            # AltBeacon on Ch 37
            adv_a1 = bytes.fromhex("c011111111c0")
            p1 = build_altbeacon(mfg_id=0x0118, beacon_id=bytes(20), ref_rssi=-59)
            pdu1 = bytes([0x02, len(adv_a1) + len(p1)]) + adv_a1 + p1

            # GAEN on Ch 39
            adv_a2 = bytes.fromhex("c022222222c0")
            p2 = build_gaen(rpi=bytes(16), aem=bytes(4))
            pdu2 = bytes([0x02, len(adv_a2) + len(p2)]) + adv_a2 + p2

            shared_bus.deliver_raw_packet(pdu=pdu1, chan=37, rssi=-62)
            shared_bus.deliver_raw_packet(pdu=pdu2, chan=39, rssi=-68)

            merged = topo.get_merged_packets(max_count=10, timeout=0.5)
            assert len(merged) == 2
            assert {pkt.chan for pkt in merged} == {37, 39}

    def test_comb_stimulator_with_dual_channel_observer(self) -> None:
        shared_bus = VirtualRadioBus()
        # Stimulator device transmitting on bus
        topo_a = TopologyAOrchestrator.create_mock(bus=shared_bus, observer_channel=37)
        topo_b = TopologyBOrchestrator.create_mock(bus=shared_bus, chan1=37, chan2=38)

        topo_a.start()
        topo_b.start()
        time.sleep(0.05)

        # Inject beacon from stimulator (broadcasts across primary channels in mock bus)
        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
        topo_a.inject_beacon(adv_data=payload, interval_ms=50, mode=2)

        # Topology B must capture on both 37 and 38
        merged = topo_b.get_merged_packets(max_count=10, timeout=0.5)
        assert len(merged) >= 2
        assert {pkt.chan for pkt in merged} == {37, 38}

        topo_a.stop()
        topo_b.stop()


# ==============================================================================
# Group 4: PCAP and Telemetry Paired Cross-Validation (Tests 13-17)
# ==============================================================================


class TestPcapAndTelemetryPairedValidation:
    """Verifies fidelity across PCAP DLT 256, JSON session schema, and CSV tabular logs."""

    def test_comb_pcap_paired_with_telemetry_json(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "paired.pcap"
        json_file = tmp_path / "paired.json"

        session = TelemetrySession(topology="Topology A Stimulator")
        writer = PcapBleWriter(pcap_file)

        pal_mac = generate_palindromic_mac("static", seed=b"pcap-json-sync")
        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 10, 20, -59)
        pdu = bytes([0x02, len(pal_mac) + len(payload)]) + pal_mac + payload

        # Record 10 packets with incremental timestamps
        for i in range(10):
            ts = 1_000_000 + (i * 100_000)
            writer.write_packet(ts_usec=ts, aa=0x8E89BED6, chan=37, rssi=-60 + i, packet=pdu)
            frame = dissect_advertising_pdu(pdu, chan=37, rssi=-60 + i, ts_usec=ts)
            session.record_packet(frame)

        writer.close()
        session.export_json(json_file)

        # Cross-validate PCAP vs JSON
        with PcapBleReader(pcap_file) as reader:
            pcap_pkts = list(reader)

        json_data = json.loads(json_file.read_text(encoding="utf-8"))
        assert len(pcap_pkts) == 10
        assert json_data["metadata"]["total_packets"] == 10
        assert json_data["metadata"]["unique_devices_count"] == 1
        assert json_data["devices"][0]["mac_address"] == mac_to_str(pal_mac)

    def test_comb_pcap_paired_with_telemetry_csv(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "sync.pcap"
        csv_file = tmp_path / "sync.csv"

        session = TelemetrySession(topology="Topology A")
        writer = PcapBleWriter(pcap_file)

        mac1 = generate_palindromic_mac("static", seed=b"sync-mac-1")
        mac2 = generate_palindromic_mac("nrpa", seed=b"sync-mac-2")

        pdu1 = bytes([0x02, 6]) + mac1
        pdu2 = bytes([0x02, 6]) + mac2

        writer.write_packet(ts_usec=1000, aa=0x8E89BED6, chan=37, rssi=-55, packet=pdu1)
        writer.write_packet(ts_usec=2000, aa=0x8E89BED6, chan=38, rssi=-70, packet=pdu2)
        writer.close()

        session.record_packet(dissect_advertising_pdu(pdu1, chan=37, rssi=-55, ts_usec=1000))
        session.record_packet(dissect_advertising_pdu(pdu2, chan=38, rssi=-70, ts_usec=2000))
        session.export_csv(csv_file)

        # Read back CSV
        with open(csv_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        macs_in_csv = {r["mac_address"] for r in rows}
        assert macs_in_csv == {mac_to_str(mac1), mac_to_str(mac2)}

    def test_comb_palindromic_mac_traceability_across_artifacts(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "trace.pcap"
        json_file = tmp_path / "trace.json"
        csv_file = tmp_path / "trace.csv"

        pal_mac = generate_palindromic_mac("static", seed=b"traceability-seed")
        payload = build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)
        pdu = bytes([0x02, len(pal_mac) + len(payload)]) + pal_mac + payload

        # Pass through pipeline
        frame = dissect_advertising_pdu(pdu, chan=37, rssi=-60, ts_usec=5000)
        session = TelemetrySession(topology="Topology A")
        session.record_packet(frame)
        session.export_json(json_file)
        session.export_csv(csv_file)

        with PcapBleWriter(pcap_file) as writer:
            writer.write_dissected_frame(frame)

        # Trace across all three formats
        # 1. PCAP
        with PcapBleReader(pcap_file) as reader:
            pcap_pkts = list(reader)
            assert len(pcap_pkts) == 1
            assert pal_mac in pcap_pkts[0].body

        # 2. JSON
        j_data = json.loads(json_file.read_text(encoding="utf-8"))
        assert j_data["devices"][0]["mac_address"] == mac_to_str(pal_mac)

        # 3. CSV
        with open(csv_file, encoding="utf-8") as f:
            csv_text = f.read()
            assert mac_to_str(pal_mac) in csv_text

    def test_comb_correlator_with_telemetry_event_logging(self, tmp_path: Path) -> None:
        session = TelemetrySession(topology="Topology A")
        correlator = StimulusResponseCorrelator(max_latency_usec=5_000_000)

        stim_mac = bytes.fromhex("c011222211c0")
        correlator.register_stimulus(adv_a=stim_mac, beacon_type="AltBeacon", burst_id=99, start_time_usec=1000)

        responder_mac = bytes.fromhex("334455667788")
        scan_req = build_scan_req(scan_a=responder_mac, adv_a=stim_mac)
        frame = dissect_advertising_pdu(scan_req, chan=37, rssi=-62, ts_usec=1250)

        match = correlator.process_frame(frame)
        assert match is not None

        # Log event into telemetry
        session.record_event({
            "burst_id": match.stimulus_id,
            "stimulus_mac": match.stimulus_adv_a,
            "stimulus_type": "AltBeacon",
            "response_pdu_type": match.response_pdu_type,
            "responder_mac": match.responder_mac,
            "responder_mac_type": match.responder_type,
            "delta_ms": match.latency_ms,
            "chan": match.channel,
            "rssi": match.rssi,
            "timestamp_usec": match.response_timestamp_usec,
        })

        out_csv = tmp_path / "events.csv"
        session.export_events_csv(out_csv)
        content = out_csv.read_text(encoding="utf-8")
        assert "33:44:55:66:77:88" in content
        assert "AltBeacon" in content

    def test_comb_connect_ind_with_pcap_and_telemetry(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "conn.pcap"
        session = TelemetrySession(topology="Topology A Observer")

        init_a = bytes.fromhex("112233445566")
        adv_a = bytes.fromhex("665544332211")
        lldata = bytes([0xAA] * 22)  # 22 bytes LLData
        pdu = bytes([0x05, len(init_a) + len(adv_a) + len(lldata)]) + init_a + adv_a + lldata

        frame = dissect_advertising_pdu(pdu, chan=37, rssi=-58, ts_usec=500000)
        session.record_packet(frame)

        with PcapBleWriter(pcap_path) as writer:
            writer.write_dissected_frame(frame)

        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 1
            assert pkts[0].body[0] & 0x0F == 5  # CONNECT_IND

        # Telemetry should track both init_a and adv_a
        assert "11:22:33:44:55:66" in session.devices
        assert "66:55:44:33:22:11" in session.devices


# ==============================================================================
# Group 5: Complex Multi-Beacon Sequences & Aggregation (Tests 18-25)
# ==============================================================================


class TestComplexMultiBeaconSequences:
    """Multi-vendor burst rotations, symmetry preservation, and aggregation."""

    def test_comb_multi_vendor_burst_rotation_session(self) -> None:
        session = TelemetrySession(topology="Multi-Vendor Session")
        beacons = [
            ("iBeacon", build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)),
            ("AltBeacon", build_altbeacon(0x0118, bytes(20), -59)),
            ("Eddystone-UID", build_eddystone_uid(bytes(10), bytes(6), -20)),
            ("Eddystone-URL", build_eddystone_url("https://example.com/multi", -18)),
            ("Eddystone-TLM", build_eddystone_tlm(3300, 25.0, 100, 1000)),
            ("GAEN", build_gaen(bytes(16), bytes(4))),
        ]

        mac = bytes.fromhex("c011222211c0")
        for i, (btype, payload) in enumerate(beacons):
            pdu = bytes([0x02, len(mac) + len(payload)]) + mac + payload
            frame = dissect_advertising_pdu(pdu, chan=37, rssi=-60 - i, ts_usec=i * 10000)
            assert frame.beacon_type == btype
            session.record_packet(frame)

        assert "C0:11:22:22:11:C0" in session.devices
        dev = session.devices["C0:11:22:22:11:C0"]
        assert dev.packet_count == 6
        assert len(dev.beacon_types) == 6

    def test_comb_palindromic_mac_endianness_preservation_in_pcap(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "pal_endian.pcap"
        pal_mac = generate_palindromic_mac("static", seed=b"pal-endian-test")
        pdu = bytes([0x02, 6]) + pal_mac

        with PcapBleWriter(pcap_file) as writer:
            writer.write_packet(ts_usec=1000, aa=0x8E89BED6, chan=37, rssi=-60, packet=pdu)

        with PcapBleReader(pcap_file) as reader:
            pkts = list(reader)
            extracted_mac = pkts[0].body[2:8]
            assert extracted_mac == pal_mac
            # Forward equals reverse
            assert extracted_mac == extracted_mac[::-1]

    def test_comb_multi_beacon_rssi_aggregation(self) -> None:
        session = TelemetrySession(topology="RSSI Test")
        adv_a = bytes.fromhex("112233445566")
        pdu = bytes([0x00, 6]) + adv_a

        rssi_values = [-80, -60, -40]
        for r in rssi_values:
            session.record_packet(dissect_advertising_pdu(pdu, chan=37, rssi=r))

        dev = session.devices["11:22:33:44:55:66"]
        assert dev.rssi_min == -80
        assert dev.rssi_max == -40
        assert dev.rssi_avg == -60.0

    def test_comb_channel_hop_blindness_demonstration(self) -> None:
        bus = VirtualRadioBus()
        # Single-channel sniffer tuned to Ch 37 only
        single_obs = TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37, observer_hop=False)
        # Dual-channel sniffer tuned to Ch 37 and Ch 38
        dual_obs = TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38)

        single_obs.start()
        dual_obs.start()
        time.sleep(0.05)

        # Peripheral broadcasting alternating packets on Ch 37 and Ch 38
        pdu37 = bytes([0x02, 6]) + bytes.fromhex("112233445566")
        pdu38 = bytes([0x02, 6]) + bytes.fromhex("665544332211")
        bus.deliver_raw_packet(pdu=pdu37, chan=37, rssi=-60)
        bus.deliver_raw_packet(pdu=pdu38, chan=38, rssi=-60)

        pkts_single = single_obs.get_captured_packets(timeout=0.3)
        pkts_dual = dual_obs.get_merged_packets(max_count=10, timeout=0.3)

        # Single-channel sniffer misses Ch 38 (only gets 1 packet)
        assert len(pkts_single) == 1
        assert pkts_single[0].chan == 37

        # Dual-channel sniffer captures both (eliminates blindness)
        assert len(pkts_dual) == 2
        assert {p.chan for p in pkts_dual} == {37, 38}

        single_obs.stop()
        dual_obs.stop()

    def test_comb_eddystone_uid_and_tlm_interleaved(self) -> None:
        session = TelemetrySession(topology="Interleaved Eddystone")
        adv_a = bytes.fromhex("c011222211c0")

        uid_payload = build_eddystone_uid(bytes(10), bytes(6), -20)
        tlm_payload = build_eddystone_tlm(3300, 22.0, 10, 100)

        pdu_uid = bytes([0x02, len(adv_a) + len(uid_payload)]) + adv_a + uid_payload
        pdu_tlm = bytes([0x02, len(adv_a) + len(tlm_payload)]) + adv_a + tlm_payload

        session.record_packet(dissect_advertising_pdu(pdu_uid, chan=37, rssi=-55))
        session.record_packet(dissect_advertising_pdu(pdu_tlm, chan=37, rssi=-57))

        dev = session.devices["C0:11:22:22:11:C0"]
        assert dev.packet_count == 2
        assert "Eddystone-UID" in dev.beacon_types
        assert "Eddystone-TLM" in dev.beacon_types

    def test_comb_active_scan_burst_correlation_latency_distribution(self) -> None:
        correlator = StimulusResponseCorrelator(max_latency_usec=5_000_000)
        stim_mac = bytes.fromhex("c011222211c0")
        correlator.register_stimulus(adv_a=stim_mac, burst_id=1, start_time_usec=1000, duration_usec=0)

        resp_mac = bytes.fromhex("445566778899")
        # 3 responses at latencies 10ms, 20ms, 30ms (10_000, 20_000, 30_000 us)
        for lat_us in [10_000, 20_000, 30_000]:
            req = build_scan_req(scan_a=resp_mac, adv_a=stim_mac)
            frame = dissect_advertising_pdu(req, ts_usec=1000 + lat_us)
            correlator.process_frame(frame)

        summary = correlator.get_summary()
        assert summary.total_responses == 3
        assert summary.min_latency_ms == pytest.approx(10.0, abs=0.01)
        assert summary.max_latency_ms == pytest.approx(30.0, abs=0.01)
        assert summary.avg_latency_ms == pytest.approx(20.0, abs=0.01)

    def test_comb_all_six_beacons_in_single_pcap_file(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "all_beacons.pcap"
        beacons = [
            ("iBeacon", build_ibeacon("e2c56db5-dffb-48d2-b060-d0f5a71096e0", 1, 1, -59)),
            ("AltBeacon", build_altbeacon(0x0118, bytes(20), -59)),
            ("Eddystone-UID", build_eddystone_uid(bytes(10), bytes(6), -20)),
            ("Eddystone-URL", build_eddystone_url("https://petsymposium.org/", -18)),
            ("Eddystone-TLM", build_eddystone_tlm(3300, 25.0, 100, 1000)),
            ("GAEN", build_gaen(bytes(16), bytes(4))),
        ]

        mac = bytes.fromhex("c011222211c0")
        with PcapBleWriter(pcap_file) as writer:
            for i, (_, payload) in enumerate(beacons):
                pdu = bytes([0x02, len(mac) + len(payload)]) + mac + payload
                writer.write_packet(ts_usec=1000 * (i + 1), aa=0x8E89BED6, chan=37, rssi=-60, packet=pdu)

        # Read back and dissect all
        with PcapBleReader(pcap_file) as reader:
            pkts = list(reader)
            assert len(pkts) == 6
            types_read = []
            for pkt in pkts:
                frame = dissect_advertising_pdu(pkt.body)
                types_read.append(frame.beacon_type)

            assert types_read == [name for name, _ in beacons]

    def test_comb_palindromic_mac_filter_and_correlation(self) -> None:
        correlator = StimulusResponseCorrelator()
        target_mac = generate_palindromic_mac("static", seed=b"target-pal-mac")
        other_mac = bytes.fromhex("112233445566")

        correlator.register_stimulus(adv_a=target_mac, beacon_type="iBeacon", burst_id=1, start_time_usec=1000)

        # Background noise request to other_mac
        noise_req = build_scan_req(scan_a=bytes(6), adv_a=other_mac)
        match_noise = correlator.process_frame(dissect_advertising_pdu(noise_req, ts_usec=1100))
        assert match_noise is None

        # Targeted response to target_mac
        target_req = build_scan_req(scan_a=bytes(6), adv_a=target_mac)
        match_target = correlator.process_frame(dissect_advertising_pdu(target_req, ts_usec=1200))
        assert match_target is not None
        assert match_target.stimulus_adv_a == mac_to_str(target_mac)
