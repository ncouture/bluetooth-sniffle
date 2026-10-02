"""Milestone 5 Tier 4: Realistic PoPETs 2025-0103 Application Scenarios.

This suite simulates five comprehensive real-world application scenarios based on the
PoPETs 2025-0103 research paper ("Stimulating BLE Privacy Failures: Active Probing
and Side-Channel Elicitation in Commercial Trackers and Exposure Notification Systems"):

1. Scenario 1: Retail Tracking Stimulation Simulation
   - Topology A: Stimulator emits randomized advertising bursts mimicking commercial
     trackers (iBeacon, AltBeacon) with palindromic MACs.
   - Observer captures responses, correlates latencies, and generates JSON/CSV telemetry.

2. Scenario 2: Contact Tracing Privacy Evaluation
   - Topology A: Emits Exposure Notification / GAEN frames (Service UUID 0xFD6F) with
     rotating pseudo-random RPAs and encrypted metadata (RPI + AEM).
   - Measures correlatability of observed RPAs and verifies burst ID association.

3. Scenario 3: Active Elicitation of Device Names
   - Topology A in active-scan mode: Emits SCAN_REQ to observed target devices.
   - Ingests SCAN_RSP containing Complete Local Name.
   - Validates that Wireshark PCAP output accurately tags elicited names and MAC addresses.

4. Scenario 4: Dual-Channel Anti-Blindness Validation
   - Topology B: Target rotates between advertising channels 37 and 38.
   - Single-channel sniffers experience periodic blindness (missed bursts); dual-channel
     Topology B captures interleaved bursts without packet loss.
   - Verifies merged timestamp synchronization and channel tagging.

5. Scenario 5: Full Pipeline Hardware Loopback Simulation
   - Complete offline replay of the 5-stage hardware verification sequence (Topology A & B,
     all 6 beacon formats, active scanning, burst correlation, PCAP export, telemetry generation).
   - Validates that the entire architecture functions cohesively without external hardware.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from uuid import UUID

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
    GaenInfo,
    classify_address,
    dissect_advertising_pdu,
)
from bluetooth_sniffle.sniff.pcap import PcapBleReader, PcapBleWriter
from bluetooth_sniffle.sniff.telemetry import TelemetrySession
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator


def _make_adv_pdu(mac: bytes, payload: bytes, pdu_type: int = 0x02) -> bytes:
    """Wrap address and advertising payload into a Link Layer PDU."""
    return bytes([pdu_type & 0x0F, len(mac) + len(payload)]) + mac + payload


class TestPoPETsScenario1RetailTrackingStimulation:
    """Scenario 1: Retail Tracking Stimulation Simulation.

    Simulates commercial retail trackers emitting iBeacon and AltBeacon bursts
    using palindromic MAC addresses to probe observer responsiveness, recording
    latencies and exporting telemetry artifacts.
    """

    def test_scenario1_retail_tracking_stimulation_complete(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "retail_tracking.pcap"
        telemetry_json = tmp_path / "retail_telemetry.json"
        devices_csv = tmp_path / "retail_devices.csv"
        events_csv = tmp_path / "retail_events.csv"

        bus = VirtualRadioBus()
        correlator = StimulusResponseCorrelator(max_latency_usec=100_000, clock_tolerance_usec=5_000)
        session = TelemetrySession(topology="Topology A Retail Tracking")

        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            # 1. Generate stimulus bursts with palindromic MACs
            stim1_mac = generate_palindromic_mac("static", seed=b"111_retail")
            stim2_mac = generate_palindromic_mac("static", seed=b"222_retail")
            assert is_palindromic_mac(stim1_mac)
            assert is_palindromic_mac(stim2_mac)

            # Stimulus 1: iBeacon burst
            correlator.register_stimulus(
                adv_a=stim1_mac,
                beacon_type="iBeacon",
                burst_id=1,
                stimulus_id="1",
                start_time_usec=1_000_000,
                duration_usec=50_000,
            )
            ibeacon_payload = build_ibeacon(
                uuid=UUID("11111111-2222-3333-4444-555555555555"),
                major=100,
                minor=1,
                tx_power=-59,
            )
            ibeacon_pdu = _make_adv_pdu(stim1_mac, ibeacon_payload)
            bus.deliver_raw_packet(ibeacon_pdu, chan=37, rssi=-68)

            # Responder reacts to Stimulus 1 with a SCAN_REQ
            responder1_mac = bytes.fromhex("001122334455")
            scan_req1 = build_scan_req(scan_a=responder1_mac, adv_a=stim1_mac)
            bus.deliver_raw_packet(scan_req1, chan=37, rssi=-55)

            # Stimulus 2: AltBeacon burst
            correlator.register_stimulus(
                adv_a=stim2_mac,
                beacon_type="AltBeacon",
                burst_id=2,
                stimulus_id="2",
                start_time_usec=1_002_000,
                duration_usec=50_000,
            )
            altbeacon_payload = build_altbeacon(
                beacon_id=b"\xAA" * 20,
                ref_rssi=-24,
            )
            altbeacon_pdu = _make_adv_pdu(stim2_mac, altbeacon_payload)
            bus.deliver_raw_packet(altbeacon_pdu, chan=37, rssi=-72)

            # Responder reacts to Stimulus 2 with a SCAN_REQ
            responder2_mac = bytes.fromhex("0066778899AA")
            scan_req2 = build_scan_req(scan_a=responder2_mac, adv_a=stim2_mac)
            bus.deliver_raw_packet(scan_req2, chan=37, rssi=-60)

            # Observer collects packets from mock sniffer
            pkts = topo.get_captured_packets(timeout=0.5)
            assert len(pkts) == 4

        # 2. Process and dissect captured packets
        with PcapBleWriter(pcap_path) as writer:
            for p in pkts:
                frame = dissect_advertising_pdu(p.body, chan=p.chan, rssi=p.rssi, ts_usec=p.ts)
                writer.write_dissected_frame(frame)
                session.record_packet(frame)

                match = correlator.process_frame(frame)
                if match:
                    session.record_event({
                        "burst_id": match.stimulus_id,
                        "stimulus_mac": match.stimulus_adv_a,
                        "stimulus_type": "iBeacon" if match.stimulus_id == "1" else "AltBeacon",
                        "response_pdu_type": match.response_pdu_type,
                        "responder_mac": match.responder_mac,
                        "responder_mac_type": match.responder_type,
                        "delta_ms": match.latency_ms,
                        "chan": match.channel,
                        "rssi": match.rssi,
                        "timestamp_usec": match.response_timestamp_usec,
                    })

        # 3. Export Telemetry
        session.export_json(telemetry_json)
        session.export_devices_csv(devices_csv)
        session.export_events_csv(events_csv)

        # 4. Verify Correlator Results
        correlator_summary = correlator.get_summary()
        assert correlator_summary.total_stimuli == 2
        assert correlator_summary.total_responses == 2
        assert correlator_summary.correlated_stimuli_count == 2

        # 5. Verify Telemetry JSON
        with open(telemetry_json, "r", encoding="utf-8") as f:
            tele_data = json.load(f)
        assert tele_data["metadata"]["total_packets"] == 4
        assert tele_data["metadata"]["unique_devices_count"] == 4
        assert len(tele_data["stimulus_response_events"]) == 2

        # 6. Verify Devices CSV and Events CSV
        with open(devices_csv, "r", encoding="utf-8") as f:
            dev_rows = list(csv.DictReader(f))
        assert len(dev_rows) == 4
        macs = {r["mac_address"] for r in dev_rows}
        assert mac_to_str(stim1_mac).upper() in macs
        assert mac_to_str(stim2_mac).upper() in macs
        assert "00:11:22:33:44:55" in macs
        assert "00:66:77:88:99:AA" in macs

        with open(events_csv, "r", encoding="utf-8") as f:
            evt_rows = list(csv.DictReader(f))
        assert len(evt_rows) == 2
        assert evt_rows[0]["burst_id"] == "1"
        assert evt_rows[0]["responder_mac"] == "00:11:22:33:44:55"
        assert evt_rows[1]["burst_id"] == "2"
        assert evt_rows[1]["responder_mac"] == "00:66:77:88:99:AA"

        # 7. Verify PCAP Integrity
        with PcapBleReader(pcap_path) as reader:
            pcap_pkts = list(reader)
            assert len(pcap_pkts) == 4
            for pkt in pcap_pkts:
                assert pkt.ble_chan == 37
                assert not pkt.crc_err


class TestPoPETsScenario2ContactTracingPrivacyEvaluation:
    """Scenario 2: Contact Tracing Privacy Evaluation.

    Simulates the Google/Apple Exposure Notification (GAEN, 0xFD6F) service with
    periodic Resolvable Private Address (RPA) rotation, testing whether stimulus
    bursts can identify and correlate target responses across rotation epochs.
    """

    def test_scenario2_contact_tracing_privacy_complete(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "contact_tracing.pcap"
        session = TelemetrySession(topology="Topology A GAEN Privacy")
        correlator = StimulusResponseCorrelator(max_latency_usec=50_000)

        # 3 Rotation Epochs with different RPAs
        rpa_epochs = [
            generate_palindromic_mac("rpa", seed=b"ep1_rpa"),
            generate_palindromic_mac("rpa", seed=b"ep2_rpa"),
            generate_palindromic_mac("rpa", seed=b"ep3_rpa"),
        ]
        for rpa in rpa_epochs:
            assert classify_address(rpa) == BleAddressType.RPA

        with PcapBleWriter(pcap_path) as writer:
            # Replay 3 burst-response cycles across epochs
            for epoch_idx, rpa in enumerate(rpa_epochs, start=1):
                burst_time = epoch_idx * 1_000_000
                correlator.register_stimulus(
                    adv_a=rpa,
                    beacon_type="GAEN",
                    burst_id=epoch_idx,
                    stimulus_id=str(epoch_idx),
                    start_time_usec=burst_time,
                    duration_usec=30_000,
                )

                # Target emits GAEN broadcast with 16B RPI and 4B AEM
                rpi = bytes([epoch_idx] * 16)
                aem = bytes([0x50, 0x01, 0x02, epoch_idx])
                gaen_payload = build_gaen(rpi=rpi, aem=aem)
                gaen_pdu = _make_adv_pdu(rpa, gaen_payload)

                frame_gaen = dissect_advertising_pdu(
                    gaen_pdu, chan=37, rssi=-65, ts_usec=burst_time + 1000
                )
                assert frame_gaen.beacon_type == "GAEN"
                assert isinstance(frame_gaen.beacon_info, GaenInfo)
                assert frame_gaen.beacon_info.rpi == rpi
                assert frame_gaen.beacon_info.aem == aem
                writer.write_dissected_frame(frame_gaen)
                session.record_packet(frame_gaen)

                # Auditor / Observer stimulates target, eliciting a SCAN_REQ from listener
                listener_mac = bytes.fromhex("223344556677")
                scan_req_pdu = build_scan_req(scan_a=listener_mac, adv_a=rpa)
                frame_req = dissect_advertising_pdu(
                    scan_req_pdu, chan=37, rssi=-60, ts_usec=burst_time + 8_500
                )
                writer.write_dissected_frame(frame_req)
                session.record_packet(frame_req)

                match = correlator.process_frame(frame_req)
                assert match is not None
                assert match.stimulus_id == str(epoch_idx)
                assert match.responder_mac == "22:33:44:55:66:77"
                assert match.latency_ms == pytest.approx(8.5, abs=0.01)

                session.record_event({
                    "burst_id": match.stimulus_id,
                    "stimulus_mac": match.stimulus_adv_a,
                    "stimulus_type": "GAEN",
                    "response_pdu_type": match.response_pdu_type,
                    "responder_mac": match.responder_mac,
                    "responder_mac_type": match.responder_type,
                    "delta_ms": match.latency_ms,
                    "chan": match.channel,
                    "rssi": match.rssi,
                    "timestamp_usec": match.response_timestamp_usec,
                })

        # Verify correlator tracked all 3 bursts across RPA rotations
        summary = correlator.get_summary()
        assert summary.total_stimuli == 3
        assert summary.total_responses == 3
        assert summary.correlated_stimuli_count == 3
        assert summary.avg_latency_ms == pytest.approx(8.5, abs=0.01)

        # Verify Telemetry captured all 3 rotating RPAs under service 0xFD6F
        tele_summary = session.get_summary()
        assert tele_summary["metadata"]["total_packets"] == 6
        # Devices: 3 RPAs + 1 listener = 4 unique devices
        assert tele_summary["metadata"]["unique_devices_count"] == 4

        for rpa in rpa_epochs:
            rpa_str = mac_to_str(rpa).upper()
            assert rpa_str in session.devices
            dev = session.devices[rpa_str]
            assert "0xFD6F" in dev.service_uuids
            assert "GAEN" in dev.beacon_types

        # Verify PCAP file contains all 6 packets
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 6
            for i in range(3):
                # Even indices: ADV_NONCONN_IND (GAEN)
                assert pkts[i * 2].body[0] & 0x0F == 2
                # Odd indices: SCAN_REQ
                assert pkts[i * 2 + 1].body[0] & 0x0F == 3


class TestPoPETsScenario3ActiveElicitationDeviceNames:
    """Scenario 3: Active Elicitation of Device Names.

    Simulates Topology A active scanning where an active probe (SCAN_REQ) is
    transmitted upon detecting an advertiser, eliciting a SCAN_RSP containing
    a Complete Local Name, and confirming end-to-end PCAP and telemetry capture.
    """

    def test_scenario3_active_elicitation_device_names_complete(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "active_elicitation.pcap"
        session = TelemetrySession(topology="Topology A Active Scan")

        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            # 1. Target advertiser emits ADV_IND with palindromic MAC
            target_mac = generate_palindromic_mac("static", seed=b"target_mac_pal")
            adv_ind_pdu = bytes([0x00, 0x06]) + target_mac
            bus.deliver_raw_packet(adv_ind_pdu, chan=37, rssi=-64)

            # 2. Scanner sends SCAN_REQ to target
            scanner_mac = bytes.fromhex("102030405060")
            scan_req_pdu = build_scan_req(scan_a=scanner_mac, adv_a=target_mac)
            bus.deliver_raw_packet(scan_req_pdu, chan=37, rssi=-50)

            # 3. Target responds with SCAN_RSP containing Complete Local Name
            scan_rsp_pdu = build_scan_rsp(
                adv_a=target_mac, local_name="PoPETs-Tracker-X9"
            )
            bus.deliver_raw_packet(scan_rsp_pdu, chan=37, rssi=-63)

            # Sniffer captures all 3 packets
            raw_pkts = topo.get_captured_packets(timeout=0.5)
            assert len(raw_pkts) == 3

        # Dissect and export to PCAP and Telemetry
        with PcapBleWriter(pcap_path) as writer:
            for pkt in raw_pkts:
                frame = dissect_advertising_pdu(
                    pkt.body, chan=pkt.chan, rssi=pkt.rssi, ts_usec=pkt.ts
                )
                writer.write_dissected_frame(frame)
                session.record_packet(frame)

        # 4. Verify PCAP structure
        with PcapBleReader(pcap_path) as reader:
            captured = list(reader)
            assert len(captured) == 3

            # ADV_IND
            assert captured[0].body[0] & 0x0F == 0
            # SCAN_REQ
            assert captured[1].body[0] & 0x0F == 3
            # SCAN_RSP
            assert captured[2].body[0] & 0x0F == 4

        # 5. Verify Telemetry device profiling
        target_str = mac_to_str(target_mac).upper()
        assert target_str in session.devices
        target_dev = session.devices[target_str]
        # Target appears in ADV_IND, as adv_a in SCAN_REQ, and in SCAN_RSP
        assert target_dev.packet_count == 3
        assert "PoPETs-Tracker-X9" in target_dev.observed_names

        scanner_str = mac_to_str(scanner_mac).upper()
        assert scanner_str in session.devices
        assert session.devices[scanner_str].packet_count == 1


class TestPoPETsScenario4DualChannelAntiBlindnessValidation:
    """Scenario 4: Dual-Channel Anti-Blindness Validation.

    Simulates target advertisement hopping across channels 37 and 38. Demonstrates
    that a single-channel sniffer suffers blindness (misses 50% of broadcasts),
    while Topology B captures all packets with strict chronological interleaving.
    """

    def test_scenario4_dual_channel_anti_blindness_complete(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "dual_channel_merged.pcap"
        bus = VirtualRadioBus()

        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo_b:
            target_mac = generate_palindromic_mac("static", seed=b"target_dual_pal")

            # Target hops across 37 and 38 for 10 consecutive bursts
            for i in range(10):
                chan = 37 if i % 2 == 0 else 38
                # Alternating iBeacon (on 37) and AltBeacon (on 38)
                if chan == 37:
                    payload = build_ibeacon(
                        uuid=UUID("12345678-1234-5678-1234-567812345678"),
                        major=i,
                        minor=1,
                    )
                else:
                    payload = build_altbeacon(
                        beacon_id=bytes([i] * 20),
                        ref_rssi=-24,
                    )

                pdu = _make_adv_pdu(target_mac, payload)
                bus.deliver_raw_packet(pdu, chan=chan, rssi=-60 - i)

            # Retrieve merged dual-channel packets
            merged_pkts = topo_b.get_merged_packets(max_count=10, timeout=1.0)
            assert len(merged_pkts) == 10

        # Verify Monotonic Timestamps and Alternating Channels
        timestamps = [p.ts for p in merged_pkts]
        assert timestamps == sorted(timestamps)

        channels = [p.chan for p in merged_pkts]
        assert channels == [37, 38, 37, 38, 37, 38, 37, 38, 37, 38]

        # Single-channel blindness demonstration:
        # A channel-37-only sniffer would see only half the packets
        ch37_only = [p for p in merged_pkts if p.chan == 37]
        ch38_only = [p for p in merged_pkts if p.chan == 38]
        assert len(ch37_only) == 5
        assert len(ch38_only) == 5

        # Write merged dual-channel capture to PCAP
        session = TelemetrySession(topology="Topology B Dual Channel")
        with PcapBleWriter(pcap_path) as writer:
            for p in merged_pkts:
                frame = dissect_advertising_pdu(p.body, chan=p.chan, rssi=p.rssi, ts_usec=p.ts)
                writer.write_dissected_frame(frame)
                session.record_packet(frame)

        # Verify PCAP output
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) == 10
            for i, pkt in enumerate(pkts):
                expected_chan = 37 if i % 2 == 0 else 38
                assert pkt.ble_chan == expected_chan

        # Verify Telemetry channel counts
        summary = session.get_summary()
        assert summary["metadata"]["total_packets"] == 10
        assert summary["metadata"]["channel_packet_counts"][37] == 5
        assert summary["metadata"]["channel_packet_counts"][38] == 5
        dev = session.devices[mac_to_str(target_mac).upper()]
        assert dev.channels_seen == {37, 38}
        assert dev.beacon_types == {"iBeacon", "AltBeacon"}


class TestPoPETsScenario5FullPipelineHardwareLoopbackSimulation:
    """Scenario 5: Full Pipeline Hardware Loopback Simulation.

    Simulates the complete offline replay of the 5-stage verification sequence:
    1. Dongle configuration / initialization commands.
    2. Multi-beacon transmission (all 6 beacon formats) with palindromic MACs.
    3. Active scanning and elicitation (SCAN_REQ / SCAN_RSP).
    4. Burst stimulus-response correlation and latency evaluation.
    5. Dual-topology artifact generation (PCAP + JSON + CSV).
    """

    def test_scenario5_full_pipeline_hardware_loopback_complete(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "full_pipeline_loopback.pcap"
        telemetry_json = tmp_path / "full_pipeline_telemetry.json"
        devices_csv = tmp_path / "full_pipeline_devices.csv"
        events_csv = tmp_path / "full_pipeline_events.csv"

        bus = VirtualRadioBus()
        correlator = StimulusResponseCorrelator(max_latency_usec=50_000)
        session = TelemetrySession(topology="Topology A & B Hybrid Loopback")

        # ----------------------------------------------------------------------
        # Stage 1 & 2: Multi-Beacon Transmission with Palindromic MACs
        # ----------------------------------------------------------------------
        beacon_pdus = []
        # 1. iBeacon
        mac1 = generate_palindromic_mac("static", seed=b"seed_mac_1")
        pay1 = build_ibeacon(UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), 10, 20)
        beacon_pdus.append((_make_adv_pdu(mac1, pay1), mac1, "iBeacon", 37))

        # 2. AltBeacon
        mac2 = generate_palindromic_mac("static", seed=b"seed_mac_2")
        pay2 = build_altbeacon(beacon_id=b"\x11" * 20, ref_rssi=-24)
        beacon_pdus.append((_make_adv_pdu(mac2, pay2), mac2, "AltBeacon", 38))

        # 3. Eddystone-UID
        mac3 = generate_palindromic_mac("nrpa", seed=b"seed_mac_3")
        pay3 = build_eddystone_uid(b"\xAA" * 10, b"\xBB" * 6)
        beacon_pdus.append((_make_adv_pdu(mac3, pay3), mac3, "Eddystone-UID", 39))

        # 4. Eddystone-URL
        mac4 = generate_palindromic_mac("nrpa", seed=b"seed_mac_4")
        pay4 = build_eddystone_url("https://example.com")
        beacon_pdus.append((_make_adv_pdu(mac4, pay4), mac4, "Eddystone-URL", 37))

        # 5. Eddystone-TLM
        mac5 = generate_palindromic_mac("rpa", seed=b"seed_mac_5")
        pay5 = build_eddystone_tlm(3300, 24.5, 100, 1000)
        beacon_pdus.append((_make_adv_pdu(mac5, pay5), mac5, "Eddystone-TLM", 38))

        # 6. GAEN (Exposure Notification)
        mac6 = generate_palindromic_mac("rpa", seed=b"seed_mac_6")
        pay6 = build_gaen(b"\xEE" * 16, b"\x01\x02\x03\x04")
        beacon_pdus.append((_make_adv_pdu(mac6, pay6), mac6, "GAEN", 39))

        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo_b:
            # Deliver all beacons on their assigned channels
            for idx, (pdu, mac, b_type, chan) in enumerate(beacon_pdus, start=1):
                correlator.register_stimulus(
                    adv_a=mac,
                    beacon_type=b_type,
                    burst_id=idx,
                    start_time_usec=idx * 1_000_000,
                    duration_usec=20_000,
                )
                bus.deliver_raw_packet(pdu, chan=chan, rssi=-60 - idx)

            # ------------------------------------------------------------------
            # Stage 3: Active Scanning & Elicitation
            # ------------------------------------------------------------------
            active_target_mac = generate_palindromic_mac("static", seed=b"active_target")
            active_scanner_mac = bytes.fromhex("112233445566")
            req = build_scan_req(scan_a=active_scanner_mac, adv_a=active_target_mac)
            rsp = build_scan_rsp(adv_a=active_target_mac, local_name="LoopbackDevice-Elicited")
            bus.deliver_raw_packet(req, chan=37, rssi=-55)
            bus.deliver_raw_packet(rsp, chan=37, rssi=-56)

            # ------------------------------------------------------------------
            # Stage 4: Responder packet elicitation for burst 1
            # ------------------------------------------------------------------
            resp1 = build_scan_req(scan_a=bytes.fromhex("aabbccddeeff"), adv_a=mac1)
            bus.deliver_raw_packet(resp1, chan=37, rssi=-58)

            # Retrieve captured packets on monitored channels (37 and 38)
            captured = topo_b.get_merged_packets(max_count=20, timeout=1.0)
            # Beacons on ch 37 & 38: iBeacon(37), AltBeacon(38), Eddystone-URL(37), Eddystone-TLM(38) = 4
            # Plus active scan req & rsp on 37 = 2
            # Plus responder for burst 1 on 37 = 1
            # Total expected on 37 and 38 = 7 packets
            assert len(captured) == 7

        # ----------------------------------------------------------------------
        # Stage 5: Dual-Topology Artifact Generation (PCAP + JSON + CSV)
        # ----------------------------------------------------------------------
        with PcapBleWriter(pcap_path) as writer:
            for p in captured:
                frame = dissect_advertising_pdu(p.body, chan=p.chan, rssi=p.rssi, ts_usec=p.ts)
                writer.write_dissected_frame(frame)
                session.record_packet(frame)

                match = correlator.process_frame(frame)
                if match:
                    session.record_event({
                        "burst_id": match.stimulus_id,
                        "stimulus_mac": match.stimulus_adv_a,
                        "stimulus_type": "iBeacon",
                        "response_pdu_type": match.response_pdu_type,
                        "responder_mac": match.responder_mac,
                        "responder_mac_type": match.responder_type,
                        "delta_ms": match.latency_ms,
                        "chan": match.channel,
                        "rssi": match.rssi,
                        "timestamp_usec": match.response_timestamp_usec,
                    })

        session.export_json(telemetry_json)
        session.export_devices_csv(devices_csv)
        session.export_events_csv(events_csv)

        # Assertions on pipeline completeness
        # 1. PCAP verification
        with PcapBleReader(pcap_path) as reader:
            pcap_pkts = list(reader)
            assert len(pcap_pkts) == 7

        # 2. Telemetry verification
        summary = session.get_summary()
        assert summary["metadata"]["total_packets"] == 7
        assert len(summary["stimulus_response_events"]) == 1
        assert summary["stimulus_response_events"][0]["responder_mac"] == "AA:BB:CC:DD:EE:FF"

        # 3. Elicited name verified
        active_target_str = mac_to_str(active_target_mac).upper()
        assert active_target_str in session.devices
        assert "LoopbackDevice-Elicited" in session.devices[active_target_str].observed_names

        # 4. Artifact existence and non-empty content
        assert pcap_path.stat().st_size > 0
        assert telemetry_json.stat().st_size > 0
        assert devices_csv.stat().st_size > 0
        assert events_csv.stat().st_size > 0
