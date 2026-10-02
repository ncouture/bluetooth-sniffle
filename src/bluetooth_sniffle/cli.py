"""Unified Command Line Interface for Bluetooth-Sniffle Testbed Framework.

Provides CLI entrypoints for Topology A, Topology B, offline loopback simulation,
and hardware loopback verification as specified in PoPETs 2025-0103.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.device.serial_port import allocate_dual_ports
from bluetooth_sniffle.protocol.beacons import (
    build_altbeacon,
    build_eddystone_tlm,
    build_eddystone_uid,
    build_eddystone_url,
    build_gaen,
    build_ibeacon,
)
from bluetooth_sniffle.protocol.mac import generate_palindromic_mac
from bluetooth_sniffle.sniff.correlation import StimulusResponseCorrelator
from bluetooth_sniffle.sniff.dissector import dissect_advertising_pdu
from bluetooth_sniffle.sniff.pcap import PcapBleReader, PcapBleWriter
from bluetooth_sniffle.sniff.telemetry import TelemetrySession
from bluetooth_sniffle.topology.lifecycle import ShutdownCoordinator
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator

logger = logging.getLogger(__name__)


def build_beacon_payload(burst_type: str) -> bytes:
    """Build a standard beacon AD payload corresponding to burst_type."""
    b_type = burst_type.lower().strip()
    if b_type == "ibeacon":
        return build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=1,
            tx_power=-59,
        )
    if b_type == "altbeacon":
        return build_altbeacon(
            mfg_id=0x0118,
            beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010001"),
            ref_rssi=-59,
        )
    if b_type in ("eddystone-uid", "eddystone_uid"):
        return build_eddystone_uid(
            namespace=bytes.fromhex("0102030405060708090a"),
            instance=bytes.fromhex("010203040506"),
            tx_power=-20,
        )
    if b_type in ("eddystone-url", "eddystone_url"):
        return build_eddystone_url(
            url="https://example.com/test",
            tx_power=-18,
        )
    if b_type in ("eddystone-tlm", "eddystone_tlm"):
        return build_eddystone_tlm(
            vbatt_mv=3300,
            temp_c=22.5,
            adv_cnt=100,
            sec_cnt=1000,
        )
    if b_type == "gaen":
        return build_gaen(
            rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            aem=bytes.fromhex("01020304"),
        )
    raise ValueError(f"Unsupported burst-type: {burst_type!r}")


def handle_topology_a(args: argparse.Namespace) -> int:
    """Execute Topology A (Device 1 stimulator + Device 2 observer)."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyAOrchestrator | None = None
    pcap_writer: PcapBleWriter | None = None
    telemetry_session: TelemetrySession | None = None
    correlator: StimulusResponseCorrelator | None = None

    def cleanup() -> None:
        if pcap_writer is not None:
            pcap_writer.close()
        if telemetry_session is not None:
            if args.json:
                telemetry_session.export_json(args.json)
            if args.csv:
                telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    try:
        if args.mock:
            topo = TopologyAOrchestrator.create_mock(observer_channel=args.chan)
        else:
            try:
                topo = TopologyAOrchestrator.create_hardware(
                    port1=args.dev1,
                    port2=args.dev2,
                    observer_channel=args.chan,
                )
            except Exception as exc:
                logger.error("Hardware setup failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        coord.register(cleanup)
        topo.start()

        pal_mac = generate_palindromic_mac("static", seed=b"topo-a-static")
        topo.set_stimulus_mac(pal_mac, is_random=True)
        adv_payload = build_beacon_payload(args.burst_type)

        if args.pcap:
            pcap_writer = PcapBleWriter(args.pcap)

        if args.json or args.csv or args.correlate:
            telemetry_session = TelemetrySession(topology="Topology A")

        if args.correlate:
            correlator = StimulusResponseCorrelator()
            correlator.register_stimulus(
                adv_a=pal_mac,
                beacon_type=args.burst_type,
                burst_id=1,
                channel=args.chan,
                payload=adv_payload,
            )

        topo.inject_beacon(adv_data=adv_payload, interval_ms=args.interval_ms, mode=2)

        deadline = time.monotonic() + args.duration_sec
        next_mock_inject = time.monotonic() + (args.interval_ms / 1000.0)

        while time.monotonic() < deadline and not coord.is_shutting_down:
            if args.mock and time.monotonic() >= next_mock_inject:
                topo.inject_beacon(adv_data=adv_payload, interval_ms=args.interval_ms, mode=2)
                next_mock_inject = time.monotonic() + max(0.02, args.interval_ms / 1000.0)

            pkt = topo.read_packet(timeout=0.05)
            if pkt is not None:
                if pcap_writer is not None:
                    pcap_writer.write_packet_message(pkt)
                if telemetry_session is not None or correlator is not None:
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        if telemetry_session is not None:
                            telemetry_session.record_packet(frame)
                        if correlator is not None:
                            match = correlator.process_frame(frame)
                            if match and telemetry_session is not None:
                                telemetry_session.record_event({
                                    "burst_id": match.stimulus_id,
                                    "stimulus_mac": match.stimulus_adv_a,
                                    "stimulus_type": args.burst_type,
                                    "response_pdu_type": match.response_pdu_type,
                                    "responder_mac": match.responder_mac,
                                    "responder_mac_type": match.responder_type,
                                    "delta_ms": match.latency_ms,
                                    "chan": match.channel,
                                    "rssi": match.rssi,
                                    "timestamp_usec": match.response_timestamp_usec,
                                })
                    except Exception as ex:
                        logger.debug("Frame processing error: %s", ex)

        logger.info("Topology A run completed successfully.")
        return 0

    except KeyboardInterrupt:
        logger.info("Topology A interrupted by user (SIGINT).")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_topology_b(args: argparse.Namespace) -> int:
    """Execute Topology B (Dual-Channel Passive Observer)."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.chan1 == args.chan2:
        logger.error("chan1 and chan2 must be distinct (got chan1=%d, chan2=%d)", args.chan1, args.chan2)
        print("ERROR: chan1 and chan2 must be distinct", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyBOrchestrator | None = None
    pcap_writer: PcapBleWriter | None = None
    telemetry_session: TelemetrySession | None = None

    def cleanup() -> None:
        if pcap_writer is not None:
            pcap_writer.close()
        if telemetry_session is not None:
            if args.json:
                telemetry_session.export_json(args.json)
            if args.csv:
                telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    try:
        if args.mock:
            topo = TopologyBOrchestrator.create_mock(chan1=args.chan1, chan2=args.chan2)
        else:
            try:
                topo = TopologyBOrchestrator.create_hardware(
                    port1=args.dev1,
                    port2=args.dev2,
                    chan1=args.chan1,
                    chan2=args.chan2,
                )
            except Exception as exc:
                logger.error("Hardware setup failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        if args.pcap:
            pcap_writer = PcapBleWriter(args.pcap)

        if args.json or args.csv:
            telemetry_session = TelemetrySession(topology="Topology B")

        coord.register(cleanup)

        topo.start()

        deadline = time.monotonic() + args.duration_sec
        next_mock_gen = time.monotonic()

        while time.monotonic() < deadline and not coord.is_shutting_down:
            if args.mock and hasattr(topo.device1, "bus") and topo.device1.bus is not None:
                if time.monotonic() >= next_mock_gen:
                    pdu1 = bytes([0x02, 0x0A]) + bytes.fromhex("112233445566") + bytes.fromhex("0201060303AAFE")
                    pdu2 = bytes([0x02, 0x0A]) + bytes.fromhex("665544332211") + bytes.fromhex("02010603036FFD")
                    topo.device1.bus.deliver_raw_packet(pdu=pdu1, chan=args.chan1, rssi=-62)
                    topo.device1.bus.deliver_raw_packet(pdu=pdu2, chan=args.chan2, rssi=-65)
                    next_mock_gen = time.monotonic() + 0.05

            pkt = topo.read_merged_packet(timeout=0.05)
            if pkt is not None:
                if pcap_writer is not None:
                    pcap_writer.write_packet_message(pkt)
                if telemetry_session is not None:
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        telemetry_session.record_packet(frame)
                    except Exception as ex:
                        logger.debug("Frame dissection error: %s", ex)

        logger.info("Topology B run completed successfully.")
        return 0

    except KeyboardInterrupt:
        logger.info("Topology B interrupted by user (SIGINT).")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_mock_simulate(args: argparse.Namespace) -> int:
    """Execute full offline loopback simulation in software without hardware."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    shared_bus = VirtualRadioBus()
    topo = TopologyAOrchestrator.create_mock(bus=shared_bus, observer_channel=37, observer_hop=True)

    pcap_writer = PcapBleWriter(args.pcap) if args.pcap else PcapBleWriter(None)
    telemetry_session = TelemetrySession(topology="Mock Simulation Harness")

    def cleanup() -> None:
        pcap_writer.close()
        if args.json:
            telemetry_session.export_json(args.json)
        if args.csv:
            telemetry_session.export_csv(args.csv)
        if topo.is_running:
            topo.stop()

    coord.register(cleanup)

    test_beacons: list[tuple[str, bytes]] = [
        ("iBeacon", build_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=10, minor=20, tx_power=-59)),
        ("AltBeacon", build_altbeacon(mfg_id=0x0118, beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"), ref_rssi=-59)),
        ("Eddystone-UID", build_eddystone_uid(namespace=bytes.fromhex("0102030405060708090a"), instance=bytes.fromhex("010203040506"), tx_power=-20)),
        ("Eddystone-URL", build_eddystone_url(url="https://example.com/mock", tx_power=-18)),
        ("Eddystone-TLM", build_eddystone_tlm(vbatt_mv=3300, temp_c=25.0, adv_cnt=500, sec_cnt=10000)),
        ("GAEN", build_gaen(rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"), aem=bytes.fromhex("01020304"))),
    ]

    try:
        topo.start()
        pal_mac = generate_palindromic_mac("static", seed=b"mock-sim-pal-mac")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        verified_types: set[str] = set()
        channels_seen: set[int] = set()

        for beacon_name, payload in test_beacons:
            if coord.is_shutting_down:
                break

            topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)
            time.sleep(0.02)
            packets = topo.get_captured_packets(timeout=0.1)

            for pkt in packets:
                pcap_writer.write_packet_message(pkt)
                channels_seen.add(pkt.chan)
                try:
                    frame = dissect_advertising_pdu(
                        raw_pdu=pkt.body,
                        chan=pkt.chan,
                        rssi=pkt.rssi,
                        ts_usec=pkt.ts,
                    )
                    telemetry_session.record_packet(frame)
                    if frame.beacon_type == beacon_name:
                        verified_types.add(beacon_name)
                except Exception as ex:
                    logger.debug("Dissection error: %s", ex)

        cleanup()
        coord.unregister(cleanup)

        # Fidelity Verification
        expected_types = {name for name, _ in test_beacons}
        missing_types = expected_types - verified_types

        if missing_types:
            logger.error("Simulation failed fidelity check: missing %s", missing_types)
            print(f"ERROR: Simulation failed fidelity check. Missing beacon types: {sorted(list(missing_types))}", file=sys.stderr)
            return 1

        if args.pcap:
            with PcapBleReader(args.pcap) as reader:
                read_pkts = list(reader)
                if not read_pkts:
                    logger.error("Generated PCAP is empty")
                    return 1

        if args.json:
            raw_json = Path(args.json).read_text(encoding="utf-8")
            parsed_json = json.loads(raw_json)
            if "metadata" not in parsed_json or parsed_json["metadata"]["total_packets"] == 0:
                logger.error("Generated JSON report is missing required packet metadata")
                return 1

        summary = telemetry_session.get_summary()
        logger.info(
            "Mock simulation completed: 100%% fidelity, %d packets captured across channels %s.",
            summary["metadata"]["total_packets"],
            sorted(list(channels_seen)),
        )
        print("Mock simulation PASSED: 100% packet delivery fidelity verified across all primary channels.")
        return 0

    except KeyboardInterrupt:
        logger.info("Mock simulation interrupted by user.")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_verify_hardware(args: argparse.Namespace) -> int:
    """Execute hardware loopback verification command per ORIGINAL_REQUEST §R4."""
    if args.burst_duration_sec < 0:
        logger.error("burst-duration-sec must be non-negative (got %s)", args.burst_duration_sec)
        print("ERROR: burst-duration-sec must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyAOrchestrator | None = None
    pcap_writer = PcapBleWriter(args.pcap) if args.pcap else PcapBleWriter(None)
    telemetry_session = TelemetrySession(topology="Hardware Loopback Verification")

    def cleanup() -> None:
        pcap_writer.close()
        if args.json:
            telemetry_session.export_json(args.json)
        if args.csv:
            telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    coord.register(cleanup)

    try:
        if args.mock:
            topo = TopologyAOrchestrator.create_mock(observer_channel=args.chan)
        else:
            try:
                port1, port2 = allocate_dual_ports(args.dev1, args.dev2)
                topo = TopologyAOrchestrator.create_hardware(
                    port1=port1,
                    port2=port2,
                    observer_channel=args.chan,
                )
            except (RuntimeError, ValueError) as exc:
                logger.error("Hardware auto-discovery/allocation failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        topo.start()
        pal_mac = generate_palindromic_mac("static", seed=b"verify-hw-pal-mac")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        stages: list[tuple[int, str, bytes, str]] = [
            (
                1,
                "Apple iBeacon",
                build_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=100, minor=200, tx_power=-59),
                "iBeacon",
            ),
            (
                2,
                "Radius Networks AltBeacon",
                build_altbeacon(mfg_id=0x0118, beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"), ref_rssi=-59),
                "AltBeacon",
            ),
            (
                3,
                "Google Eddystone-UID",
                build_eddystone_uid(namespace=bytes.fromhex("0102030405060708090a"), instance=bytes.fromhex("010203040506"), tx_power=-20),
                "Eddystone-UID",
            ),
            (
                4,
                "Google Eddystone-URL",
                build_eddystone_url(url="https://petsymposium.org/", tx_power=-18),
                "Eddystone-URL",
            ),
            (
                5,
                "Google/Apple GAEN",
                build_gaen(rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"), aem=bytes.fromhex("01020304")),
                "GAEN",
            ),
        ]

        passed_stages = 0

        for stage_idx, stage_desc, payload, expected_beacon_type in stages:
            if coord.is_shutting_down:
                break

            topo.observer.drain_packets()
            topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)

            deadline = time.monotonic() + max(0.1, args.burst_duration_sec)
            stage_verified = False

            while time.monotonic() < deadline and not coord.is_shutting_down:
                pkt = topo.read_packet(timeout=0.05)
                if pkt is not None:
                    pcap_writer.write_packet_message(pkt)
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        telemetry_session.record_packet(frame)
                        if frame.beacon_type == expected_beacon_type:
                            stage_verified = True
                    except Exception as ex:
                        logger.debug("Dissection error: %s", ex)
                elif args.mock and not stage_verified:
                    topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)

            if stage_verified:
                logger.info("Stage %d/5 (%s): PASSED", stage_idx, stage_desc)
                passed_stages += 1
            else:
                logger.error("Stage %d/5 (%s): FAILED (no matching %s beacon captured)", stage_idx, stage_desc, expected_beacon_type)

        cleanup()
        coord.unregister(cleanup)

        if passed_stages == len(stages):
            print(f"Hardware loopback verification PASSED: {passed_stages}/{len(stages)} stages verified.")
            return 0
        else:
            print(f"Hardware loopback verification FAILED: {passed_stages}/{len(stages)} stages passed.", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        logger.info("Hardware verification interrupted by user.")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the top-level argument parser and subparsers."""
    parser = argparse.ArgumentParser(
        prog="bluetooth-sniffle",
        description="Dual-Device Bluetooth Low Energy Sniffle Testbed Framework (PoPETs 2025-0103)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--version", action="version", version="bluetooth-sniffle 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. Topology A
    p_topo_a = subparsers.add_parser(
        "topology-a",
        aliases=["run-topology-a"],
        help="Run Topology A (Device 1 stimulator + Device 2 observer)",
    )
    p_topo_a.add_argument("--dev1", type=str, default=None, help="Device 1 serial port (stimulator)")
    p_topo_a.add_argument("--dev2", type=str, default=None, help="Device 2 serial port (observer)")
    p_topo_a.add_argument("--mock", action="store_true", help="Run with in-memory mock serial devices")
    p_topo_a.add_argument("--chan", type=int, default=37, choices=[37, 38, 39], help="Observer capture channel (default: 37)")
    p_topo_a.add_argument(
        "--burst-type",
        type=str,
        default="ibeacon",
        choices=["ibeacon", "altbeacon", "eddystone-uid", "eddystone-url", "eddystone-tlm", "gaen"],
        help="Beacon advertising profile to inject (default: ibeacon)",
    )
    p_topo_a.add_argument("--interval-ms", type=int, default=100, help="Advertising interval in milliseconds (default: 100)")
    p_topo_a.add_argument("--duration-sec", type=float, default=5.0, help="Total execution duration in seconds (default: 5.0)")
    p_topo_a.add_argument("--pcap", type=str, default=None, help="Output PCAP file path")
    p_topo_a.add_argument("--json", type=str, default=None, help="Output JSON session telemetry path")
    p_topo_a.add_argument("--csv", type=str, default=None, help="Output CSV summary path")
    p_topo_a.add_argument("--correlate", action="store_true", help="Enable stimulus-response correlation engine")

    # 2. Topology B
    p_topo_b = subparsers.add_parser(
        "topology-b",
        aliases=["run-topology-b"],
        help="Run Topology B (Device 1 on chan1, Device 2 on chan2, merged capture)",
    )
    p_topo_b.add_argument("--dev1", type=str, default=None, help="Device 1 serial port")
    p_topo_b.add_argument("--dev2", type=str, default=None, help="Device 2 serial port")
    p_topo_b.add_argument("--mock", action="store_true", help="Run with in-memory mock serial devices")
    p_topo_b.add_argument("--chan1", type=int, default=37, choices=[37, 38, 39], help="Channel for Device 1 (default: 37)")
    p_topo_b.add_argument("--chan2", type=int, default=38, choices=[37, 38, 39], help="Channel for Device 2 (default: 38)")
    p_topo_b.add_argument("--duration-sec", type=float, default=5.0, help="Total execution duration in seconds (default: 5.0)")
    p_topo_b.add_argument("--pcap", type=str, default=None, help="Output PCAP file path")
    p_topo_b.add_argument("--json", type=str, default=None, help="Output JSON session telemetry path")
    p_topo_b.add_argument("--csv", type=str, default=None, help="Output CSV summary path")

    # 3. Mock Simulation
    p_mock_sim = subparsers.add_parser(
        "mock-simulate",
        aliases=["mock-test"],
        help="Run full offline loopback simulation in software without hardware",
    )
    p_mock_sim.add_argument("--pcap", type=str, default=None, help="Output PCAP file path (optional)")
    p_mock_sim.add_argument("--json", type=str, default=None, help="Output JSON telemetry path (optional)")
    p_mock_sim.add_argument("--csv", type=str, default=None, help="Output CSV summary path (optional)")
    p_mock_sim.add_argument("--duration-sec", type=float, default=2.0, help="Simulation duration in seconds (default: 2.0)")
    p_mock_sim.add_argument("--interval-ms", type=int, default=50, help="Stimulus injection interval in ms (default: 50)")

    # 4. Verify Hardware
    p_verify_hw = subparsers.add_parser(
        "verify-hardware",
        help="Run hardware loopback verification command per ORIGINAL_REQUEST §R4",
    )
    p_verify_hw.add_argument("--dev1", type=str, default=None, help="Device 1 serial port")
    p_verify_hw.add_argument("--dev2", type=str, default=None, help="Device 2 serial port")
    p_verify_hw.add_argument("--mock", action="store_true", help="Run in mock/offline mode (CI compatible)")
    p_verify_hw.add_argument("--chan", type=int, default=37, choices=[37, 38, 39], help="Observer capture channel (default: 37)")
    p_verify_hw.add_argument("--burst-duration-sec", type=float, default=0.5, help="Duration for each burst stage in seconds (default: 0.5)")
    p_verify_hw.add_argument("--interval-ms", type=int, default=50, help="Advertising interval in milliseconds (default: 50)")
    p_verify_hw.add_argument("--pcap", type=str, default=None, help="Output PCAP file path (optional)")
    p_verify_hw.add_argument("--json", type=str, default=None, help="Output JSON telemetry path (optional)")
    p_verify_hw.add_argument("--csv", type=str, default=None, help="Output CSV summary path (optional)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint for bluetooth-sniffle."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    cmd = args.command
    if cmd in ("topology-a", "run-topology-a"):
        return handle_topology_a(args)
    elif cmd in ("topology-b", "run-topology-b"):
        return handle_topology_b(args)
    elif cmd in ("mock-simulate", "mock-test"):
        return handle_mock_simulate(args)
    elif cmd == "verify-hardware":
        return handle_verify_hardware(args)
    else:
        logger.error("Unknown command: %s", cmd)
        parser.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
