"""Comprehensive unit and integration tests for bluetooth-sniffle unified CLI.

Verifies argument parsing, topology execution, mock simulation harness, hardware
loopback verification, output artifact generation (PCAP, JSON, CSV), error paths,
and graceful SIGINT handling.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from bluetooth_sniffle.cli import create_parser, main
from bluetooth_sniffle.sniff.pcap import PcapBleReader
from bluetooth_sniffle.topology.lifecycle import ShutdownCoordinator
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator


@pytest.fixture(autouse=True)
def reset_shutdown_coordinator() -> None:
    """Ensure ShutdownCoordinator is reset before and after each test."""
    coord = ShutdownCoordinator.get_instance()
    coord.reset()
    yield
    coord.reset()


class TestCliArgumentParsing:
    """Tests for CLI parser configuration and command routing."""

    def test_parser_creation(self) -> None:
        parser = create_parser()
        assert parser.prog == "bluetooth-sniffle"

    def test_help_flag_returns_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--help"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "topology-a" in captured.out
        assert "topology-b" in captured.out
        assert "mock-simulate" in captured.out
        assert "verify-hardware" in captured.out

    def test_subcommand_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        for subcmd in ["topology-a", "topology-b", "mock-simulate", "verify-hardware"]:
            rc = main([subcmd, "--help"])
            assert rc == 0
            captured = capsys.readouterr()
            assert subcmd in captured.out or "usage:" in captured.out

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--version"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "bluetooth-sniffle 0.1.0" in captured.out

    def test_empty_arguments_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main([])
        assert rc == 2
        captured = capsys.readouterr()
        assert "usage:" in captured.err

    def test_default_argv_uses_sys_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["bluetooth-sniffle", "--help"])
        rc = main()
        assert rc == 0


class TestTopologyACli:
    """Tests for CLI execution of Topology A in mock mode."""

    def test_topology_a_mock_basic(self) -> None:
        rc = main(["topology-a", "--mock", "--duration-sec", "0.1", "--interval-ms", "50"])
        assert rc == 0

    def test_topology_a_alias_run_topology_a(self) -> None:
        rc = main(["run-topology-a", "--mock", "--duration-sec", "0.1", "--interval-ms", "50"])
        assert rc == 0

    @pytest.mark.parametrize(
        "burst_type",
        ["ibeacon", "altbeacon", "eddystone-uid", "eddystone-url", "eddystone-tlm", "gaen"],
    )
    def test_topology_a_all_burst_types(self, burst_type: str) -> None:
        rc = main([
            "topology-a",
            "--mock",
            "--burst-type",
            burst_type,
            "--duration-sec",
            "0.1",
            "--interval-ms",
            "50",
        ])
        assert rc == 0

    def test_topology_a_with_artifacts_and_correlation(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "topo_a.pcap"
        json_file = tmp_path / "topo_a.json"
        csv_file = tmp_path / "topo_a.csv"

        rc = main([
            "topology-a",
            "--mock",
            "--burst-type",
            "ibeacon",
            "--chan",
            "37",
            "--duration-sec",
            "0.2",
            "--interval-ms",
            "50",
            "--pcap",
            str(pcap_file),
            "--json",
            str(json_file),
            "--csv",
            str(csv_file),
            "--correlate",
        ])
        assert rc == 0

        # 1. Verify PCAP
        assert pcap_file.exists()
        with PcapBleReader(pcap_file) as reader:
            packets = list(reader)
            assert len(packets) >= 1
            for pkt in packets:
                assert pkt.ble_chan == 37
                assert not pkt.crc_err

        # 2. Verify JSON
        assert json_file.exists()
        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert "metadata" in data
        assert "devices" in data
        assert data["metadata"]["topology"] == "Topology A"
        assert data["metadata"]["total_packets"] >= 1

        # 3. Verify CSV
        assert csv_file.exists()
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) >= 1
            assert "mac_address" in rows[0]


class TestTopologyBCli:
    """Tests for CLI execution of Topology B in mock mode."""

    def test_topology_b_mock_basic(self) -> None:
        rc = main(["topology-b", "--mock", "--chan1", "37", "--chan2", "38", "--duration-sec", "0.1"])
        assert rc == 0

    def test_topology_b_alias_run_topology_b(self) -> None:
        rc = main(["run-topology-b", "--mock", "--chan1", "38", "--chan2", "39", "--duration-sec", "0.1"])
        assert rc == 0

    def test_topology_b_artifacts(self, tmp_path: Path) -> None:
        pcap_file = tmp_path / "topo_b.pcap"
        json_file = tmp_path / "topo_b.json"
        csv_file = tmp_path / "topo_b.csv"

        rc = main([
            "topology-b",
            "--mock",
            "--chan1",
            "37",
            "--chan2",
            "38",
            "--duration-sec",
            "0.25",
            "--pcap",
            str(pcap_file),
            "--json",
            str(json_file),
            "--csv",
            str(csv_file),
        ])
        assert rc == 0

        # Verify PCAP output
        assert pcap_file.exists()
        with PcapBleReader(pcap_file) as reader:
            packets = list(reader)
            assert len(packets) >= 1
            # Check channels in capture
            channels_seen = {pkt.ble_chan for pkt in packets}
            assert channels_seen.issubset({37, 38})

        # Verify JSON output
        assert json_file.exists()
        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert data["metadata"]["topology"] == "Topology B"
        assert data["metadata"]["total_packets"] >= 1

        # Verify CSV output
        assert csv_file.exists()
        with open(csv_file, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            assert len(rows) >= 1


class TestMockSimulateCli:
    """Tests for offline loopback simulation command."""

    def test_mock_simulate_in_memory(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["mock-simulate", "--duration-sec", "0.5", "--interval-ms", "50"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "PASSED: 100% packet delivery fidelity verified" in captured.out

    def test_mock_simulate_alias_mock_test(self) -> None:
        rc = main(["mock-test", "--duration-sec", "0.5", "--interval-ms", "50"])
        assert rc == 0

    def test_mock_simulate_with_artifacts(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "simulation.pcap"
        json_path = tmp_path / "simulation.json"
        csv_path = tmp_path / "simulation.csv"

        rc = main([
            "mock-simulate",
            "--duration-sec",
            "0.5",
            "--interval-ms",
            "50",
            "--pcap",
            str(pcap_path),
            "--json",
            str(json_path),
            "--csv",
            str(csv_path),
        ])
        assert rc == 0

        # Verify PCAP
        assert pcap_path.exists()
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) >= 6
            # Assert all 3 primary channels are represented
            channels = {pkt.ble_chan for pkt in pkts}
            assert {37, 38, 39}.issubset(channels)

        # Verify JSON
        assert json_path.exists()
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["metadata"]["total_packets"] >= 6
        # Assert detected beacon types
        beacon_types = set()
        for dev in data["devices"]:
            beacon_types.update(dev.get("beacon_types", []))
        assert "iBeacon" in beacon_types
        assert "AltBeacon" in beacon_types
        assert "Eddystone-UID" in beacon_types
        assert "Eddystone-URL" in beacon_types
        assert "Eddystone-TLM" in beacon_types
        assert "GAEN" in beacon_types

        # Verify CSV
        assert csv_path.exists()
        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            assert len(rows) >= 1


class TestVerifyHardwareCli:
    """Tests for hardware loopback verification command."""

    def test_verify_hardware_mock_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["verify-hardware", "--mock", "--burst-duration-sec", "0.2", "--interval-ms", "50"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Hardware loopback verification PASSED: 5/5 stages verified" in captured.out

    def test_verify_hardware_mock_with_artifacts(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "verify_hw.pcap"
        json_path = tmp_path / "verify_hw.json"
        csv_path = tmp_path / "verify_hw.csv"

        rc = main([
            "verify-hardware",
            "--mock",
            "--chan",
            "37",
            "--burst-duration-sec",
            "0.2",
            "--interval-ms",
            "50",
            "--pcap",
            str(pcap_path),
            "--json",
            str(json_path),
            "--csv",
            str(csv_path),
        ])
        assert rc == 0

        # Verify PCAP
        assert pcap_path.exists()
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) >= 5

        # Verify JSON
        assert json_path.exists()
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["metadata"]["topology"] == "Hardware Loopback Verification"
        assert data["metadata"]["total_packets"] >= 5


class TestCliErrorHandling:
    """Tests for error checking and validation."""

    def test_invalid_subcommand(self) -> None:
        rc = main(["nonexistent-command"])
        assert rc == 2

    def test_topology_a_negative_duration(self) -> None:
        rc = main(["topology-a", "--mock", "--duration-sec", "-1.0"])
        assert rc == 2

    def test_topology_a_invalid_interval(self) -> None:
        rc = main(["topology-a", "--mock", "--interval-ms", "5"])
        assert rc == 2

    def test_topology_a_invalid_channel(self) -> None:
        rc = main(["topology-a", "--mock", "--chan", "99"])
        assert rc == 2

    def test_topology_a_invalid_burst_type(self) -> None:
        rc = main(["topology-a", "--mock", "--burst-type", "nonexistent"])
        assert rc == 2

    def test_topology_b_negative_duration(self) -> None:
        rc = main(["topology-b", "--mock", "--duration-sec", "-2.0"])
        assert rc == 2

    def test_topology_b_identical_channels(self) -> None:
        rc = main(["topology-b", "--mock", "--chan1", "37", "--chan2", "37"])
        assert rc == 2

    def test_mock_simulate_negative_duration(self) -> None:
        rc = main(["mock-simulate", "--duration-sec", "-0.5"])
        assert rc == 2

    def test_verify_hardware_negative_duration(self) -> None:
        rc = main(["verify-hardware", "--mock", "--burst-duration-sec", "-0.1"])
        assert rc == 2

    def test_verify_hardware_missing_dongles(self) -> None:
        with patch("bluetooth_sniffle.cli.allocate_dual_ports", side_effect=RuntimeError("No devices found")):
            rc = main(["verify-hardware"])
            assert rc == 1

    def test_topology_a_hardware_allocation_failure(self) -> None:
        with patch("bluetooth_sniffle.topology.topology_a.allocate_dual_ports", side_effect=RuntimeError("Allocation failed")):
            rc = main(["topology-a"])
            assert rc == 1

    def test_topology_b_hardware_allocation_failure(self) -> None:
        with patch("bluetooth_sniffle.topology.topology_b.allocate_dual_ports", side_effect=RuntimeError("Allocation failed")):
            rc = main(["topology-b"])
            assert rc == 1


class TestCliLifecycleAndSigint:
    """Tests for clean process lifecycle, SIGINT handling, and artifact finalization."""

    def test_topology_a_sigint_handling(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        pcap_path = tmp_path / "sigint_topo_a.pcap"
        json_path = tmp_path / "sigint_topo_a.json"

        call_count = 0
        orig_read = TopologyAOrchestrator.read_packet

        def mock_read(self: TopologyAOrchestrator, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            pkt = orig_read(self, *args, **kwargs)
            if call_count >= 2:
                raise KeyboardInterrupt()
            return pkt

        monkeypatch.setattr(TopologyAOrchestrator, "read_packet", mock_read)

        rc = main([
            "topology-a",
            "--mock",
            "--duration-sec",
            "10.0",
            "--interval-ms",
            "50",
            "--pcap",
            str(pcap_path),
            "--json",
            str(json_path),
        ])
        assert rc == 0

        # Assert PCAP was cleanly flushed and closed with valid header
        assert pcap_path.exists()
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) >= 1

        # Assert JSON was written
        assert json_path.exists()
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["metadata"]["total_packets"] >= 1

    def test_topology_b_sigint_handling(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        pcap_path = tmp_path / "sigint_topo_b.pcap"
        json_path = tmp_path / "sigint_topo_b.json"

        call_count = 0
        orig_read = TopologyBOrchestrator.read_merged_packet

        def mock_read(self: TopologyBOrchestrator, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            pkt = orig_read(self, *args, **kwargs)
            if call_count >= 2:
                raise KeyboardInterrupt()
            return pkt

        monkeypatch.setattr(TopologyBOrchestrator, "read_merged_packet", mock_read)

        rc = main([
            "topology-b",
            "--mock",
            "--duration-sec",
            "10.0",
            "--pcap",
            str(pcap_path),
            "--json",
            str(json_path),
        ])
        assert rc == 0

        # Assert PCAP was cleanly flushed and closed with valid header
        assert pcap_path.exists()
        with PcapBleReader(pcap_path) as reader:
            pkts = list(reader)
            assert len(pkts) >= 1

        # Assert JSON was written
        assert json_path.exists()
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["metadata"]["total_packets"] >= 1

    def test_mock_simulate_sigint_handling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def mock_inject(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(TopologyAOrchestrator, "inject_beacon", mock_inject)
        rc = main(["mock-simulate", "--duration-sec", "5.0"])
        assert rc == 0

    def test_verify_hardware_sigint_handling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def mock_inject(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(TopologyAOrchestrator, "inject_beacon", mock_inject)
        rc = main(["verify-hardware", "--mock", "--burst-duration-sec", "5.0"])
        assert rc == 0
