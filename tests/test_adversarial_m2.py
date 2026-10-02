"""Adversarial stress and edge-case challenge suite for Milestone 2.

Covers:
  1. High-volume packet floods against Topology A:
     - 5,000-packet injection stress test
     - Bit-exact payload integrity verification (0 corruption)
     - End-to-end throughput assertion (> 5,000 pkts/s)
     - Boundary conditions and invalid parameter rejection
  2. Topology B timestamp sorting under heavy interleaved concurrent arrival:
     - Concurrent inter-channel arrival with randomized timing jitter
     - Rate-mismatched batch boundary chunking
     - Channel isolation verification
  3. Threading stress and shutdown lifecycle:
     - Sudden termination signal handling (SIGINT) with exit latency < 500ms
     - Thread termination verification (zero zombie threads)
     - File descriptor leak prevention across repeated start/stop cycles
     - Multi-threaded rapid open/close stress
  4. Serial port discovery edge cases and collision avoidance:
     - Zero dongles (missing hardware)
     - Single dongle (insufficient hardware)
     - Explicit duplicate ports
     - Auto-discovered duplicate / identical comports collision avoidance (port1 != port2)
"""

from __future__ import annotations

import os
import random
import signal
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.device.serial_port import (
    allocate_dual_ports,
    discover_sniffle_ports,
)
from bluetooth_sniffle.protocol.mac import generate_palindromic_mac
from bluetooth_sniffle.protocol.wire import (
    MESSAGE_BLEFRAME,
    PacketMessage,
)
from bluetooth_sniffle.topology.lifecycle import ShutdownCoordinator
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator


class TestTopologyAAdversarial:
    """Adversarial stress testing of Topology A (Stimulator + Observer)."""

    def test_packet_flood_high_throughput_and_zero_corruption(self) -> None:
        """Inject 5,000 distinct packets through Topology A under flood conditions.

        Asserts:
          - 0 packet loss (all 5,000 received)
          - 0 packet corruption (every packet has valid CRC, correct channel 37,
            correct palindromic transmitter MAC, and bit-exact payload match)
          - High throughput (> 5,000 packets/sec).
        """
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            pal_mac = generate_palindromic_mac("static", seed=b"flood-seed-001")
            topo.set_stimulus_mac(pal_mac, is_random=True)

            packet_count = 5000
            # Generate 5,000 unique payloads carrying sequential IDs and verification tokens
            payloads = [
                bytes([0x02, 0x01, 0x06, 0x08, 0xFF, (i >> 8) & 0xFF, i & 0xFF, 0xCA, 0xFE, 0xBA, 0xBE])
                for i in range(packet_count)
            ]

            t_start = time.perf_counter()
            for p in payloads:
                topo.inject_beacon(adv_data=p)

            # Drain observer packets
            received: list[PacketMessage] = []
            drain_deadline = time.perf_counter() + 10.0
            while len(received) < packet_count and time.perf_counter() < drain_deadline:
                batch = topo.observer.read_packets_batch(max_count=500, timeout=0.05)
                received.extend(batch)

            t_elapsed = time.perf_counter() - t_start
            throughput = len(received) / max(t_elapsed, 0.001)

            # Assert zero packet loss
            assert len(received) == packet_count, (
                f"Packet loss detected: expected {packet_count}, received {len(received)}"
            )

            # Assert zero corruption across all 5,000 packets
            for idx, pkt in enumerate(received):
                assert not pkt.crc_err, f"CRC error flag set in packet {idx}"
                assert pkt.chan == 37, f"Packet {idx} arrived on unexpected channel {pkt.chan}"
                assert pal_mac in pkt.body, f"Stimulus MAC missing from packet {idx} body"
                assert payloads[idx] in pkt.body, (
                    f"Bit corruption detected in packet {idx}: expected {payloads[idx]!r} in {pkt.body!r}"
                )

            # Assert high throughput (> 5,000 pkts/s)
            assert throughput > 5000, f"Throughput {throughput:.1f} pkt/s below 5,000 threshold"

    def test_rapid_burst_sequence_integrity(self) -> None:
        """Inject 25 rapid beacon bursts with alternating payloads and verify sequencing."""
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            pal_mac = generate_palindromic_mac("nrpa", seed=b"burst-seq-seed")
            topo.set_stimulus_mac(pal_mac, is_random=True)

            burst_count = 25
            sequence = [
                (bytes([0x02, 0x01, 0x06, 0x03, 0xFF, idx, 0xAA]), 0.001)
                for idx in range(burst_count)
            ]
            topo.inject_burst_sequence(sequence, interval_ms=20, mode=2)

            received = topo.get_captured_packets(timeout=0.5)
            assert len(received) >= burst_count

            # Verify sequential delivery of payloads
            for idx in range(burst_count):
                expected_ad = sequence[idx][0]
                assert expected_ad in received[idx].body, f"Burst {idx} payload mismatch"

    def test_invalid_parameters_rejected(self) -> None:
        """Verify that malformed or out-of-spec parameters are defensively rejected."""
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus) as topo:
            # Payload > 31 bytes
            with pytest.raises(ValueError, match="adv_data exceeds 31 bytes"):
                topo.inject_beacon(adv_data=bytes(32))

            # Scan response > 31 bytes
            with pytest.raises(ValueError, match="scan_rsp_data exceeds 31 bytes"):
                topo.inject_beacon(adv_data=bytes(10), scan_rsp_data=bytes(32))

            # Invalid advertising interval (< 20 ms)
            with pytest.raises(ValueError, match="Advertising interval"):
                topo.inject_beacon(adv_data=bytes(10), interval_ms=10)

            # Invalid advertising mode
            with pytest.raises(ValueError, match="Mode must be 0"):
                topo.inject_beacon(adv_data=bytes(10), mode=1)

        # Inject beacon while topology is stopped
        with pytest.raises(RuntimeError, match="Cannot inject beacon"):
            topo.inject_beacon(adv_data=bytes(10))


class TestTopologyBAdversarial:
    """Adversarial challenge for Topology B (Dual-Channel Passive Observer)."""

    def test_topology_b_timestamp_ordering_under_jitter(self) -> None:
        """Inject 100 interleaved packets across Ch 37 and Ch 38 with simulated delivery jitter.

        Asserts:
          - Every packet is captured (no blindness across Ch 37 and Ch 38).
          - timestamps == sorted(timestamps) strictly holds true as packets are consumed in real time.
        """
        bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo:
            time.sleep(0.02)  # Let merger thread start

            total_packets = 100
            base_ts = 2_000_000

            # Interleaved ground-truth sequence: even on Ch 37, odd on Ch 38
            timeline = []
            for i in range(total_packets):
                chan = 37 if i % 2 == 0 else 38
                ts = base_ts + i * 1000  # monotonically increasing timestamps
                timeline.append((chan, ts, f"interleaved_pkt_{i}".encode()))

            consumed_packets: list[PacketMessage] = []
            consumer_active = True

            def consumer_worker():
                while consumer_active:
                    pkt = topo.read_merged_packet(timeout=0.02)
                    if pkt is not None:
                        consumed_packets.append(pkt)

            consumer_thread = threading.Thread(target=consumer_worker, daemon=True)
            consumer_thread.start()

            def producer_worker(target_chan: int, dev: SniffleDeviceController):
                for chan, ts, body in timeline:
                    if chan == target_chan:
                        # Introduce realistic USB UART / OS scheduling jitter between 0.1ms and 4ms
                        time.sleep(random.uniform(0.0001, 0.004))
                        pkt_bytes = PacketMessage.pack(body=body, ts=ts, chan=chan)
                        dev.ser.inject_message(MESSAGE_BLEFRAME, pkt_bytes)

            p1 = threading.Thread(target=producer_worker, args=(37, topo.device1))
            p2 = threading.Thread(target=producer_worker, args=(38, topo.device2))
            p1.start()
            p2.start()
            p1.join()
            p2.join()

            # Allow consumer to drain remaining packets
            time.sleep(0.15)
            consumer_active = False
            consumer_thread.join(timeout=1.0)

            assert len(consumed_packets) == total_packets, (
                f"Missing packets: got {len(consumed_packets)}, expected {total_packets}"
            )

            timestamps = [p.ts for p in consumed_packets]
            inversions = [
                (i, timestamps[i], timestamps[i + 1])
                for i in range(len(timestamps) - 1)
                if timestamps[i] > timestamps[i + 1]
            ]

            assert len(inversions) == 0, (
                f"Timestamp sorting failure: {len(inversions)} inversions detected! "
                f"First inversion at index {inversions[0][0]}: "
                f"ts[{inversions[0][0]}]={inversions[0][1]} > ts[{inversions[0][0]+1}]={inversions[0][2]}"
            )
            assert timestamps == sorted(timestamps), "Stream timestamps are not monotonically non-decreasing"

    def test_topology_b_batch_boundary_rate_mismatch(self) -> None:
        """Verify sorting when Channel 37 generates 60 packets and Channel 38 generates 20 packets."""
        bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo:
            # Pause collector to preload queues
            topo._collector_running = False
            time.sleep(0.05)

            # Ch 37: 60 packets with ts = 10, 20, ..., 600
            for i in range(1, 61):
                raw = PacketMessage.pack(body=b"ch37_fast", ts=i * 10, chan=37)
                topo.device1._packet_queue.put(PacketMessage(raw))

            # Ch 38: 20 packets with ts = 50, 100, ..., 1000
            for i in range(1, 21):
                raw = PacketMessage.pack(body=b"ch38_slow", ts=i * 50, chan=38)
                topo.device2._packet_queue.put(PacketMessage(raw))

            # Resume collector loop
            topo._collector_running = True
            collector_thread = threading.Thread(target=topo._merge_collector_loop, daemon=True)
            collector_thread.start()

            consumed: list[PacketMessage] = []
            deadline = time.monotonic() + 3.0
            while len(consumed) < 80 and time.monotonic() < deadline:
                p = topo.read_merged_packet(timeout=0.05)
                if p:
                    consumed.append(p)

            topo._collector_running = False
            collector_thread.join(timeout=1.0)

            assert len(consumed) == 80
            timestamps = [p.ts for p in consumed]
            assert timestamps == sorted(timestamps), (
                f"Batch chunking caused timestamp inversion: ts={timestamps[:10]}...{timestamps[-10:]}"
            )

    def test_topology_b_channel_isolation(self) -> None:
        """Verify that Topology B strictly isolates primary channels (ignores Ch 39 frames)."""
        bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo:
            time.sleep(0.02)

            # Deliver packet on Channel 39 (neither device is listening on 39)
            pdu_ch39 = b"\x02\x08\xaa\xbb\xcc\xdd\xee\xff\x39\x39"
            bus.deliver_raw_packet(pdu=pdu_ch39, chan=39, rssi=-55)

            # Deliver packet on Channel 37
            pdu_ch37 = b"\x02\x08\xaa\xbb\xcc\xdd\xee\xff\x37\x37"
            bus.deliver_raw_packet(pdu=pdu_ch37, chan=37, rssi=-55)

            pkt = topo.read_merged_packet(timeout=0.5)
            assert pkt is not None
            assert pkt.chan == 37
            assert b"\x37\x37" in pkt.body

            # No second packet should arrive
            pkt_none = topo.read_merged_packet(timeout=0.05)
            assert pkt_none is None


class TestLifecycleAndThreadingStress:
    """Adversarial stress testing for lifecycle management, shutdown, and threading."""

    def test_sigint_sudden_termination_latency(self) -> None:
        """Simulate sudden SIGINT termination signal and assert shutdown in < 500ms.

        Asserts:
          - Signal is handled cleanly.
          - Shutdown coordinator signals completion within < 500ms.
          - All background reader and merger threads terminate without zombie leaks.
        """
        coord = ShutdownCoordinator.get_instance()
        coord.reset()
        coord.install_signal_handlers()

        topo = TopologyBOrchestrator.create_mock(chan1=37, chan2=38)
        topo.start()
        coord.register(topo.stop)

        active_thread_names = [t.name for t in threading.enumerate() if t.is_alive()]
        assert "TopologyBMerger" in active_thread_names
        assert any("SniffleReader" in name for name in active_thread_names)

        t_start = time.perf_counter()
        signal.raise_signal(signal.SIGINT)
        shutdown_completed = coord.wait(timeout=0.5)
        t_elapsed_ms = (time.perf_counter() - t_start) * 1000

        # Assert shutdown completes within < 500ms
        assert shutdown_completed, f"Shutdown exceeded 500ms timeout (took {t_elapsed_ms:.1f}ms)"
        assert not topo.is_running

        # Verify background threads terminated
        remaining_threads = [t.name for t in threading.enumerate() if t.is_alive()]
        assert "TopologyBMerger" not in remaining_threads, "TopologyBMerger thread leaked"
        assert not any("SniffleReader" in name for name in remaining_threads), "SniffleReader thread leaked"

    def test_file_descriptor_leak_prevention(self) -> None:
        """Assert zero file descriptors are leaked across 20 rapid start/stop cycles."""
        def get_fds() -> set[str]:
            return set(os.listdir("/proc/self/fd"))

        fds_initial = get_fds()

        for _ in range(20):
            with TopologyAOrchestrator.create_mock(observer_channel=37):
                pass
            with TopologyBOrchestrator.create_mock(chan1=37, chan2=38):
                pass

        fds_final = get_fds()
        leaked_fds = fds_final - fds_initial
        assert len(leaked_fds) == 0, f"File descriptor leak detected: leaked {leaked_fds}"

    def test_multithreaded_rapid_controller_lifecycle(self) -> None:
        """Concurrently open and close controllers across 10 threads without deadlock."""
        errors: list[Exception] = []

        def worker(thread_id: int):
            try:
                for _ in range(10):
                    ctrl = SniffleDeviceController(port=f"mock://stress_{thread_id}", mock=True)
                    ctrl.open()
                    assert ctrl.is_open
                    ctrl.close()
                    assert not ctrl.is_open
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
            assert not t.is_alive(), "Worker thread hung / deadlocked"

        assert len(errors) == 0, f"Errors in concurrent controller lifecycle: {errors}"


class TestSerialPortDiscoveryAdversarial:
    """Adversarial testing of serial port discovery, baud negotiation, and dual allocation."""

    def test_allocate_dual_ports_missing_dongles_raises(self) -> None:
        """Assert RuntimeError is raised when zero Sniffle dongles are connected."""
        with patch("serial.tools.list_ports.comports", return_value=[]):
            with pytest.raises(RuntimeError, match="Dual-device topology requires 2 Sniffle dongles, but only 0 detected"):
                allocate_dual_ports()

    def test_allocate_dual_ports_single_dongle_raises(self) -> None:
        """Assert RuntimeError is raised when only 1 Sniffle dongle is connected."""
        mock_p1 = MagicMock()
        mock_p1.vid = 0x10C4
        mock_p1.pid = 0xEA60
        mock_p1.device = "/dev/ttyUSB0"
        mock_p1.description = "Sonoff Zigbee Dongle Plus"
        mock_p1.product = "Sonoff"

        with patch("serial.tools.list_ports.comports", return_value=[mock_p1]):
            with pytest.raises(RuntimeError, match="Dual-device topology requires 2 Sniffle dongles, but only 1 detected"):
                allocate_dual_ports()

    def test_allocate_dual_ports_explicit_identical_raises_value_error(self) -> None:
        """Assert ValueError is raised when user explicitly provides identical ports."""
        with pytest.raises(ValueError, match="Conflicting port allocation: Device 1 and Device 2 cannot share port"):
            allocate_dual_ports("/dev/ttyUSB0", "/dev/ttyUSB0")

    def test_allocate_dual_ports_one_explicit_one_auto(self) -> None:
        """When dev1 is explicitly specified, auto-select distinct dev2 from available ports."""
        mock_p1 = MagicMock()
        mock_p1.vid = 0x10C4
        mock_p1.pid = 0xEA60
        mock_p1.device = "/dev/ttyUSB0"
        mock_p1.description = "Sonoff Dongle"
        mock_p1.product = "Sonoff"

        mock_p2 = MagicMock()
        mock_p2.vid = 0x0451
        mock_p2.pid = 0xBEF3
        mock_p2.device = "/dev/ttyACM0"
        mock_p2.description = "TI XDS110"
        mock_p2.product = "LaunchPad"

        with patch("serial.tools.list_ports.comports", return_value=[mock_p1, mock_p2]):
            # Specify dev1 only
            p1, p2 = allocate_dual_ports(dev1="/dev/ttyUSB0")
            assert p1 == "/dev/ttyUSB0"
            assert p2 == "/dev/ttyACM0"
            assert p1 != p2

            # Specify dev2 only
            p1, p2 = allocate_dual_ports(dev2="/dev/ttyUSB0")
            assert p1 == "/dev/ttyACM0"
            assert p2 == "/dev/ttyUSB0"
            assert p1 != p2

    def test_allocate_dual_ports_duplicate_comport_collision(self) -> None:
        """Assert collision avoidance when comports returns identical duplicate dongle paths.

        If comports reports two entries for '/dev/ttyUSB0', allocate_dual_ports must NOT
        allocate both dev1 and dev2 to '/dev/ttyUSB0'.
        """
        mock_p1 = MagicMock()
        mock_p1.vid = 0x10C4
        mock_p1.pid = 0xEA60
        mock_p1.device = "/dev/ttyUSB0"
        mock_p1.description = "Sonoff Dongle"
        mock_p1.product = "Sonoff"

        mock_p2 = MagicMock()
        mock_p2.vid = 0x10C4
        mock_p2.pid = 0xEA60
        mock_p2.device = "/dev/ttyUSB0"
        mock_p2.description = "Sonoff Dongle"
        mock_p2.product = "Sonoff"

        with patch("serial.tools.list_ports.comports", return_value=[mock_p1, mock_p2]):
            discovered = discover_sniffle_ports()
            assert len(discovered) == 1
            # If comports has duplicate items, discovery or allocation must deduplicate
            # and reject allocation due to insufficient distinct physical dongles
            with pytest.raises(RuntimeError):
                allocate_dual_ports()
