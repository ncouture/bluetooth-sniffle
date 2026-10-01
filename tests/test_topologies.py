"""Unit tests for dual-device topologies (Topology A and Topology B) and lifecycle management."""

import time

from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.protocol.beacons import (
    build_altbeacon,
    build_eddystone_uid,
    build_ibeacon,
)
from bluetooth_sniffle.protocol.mac import generate_palindromic_mac
from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.topology.lifecycle import ShutdownCoordinator
from bluetooth_sniffle.topology.topology_a import TopologyAOrchestrator
from bluetooth_sniffle.topology.topology_b import TopologyBOrchestrator


class TestTopologyA:
    """Tests for Topology A (Stimulator + Observer) orchestration."""

    def test_topology_a_lifecycle_mock(self) -> None:
        bus = VirtualRadioBus()
        topo = TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37)
        assert not topo.is_running

        topo.start()
        assert topo.is_running
        assert topo.observer.is_sniffing
        assert topo.observer.channel == 37

        topo.stop()
        assert not topo.is_running
        assert not topo.observer.is_sniffing

    def test_topology_a_context_manager(self) -> None:
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus) as topo:
            assert topo.is_running
        assert not topo.is_running

    def test_topology_a_ibeacon_injection_and_capture(self) -> None:
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            # 1. Set palindromic MAC address on stimulator
            pal_mac = generate_palindromic_mac("static", seed=b"test-seed-123456")
            topo.set_stimulus_mac(pal_mac, is_random=True)

            # 2. Build verified iBeacon payload
            ibeacon_payload = build_ibeacon(
                uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                major=1,
                minor=2,
                tx_power=-59,
            )

            # 3. Inject advertisement
            topo.inject_beacon(adv_data=ibeacon_payload, interval_ms=50, mode=2)

            # 4. Observer captures packet
            pkt = topo.read_packet(timeout=1.0)
            assert pkt is not None
            assert isinstance(pkt, PacketMessage)
            assert pkt.chan == 37
            assert pkt.crc_err is False
            assert pkt.rssi == -60

            # Verify AdvA and iBeacon payload in body
            assert pal_mac in pkt.body
            assert ibeacon_payload in pkt.body

            # Check stats
            stats = topo.get_stats()
            assert stats["stimuli_count"] == 1
            assert stats["captured_packets_total"] >= 1

    def test_topology_a_burst_sequence(self) -> None:
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37) as topo:
            pal_mac = generate_palindromic_mac("static", seed=b"burst-seed-98765")
            topo.set_stimulus_mac(pal_mac, is_random=True)

            altbeacon_payload = build_altbeacon(
                mfg_id=0x0118,
                beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"),
                ref_rssi=-59,
            )
            eddystone_payload = build_eddystone_uid(
                namespace=bytes.fromhex("0102030405060708090a"),
                instance=bytes.fromhex("010203040506"),
                tx_power=-20,
            )

            sequence = [
                (altbeacon_payload, 0.05),
                (eddystone_payload, 0.05),
            ]
            topo.inject_burst_sequence(sequence, interval_ms=20, mode=2)

            packets = topo.get_captured_packets(timeout=0.2)
            assert len(packets) >= 2

            stats = topo.get_stats()
            assert stats["stimuli_count"] == 2


class TestTopologyB:
    """Tests for Topology B (Dual-Channel Passive Observer) orchestration."""

    def test_topology_b_lifecycle_mock(self) -> None:
        bus = VirtualRadioBus()
        topo = TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38)
        assert not topo.is_running

        topo.start()
        assert topo.is_running
        assert topo.device1.is_sniffing
        assert topo.device1.channel == 37
        assert topo.device2.is_sniffing
        assert topo.device2.channel == 38

        topo.stop()
        assert not topo.is_running
        assert not topo.device1.is_sniffing
        assert not topo.device2.is_sniffing

    def test_topology_b_merged_timestamp_stream(self) -> None:
        """Test concurrent capture across Ch 37 and Ch 38 with sorted timestamps."""
        bus = VirtualRadioBus()
        with TopologyBOrchestrator.create_mock(bus=bus, chan1=37, chan2=38) as topo:
            time.sleep(0.05)  # Allow background threads to settle

            # Deliver interleaved packets directly to bus
            pdu1 = b"\x00\x08\xaa\xbb\xcc\xdd\xee\xff\x01\x01"
            pdu2 = b"\x00\x08\x11\x22\x33\x44\x55\x66\x02\x02"
            pdu3 = b"\x00\x08\xaa\xbb\xcc\xdd\xee\xff\x03\x03"

            # Deliver on Ch 37, Ch 38, and Ch 37
            bus.deliver_raw_packet(pdu=pdu1, chan=37, rssi=-62)
            bus.deliver_raw_packet(pdu=pdu2, chan=38, rssi=-65)
            bus.deliver_raw_packet(pdu=pdu3, chan=37, rssi=-60)

            # Retrieve merged packets
            merged = topo.get_merged_packets(max_count=10, timeout=0.5)
            assert len(merged) == 3

            # Verify packets from both channels were captured (no blindness)
            channels_captured = {pkt.chan for pkt in merged}
            assert channels_captured == {37, 38}

            # Verify strictly non-decreasing timestamps
            timestamps = [pkt.ts for pkt in merged]
            assert timestamps == sorted(timestamps)

            stats = topo.get_stats()
            assert stats["packets_chan1"] == 2
            assert stats["packets_chan2"] == 1
            assert stats["merged_packets_total"] == 3


class TestShutdownCoordinator:
    """Tests for process/thread lifecycle and shutdown coordinator."""

    def test_singleton_and_registration(self) -> None:
        coord = ShutdownCoordinator.get_instance()
        coord.reset()

        executed = []

        def cleanup_1():
            executed.append("first")

        def cleanup_2():
            executed.append("second")

        coord.register(cleanup_1)
        coord.register(cleanup_2)

        assert not coord.is_shutting_down
        coord.shutdown()
        assert coord.is_shutting_down

        # Callbacks run in reverse order (LIFO)
        assert executed == ["second", "first"]

    def test_error_resilience_in_callbacks(self) -> None:
        coord = ShutdownCoordinator.get_instance()
        coord.reset()

        executed = []

        def failing_cleanup():
            raise RuntimeError("Failure during teardown")

        def successful_cleanup():
            executed.append("success")

        coord.register(successful_cleanup)
        coord.register(failing_cleanup)

        # Shutdown should proceed and execute successful_cleanup despite failure
        coord.shutdown()
        assert executed == ["success"]

    def test_install_signal_handlers(self) -> None:
        coord = ShutdownCoordinator.get_instance()
        coord.reset()
        coord.install_signal_handlers()
        assert coord._handlers_installed is True
