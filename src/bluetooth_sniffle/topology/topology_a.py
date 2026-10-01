"""Topology A: Stimulator (Device 1) + Observer (Device 2).

Coordinates Device 1 as an active beacon transmitter/stimulator broadcasting
synthesized advertising payloads and palindromic MAC addresses, while Device 2
passively captures over-the-air BLE frames on primary advertising channels.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.device.serial_port import allocate_dual_ports
from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.topology.base import BaseTopology

logger = logging.getLogger(__name__)


class TopologyAOrchestrator(BaseTopology):
    """Orchestrates Topology A (Stimulator + Observer) across two Sniffle dongles."""

    def __init__(
        self,
        device1: SniffleDeviceController,
        device2: SniffleDeviceController,
        observer_channel: int = 37,
        observer_hop: bool = False,
    ) -> None:
        super().__init__(device1=device1, device2=device2)
        self.stimulator: SniffleDeviceController = device1
        self.observer: SniffleDeviceController = device2
        self.observer_channel: int = observer_channel
        self.observer_hop: bool = observer_hop

        self.stimuli_count: int = 0
        self.captured_packets: list[PacketMessage] = []

    @classmethod
    def create_mock(
        cls,
        bus: VirtualRadioBus | None = None,
        observer_channel: int = 37,
        observer_hop: bool = False,
    ) -> TopologyAOrchestrator:
        """Create a mock-backed Topology A instance for offline simulation."""
        shared_bus = bus or VirtualRadioBus()
        dev1 = SniffleDeviceController(port="mock://stimulator", mock=True, bus=shared_bus)
        dev2 = SniffleDeviceController(port="mock://observer", mock=True, bus=shared_bus)
        return cls(
            device1=dev1,
            device2=dev2,
            observer_channel=observer_channel,
            observer_hop=observer_hop,
        )

    @classmethod
    def create_hardware(
        cls,
        port1: str | None = None,
        port2: str | None = None,
        observer_channel: int = 37,
        observer_hop: bool = False,
    ) -> TopologyAOrchestrator:
        """Create a hardware-backed Topology A instance using auto-discovered ports."""
        dev1_port, dev2_port = allocate_dual_ports(port1, port2)
        dev1 = SniffleDeviceController(port=dev1_port, mock=False)
        dev2 = SniffleDeviceController(port=dev2_port, mock=False)
        return cls(
            device1=dev1,
            device2=dev2,
            observer_channel=observer_channel,
            observer_hop=observer_hop,
        )

    def start(self) -> None:
        """Open both devices, configure the observer, and prepare stimulator."""
        if self.is_running:
            return

        # 1. Open observer first so no injected packets are missed
        self.observer.open()
        self.observer.start_sniffing(
            chan=self.observer_channel,
            hop=self.observer_hop,
            validate_crc=True,
            rssi_min=-128,
        )

        # 2. Open stimulator
        self.stimulator.open()

        self.is_running = True
        logger.info(
            "Topology A started: Stimulator (%s), Observer (%s, Ch %d, Hop=%s)",
            self.stimulator.port,
            self.observer.port,
            self.observer_channel,
            self.observer_hop,
        )

    def stop(self) -> None:
        """Stop stimulus injection and close both serial devices."""
        if not self.is_running:
            return

        # 1. Close stimulator
        try:
            self.stimulator.close()
        except Exception as exc:
            logger.warning("Error closing stimulator: %s", exc)

        # 2. Close observer
        try:
            self.observer.close()
        except Exception as exc:
            logger.warning("Error closing observer: %s", exc)

        self.is_running = False
        logger.info("Topology A stopped cleanly.")

    def set_stimulus_mac(self, mac: bytes | str, is_random: bool = True) -> None:
        """Set the transmitter MAC address on the stimulator device."""
        self.stimulator.set_mac_address(mac, is_random=is_random)

    def inject_beacon(
        self,
        adv_data: bytes,
        scan_rsp_data: bytes = b"",
        interval_ms: int = 100,
        mode: int = 2,
        duration_sec: float | None = None,
    ) -> None:
        """Broadcast an advertisement payload from the stimulator.

        Args:
            adv_data: Primary AD structure payload (max 31 bytes).
            scan_rsp_data: Optional scan response data (max 31 bytes).
            interval_ms: Advertising interval in milliseconds.
            mode: 0 = connectable, 2 = non-connectable, 3 = scannable.
            duration_sec: If specified, injects for this duration then stops.
        """
        if not self.is_running:
            raise RuntimeError("Cannot inject beacon: Topology A is not running")

        self.stimulator.configure_advertising(
            adv_data=adv_data,
            scan_rsp_data=scan_rsp_data,
            interval_ms=interval_ms,
            mode=mode,
        )
        self.stimuli_count += 1

        if duration_sec is not None and duration_sec > 0:
            time.sleep(duration_sec)

    def inject_burst_sequence(
        self,
        sequence: Sequence[tuple[bytes, float]],
        interval_ms: int = 100,
        mode: int = 2,
    ) -> None:
        """Broadcast a sequence of (payload, duration_sec) beacon bursts sequentially."""
        for payload, duration in sequence:
            self.inject_beacon(
                adv_data=payload,
                interval_ms=interval_ms,
                mode=mode,
                duration_sec=duration,
            )

    def read_packet(self, timeout: float = 1.0) -> PacketMessage | None:
        """Read a single captured packet from the observer."""
        pkt = self.observer.read_packet(timeout=timeout)
        if pkt is not None:
            self.captured_packets.append(pkt)
        return pkt

    def get_captured_packets(self, timeout: float = 0.5) -> list[PacketMessage]:
        """Read all available packets currently in the observer queue."""
        packets = self.observer.read_packets_batch(max_count=200, timeout=timeout)
        self.captured_packets.extend(packets)
        return packets

    def get_stats(self) -> dict[str, Any]:
        """Return operational statistics for Topology A."""
        return {
            "topology": "Topology A (Stimulator + Observer)",
            "is_running": self.is_running,
            "stimulator_port": self.stimulator.port,
            "observer_port": self.observer.port,
            "observer_channel": self.observer_channel,
            "observer_hop": self.observer_hop,
            "stimuli_count": self.stimuli_count,
            "captured_packets_total": len(self.captured_packets),
        }
