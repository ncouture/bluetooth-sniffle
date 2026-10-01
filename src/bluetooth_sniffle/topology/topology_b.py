"""Topology B: Dual-Channel Passive Observer.

Coordinates two Sniffle dongles locked simultaneously to different primary
advertising channels (e.g. Channel 37 and Channel 38) with merged, timestamp-ordered
packet delivery to eliminate channel-hop blindness.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import VirtualRadioBus
from bluetooth_sniffle.device.serial_port import allocate_dual_ports
from bluetooth_sniffle.protocol.wire import PacketMessage
from bluetooth_sniffle.topology.base import BaseTopology

logger = logging.getLogger(__name__)


class TopologyBOrchestrator(BaseTopology):
    """Orchestrates Topology B (Dual-Channel Sniffer) with merged timestamp streams."""

    def __init__(
        self,
        device1: SniffleDeviceController,
        device2: SniffleDeviceController,
        chan1: int = 37,
        chan2: int = 38,
        jitter_window_ms: float = 30.0,
    ) -> None:
        super().__init__(device1=device1, device2=device2)
        self.chan1: int = chan1
        self.chan2: int = chan2
        self.jitter_window_s: float = max(0.005, jitter_window_ms / 1000.0)

        self.packets_chan1_count: int = 0
        self.packets_chan2_count: int = 0
        self.merged_packets_total: int = 0

        # Monotonicity & watermark tracking
        self._last_ts1: int | None = None
        self._last_ts2: int | None = None
        self._last_rx_mono1: float = 0.0
        self._last_rx_mono2: float = 0.0

        self._sorted_buffer: list[PacketMessage] = []
        self._lock: threading.Lock = threading.Lock()
        self._cond: threading.Condition = threading.Condition(self._lock)
        self._collector_thread: threading.Thread | None = None
        self._collector_running: bool = False

    @classmethod
    def create_mock(
        cls,
        bus: VirtualRadioBus | None = None,
        chan1: int = 37,
        chan2: int = 38,
        jitter_window_ms: float = 30.0,
    ) -> TopologyBOrchestrator:
        """Create a mock-backed Topology B instance for offline simulation."""
        shared_bus = bus or VirtualRadioBus()
        dev1 = SniffleDeviceController(port="mock://observer_ch1", mock=True, bus=shared_bus)
        dev2 = SniffleDeviceController(port="mock://observer_ch2", mock=True, bus=shared_bus)
        return cls(
            device1=dev1,
            device2=dev2,
            chan1=chan1,
            chan2=chan2,
            jitter_window_ms=jitter_window_ms,
        )

    @classmethod
    def create_hardware(
        cls,
        port1: str | None = None,
        port2: str | None = None,
        chan1: int = 37,
        chan2: int = 38,
        jitter_window_ms: float = 30.0,
    ) -> TopologyBOrchestrator:
        """Create a hardware-backed Topology B instance using auto-discovered ports."""
        dev1_port, dev2_port = allocate_dual_ports(port1, port2)
        dev1 = SniffleDeviceController(port=dev1_port, mock=False)
        dev2 = SniffleDeviceController(port=dev2_port, mock=False)
        return cls(
            device1=dev1,
            device2=dev2,
            chan1=chan1,
            chan2=chan2,
            jitter_window_ms=jitter_window_ms,
        )

    def start(self) -> None:
        """Open both devices and lock them to their respective primary channels."""
        if self.is_running:
            return

        # 1. Start Device 1 on chan1 (fixed, hop=False)
        self.device1.open()
        self.device1.start_sniffing(
            chan=self.chan1,
            hop=False,
            validate_crc=True,
            rssi_min=-128,
        )

        # 2. Start Device 2 on chan2 (fixed, hop=False)
        self.device2.open()
        self.device2.start_sniffing(
            chan=self.chan2,
            hop=False,
            validate_crc=True,
            rssi_min=-128,
        )

        self.is_running = True
        self._collector_running = True
        self._collector_thread = threading.Thread(
            target=self._merge_collector_loop,
            name="TopologyBMerger",
            daemon=True,
        )
        self._collector_thread.start()

        logger.info(
            "Topology B started: Device 1 (%s on Ch %d), Device 2 (%s on Ch %d)",
            self.device1.port,
            self.chan1,
            self.device2.port,
            self.chan2,
        )

    def stop(self) -> None:
        """Stop background collector and close both serial devices."""
        if not self.is_running:
            return

        self._collector_running = False
        with self._cond:
            self._cond.notify_all()

        if self._collector_thread and self._collector_thread.is_alive():
            self._collector_thread.join(timeout=2.0)
        self._collector_thread = None

        try:
            self.device1.close()
        except Exception as exc:
            logger.warning("Error closing Device 1: %s", exc)

        try:
            self.device2.close()
        except Exception as exc:
            logger.warning("Error closing Device 2: %s", exc)

        self.is_running = False
        logger.info("Topology B stopped cleanly.")

    @staticmethod
    def _drain_controller(dev: SniffleDeviceController) -> list[PacketMessage]:
        """Drain all currently available packets from a device controller without blocking."""
        if hasattr(dev, "drain_packets"):
            return dev.drain_packets()
        pkts: list[PacketMessage] = []
        while True:
            try:
                pkts.append(dev._packet_queue.get_nowait())
            except Exception:
                break
        return pkts

    def _merge_collector_loop(self) -> None:
        """Continuously collect packets from both devices and merge into sorted buffer."""
        while self._collector_running:
            batch1 = self._drain_controller(self.device1)
            batch2 = self._drain_controller(self.device2)

            if batch1 or batch2:
                now = time.monotonic()
                with self._cond:
                    if batch1:
                        self.packets_chan1_count += len(batch1)
                        for pkt in batch1:
                            pkt._arrival_mono = now
                            if self._last_ts1 is None or pkt.ts > self._last_ts1:
                                self._last_ts1 = pkt.ts
                        self._last_rx_mono1 = now
                        self._sorted_buffer.extend(batch1)

                    if batch2:
                        self.packets_chan2_count += len(batch2)
                        for pkt in batch2:
                            pkt._arrival_mono = now
                            if self._last_ts2 is None or pkt.ts > self._last_ts2:
                                self._last_ts2 = pkt.ts
                        self._last_rx_mono2 = now
                        self._sorted_buffer.extend(batch2)

                    self._sorted_buffer.sort(key=lambda pkt: pkt.ts)
                    self._cond.notify_all()
            else:
                time.sleep(0.002)

    def _is_releasable(self, pkt: PacketMessage, now: float) -> bool:
        """Evaluate if the oldest buffered packet is safe to release."""
        if not self._collector_running:
            return True
        arrival = getattr(pkt, "_arrival_mono", now)
        if (now - arrival) >= self.jitter_window_s:
            return True
        if self._last_ts1 is not None and self._last_ts2 is not None:
            watermark = min(self._last_ts1, self._last_ts2)
            if pkt.ts <= watermark:
                return True
        return False

    def read_merged_packet(self, timeout: float = 1.0) -> PacketMessage | None:
        """Retrieve the next timestamp-ordered packet from the dual-channel stream."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._collector_running:
                now = time.monotonic()
                if self._sorted_buffer and self._is_releasable(self._sorted_buffer[0], now):
                    self.merged_packets_total += 1
                    return self._sorted_buffer.pop(0)

                remaining = deadline - now
                if remaining <= 0:
                    break

                if self._sorted_buffer:
                    candidate = self._sorted_buffer[0]
                    arrival = getattr(candidate, "_arrival_mono", now)
                    candidate_wait = max(0.001, (arrival + self.jitter_window_s) - now)
                    wait_time = min(0.02, remaining, candidate_wait)
                else:
                    wait_time = min(0.02, remaining)

                self._cond.wait(timeout=wait_time)

            if not self._collector_running and self._sorted_buffer:
                self.merged_packets_total += 1
                return self._sorted_buffer.pop(0)

            return None

    def get_merged_packets(self, max_count: int = 100, timeout: float = 0.1) -> list[PacketMessage]:
        """Retrieve up to `max_count` timestamp-ordered packets from the merged stream."""
        packets: list[PacketMessage] = []
        deadline = time.monotonic() + timeout
        while len(packets) < max_count:
            remaining = max(0.0, deadline - time.monotonic())
            pkt = self.read_merged_packet(timeout=min(0.02, remaining))
            if pkt is not None:
                packets.append(pkt)
            else:
                if time.monotonic() >= deadline:
                    break
        return packets

    def get_stats(self) -> dict[str, Any]:
        """Return operational statistics for Topology B."""
        return {
            "topology": "Topology B (Dual-Channel Passive Observer)",
            "is_running": self.is_running,
            "device1_port": self.device1.port,
            "device2_port": self.device2.port,
            "chan1": self.chan1,
            "chan2": self.chan2,
            "packets_chan1": self.packets_chan1_count,
            "packets_chan2": self.packets_chan2_count,
            "merged_packets_total": self.merged_packets_total,
        }
