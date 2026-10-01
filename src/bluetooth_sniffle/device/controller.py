"""High-level Sniffle device controller.

Manages connection state, advertising injection, passive sniffing, active scanning,
and packet queuing across physical serial interfaces and simulated mock devices.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import types
from collections.abc import Sequence
from struct import pack
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.device.serial_port import open_sniffle_serial
from bluetooth_sniffle.protocol.mac import str_to_mac
from bluetooth_sniffle.protocol.wire import (
    BLE_ADV_AA,
    BLE_ADV_CRC_INIT,
    COMMAND_ADVERTISE,
    COMMAND_ADVHOP,
    COMMAND_ADVINTRVL,
    COMMAND_CRC_VALID,
    COMMAND_MARKER,
    COMMAND_RESET,
    COMMAND_RSSIFILT,
    COMMAND_SCAN,
    COMMAND_SETADDR,
    COMMAND_SETCHANAAPHY,
    COMMAND_TX_POWER,
    COMMAND_VERSION,
    MESSAGE_BLEFRAME,
    MESSAGE_MARKER,
    MESSAGE_MEASURE,
    MESSAGE_STATE,
    PHY_1M,
    MarkerMessage,
    MeasurementMessage,
    PacketMessage,
    StateMessage,
    encode_cmd,
    parse_sniffle_message,
)

logger = logging.getLogger(__name__)


class SniffleDeviceController:
    """Controller for a single Sniffle radio dongle (physical or mock)."""

    def __init__(
        self,
        port: str | None = None,
        baudrate: int = 2_000_000,
        ser: Any | None = None,
        mock: bool = False,
        bus: VirtualRadioBus | None = None,
        timeout: float = 1.0,
    ) -> None:
        self.port: str | None = port
        self.baudrate: int = baudrate
        self.timeout: float = timeout
        self.mock: bool = mock or (port is not None and port.startswith("mock://"))
        self.bus: VirtualRadioBus | None = bus
        self.ser: Any | None = ser

        # Internal state
        self.is_open: bool = False
        self.is_sniffing: bool = False
        self.is_advertising: bool = False
        self.is_scanning: bool = False
        self.channel: int = 37
        self.mac_address: bytes | None = None
        self.is_random_mac: bool = True
        self.adv_interval_ms: int = 100
        self.tx_power: int = 5

        # Asynchronous queues
        self._packet_queue: queue.Queue[PacketMessage] = queue.Queue()
        self._marker_queue: queue.Queue[MarkerMessage] = queue.Queue()
        self._measure_queue: queue.Queue[MeasurementMessage] = queue.Queue()
        self._state_queue: queue.Queue[StateMessage] = queue.Queue()

        # Threading
        self._reader_thread: threading.Thread | None = None
        self._running: bool = False
        self._lock: threading.Lock = threading.Lock()

    def open(self) -> None:
        """Open the serial port and start the asynchronous reader thread."""
        with self._lock:
            if self.is_open:
                return

            if self.ser is None:
                if self.mock:
                    port_name = self.port or "mock://sniffle"
                    self.ser = MockSerialInterface(
                        port=port_name,
                        baudrate=self.baudrate,
                        timeout=self.timeout,
                        bus=self.bus,
                    )
                else:
                    if not self.port:
                        raise ValueError("Physical serial port path must be specified when mock=False")
                    self.ser = open_sniffle_serial(
                        port=self.port,
                        baudrate=self.baudrate,
                        timeout=self.timeout,
                    )

            self.is_open = True
            self._running = True
            self._reader_thread = threading.Thread(
                target=self._reader_loop,
                name=f"SniffleReader-{self.port or 'mock'}",
                daemon=True,
            )
            self._reader_thread.start()

    def close(self, reset: bool = False) -> None:
        """Stop background worker threads and close serial connection."""
        with self._lock:
            if not self.is_open:
                return
            self._running = False
            self.is_sniffing = False
            self.is_advertising = False
            self.is_scanning = False

            if reset and self.ser is not None:
                try:
                    self.ser.write(encode_cmd([COMMAND_RESET]))
                except (OSError, RuntimeError):
                    pass

            if self.ser is not None:
                # Cancel read if supported
                if hasattr(self.ser, "cancel_read"):
                    try:
                        self.ser.cancel_read()
                    except (OSError, RuntimeError):
                        pass
                try:
                    self.ser.close()
                except (OSError, RuntimeError):
                    pass

        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=2.0)
        self._reader_thread = None
        self.is_open = False

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.close()

    def send_command(self, cmd_bytes: Sequence[int] | bytes) -> None:
        """Send a raw command to the device over the wire protocol."""
        if not self.is_open or self.ser is None:
            raise RuntimeError("Cannot send command: device is not open")
        wire_frame = encode_cmd(cmd_bytes)
        self.ser.write(wire_frame)

    def _reader_loop(self) -> None:
        """Background thread continuously reading wire frames from serial port."""
        while self._running and self.ser is not None:
            try:
                line = self.ser.readline()
            except (OSError, RuntimeError):
                break

            if not self._running:
                break
            if not line:
                continue

            try:
                msg_type, msg_obj = parse_sniffle_message(line)
            except ValueError:
                continue

            if msg_type == MESSAGE_BLEFRAME and isinstance(msg_obj, PacketMessage):
                self._packet_queue.put(msg_obj)
            elif msg_type == MESSAGE_MARKER and isinstance(msg_obj, MarkerMessage):
                self._marker_queue.put(msg_obj)
            elif msg_type == MESSAGE_MEASURE and isinstance(msg_obj, MeasurementMessage):
                self._measure_queue.put(msg_obj)
            elif msg_type == MESSAGE_STATE and isinstance(msg_obj, StateMessage):
                self._state_queue.put(msg_obj)

    # -------------------------------------------------------------------------
    # Hardware Commands & Configuration
    # -------------------------------------------------------------------------
    def set_mac_address(self, mac: bytes | str, is_random: bool = True) -> None:
        """Configure local MAC address for advertising, scanning, and initiating.

        Args:
            mac: 6-byte MAC address or string representation.
            is_random: True for Random Static / NRPA / RPA, False for Public.
        """
        mac_bytes = str_to_mac(mac) if isinstance(mac, str) else bytes(mac)
        if len(mac_bytes) != 6:
            raise ValueError(f"MAC address must be exactly 6 bytes (got {len(mac_bytes)})")

        self.send_command([COMMAND_SETADDR, 1 if is_random else 0, *mac_bytes])
        self.mac_address = mac_bytes
        self.is_random_mac = is_random

    def set_tx_power(self, power_dbm: int = 5) -> None:
        """Configure radio transmission output power in dBm."""
        if not (-20 <= power_dbm <= 10):
            raise ValueError(f"TX power {power_dbm} dBm out of valid range [-20, 10]")
        self.send_command([COMMAND_TX_POWER, power_dbm & 0xFF])
        self.tx_power = power_dbm

    def configure_advertising(
        self,
        adv_data: bytes,
        scan_rsp_data: bytes = b"",
        interval_ms: int = 100,
        mode: int = 2,
    ) -> None:
        """Configure and start legacy BLE advertising on primary channels (37, 38, 39).

        Args:
            adv_data: Primary advertising payload (AD structures, max 31 bytes).
            scan_rsp_data: Scan response payload (max 31 bytes).
            interval_ms: Advertising interval in ms (20 to 65535 ms).
            mode: 0 = connectable (ADV_IND), 2 = non-connectable (ADV_NONCONN_IND),
                  3 = scannable (ADV_SCAN_IND).
        """
        if len(adv_data) > 31:
            raise ValueError(f"adv_data exceeds 31 bytes (got {len(adv_data)})")
        if len(scan_rsp_data) > 31:
            raise ValueError(f"scan_rsp_data exceeds 31 bytes (got {len(scan_rsp_data)})")
        if mode not in (0, 2, 3):
            raise ValueError("Mode must be 0 (connectable), 2 (non-connectable), or 3 (scannable)")
        if not (20 <= interval_ms <= 0xFFFF):
            raise ValueError(f"Advertising interval {interval_ms} ms out of bounds [20, 65535]")

        # 1. Set interval
        self.send_command([COMMAND_ADVINTRVL, interval_ms & 0xFF, (interval_ms >> 8) & 0xFF])
        self.adv_interval_ms = interval_ms

        # 2. Padded advertising structures
        padded_adv = [len(adv_data), *adv_data] + [0] * (31 - len(adv_data))
        padded_scan = [len(scan_rsp_data), *scan_rsp_data] + [0] * (31 - len(scan_rsp_data))

        self.send_command([COMMAND_ADVERTISE, mode, *padded_adv, *padded_scan])
        self.is_advertising = True

    def start_sniffing(
        self,
        chan: int = 37,
        hop: bool = False,
        validate_crc: bool = True,
        rssi_min: int = -128,
    ) -> None:
        """Configure radio to passively sniff BLE advertising packets.

        Args:
            chan: Primary advertising channel (37, 38, 39) or data channel (0-36).
            hop: If True, hops between 37, 38, 39.
            validate_crc: If True, drops frames with invalid CRC.
            rssi_min: Minimum RSSI threshold in dBm.
        """
        if not (0 <= chan <= 39):
            raise ValueError(f"Channel {chan} out of range [0, 39]")

        # Set channel, access address, phy, crc init
        chan_args = list(pack("<BLBL", chan, BLE_ADV_AA, PHY_1M, BLE_ADV_CRC_INIT))
        self.send_command([COMMAND_SETCHANAAPHY, *chan_args])

        if hop:
            self.send_command([COMMAND_ADVHOP])

        self.send_command([COMMAND_CRC_VALID, 1 if validate_crc else 0])
        self.send_command([COMMAND_RSSIFILT, rssi_min & 0xFF])

        self.channel = chan
        self.is_sniffing = True

    def start_scanning(self) -> None:
        """Switch device to active scanning mode (transmitting SCAN_REQ)."""
        self.send_command([COMMAND_SCAN])
        self.is_scanning = True

    def read_packet(self, timeout: float = 1.0) -> PacketMessage | None:
        """Retrieve the next received packet from the incoming queue.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            PacketMessage or None if timeout expired.
        """
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def read_packets_batch(self, max_count: int = 100, timeout: float = 0.1) -> list[PacketMessage]:
        """Retrieve up to `max_count` packets currently available in the queue."""
        packets: list[PacketMessage] = []
        deadline = time.monotonic() + timeout
        while len(packets) < max_count:
            remaining = max(0.0, deadline - time.monotonic())
            pkt = self.read_packet(timeout=min(0.02, remaining))
            if pkt is not None:
                packets.append(pkt)
            else:
                if time.monotonic() >= deadline:
                    break
        return packets

    def drain_packets(self, max_count: int | None = None) -> list[PacketMessage]:
        """Drain all currently available packets from the queue without blocking.

        Args:
            max_count: Maximum number of packets to drain (None for all available).

        Returns:
            List of drained PacketMessage instances.
        """
        packets: list[PacketMessage] = []
        while max_count is None or len(packets) < max_count:
            try:
                packets.append(self._packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def mark_and_flush(self, timeout: float = 1.0) -> bool:
        """Synchronize with the device using a random marker token and flush stale packets."""
        token = os.urandom(4)
        self.send_command([COMMAND_MARKER, *token])

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                remaining = max(0.01, deadline - time.monotonic())
                marker = self._marker_queue.get(timeout=remaining)
                if marker.marker_data == token:
                    # Clear out stale packets accumulated before marker
                    while not self._packet_queue.empty():
                        try:
                            self._packet_queue.get_nowait()
                        except queue.Empty:
                            break
                    return True
            except queue.Empty:
                break
        return False

    def get_firmware_version(self, timeout: float = 1.0) -> tuple[int, int, int, int] | None:
        """Query firmware version from the device.

        Returns:
            tuple (major, minor, revision, api_level) or None on timeout.
        """
        self.send_command([COMMAND_VERSION])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                remaining = max(0.01, deadline - time.monotonic())
                meas = self._measure_queue.get(timeout=remaining)
                if meas.version is not None:
                    return meas.version
            except queue.Empty:
                break
        return None
