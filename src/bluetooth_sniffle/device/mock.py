"""In-memory mock serial interface and virtual radio bus.

Provides a thread-safe simulation harness emulating physical Sniffle dongles
and over-the-air BLE radio transmission for offline unit and integration testing.
"""

from __future__ import annotations

import logging
import threading
import time

from bluetooth_sniffle.protocol.wire import (
    COMMAND_ADVERTISE,
    COMMAND_ADVHOP,
    COMMAND_ADVINTRVL,
    COMMAND_CRC_VALID,
    COMMAND_FOLLOW,
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
    STATE_ADVERTISING,
    STATE_SCANNING,
    STATE_STATIC,
    MarkerMessage,
    MeasurementMessage,
    PacketMessage,
    StateMessage,
    decode_cmd,
    encode_msg,
)

logger = logging.getLogger(__name__)


class MockSerialInterface:
    """Pure-Python in-memory mock serial interface emulating PySerial Serial."""

    def __init__(
        self,
        port: str = "mock://sniffle",
        baudrate: int = 2_000_000,
        timeout: float | None = 1.0,
        bus: VirtualRadioBus | None = None,
    ) -> None:
        self.port: str = port
        self.baudrate: int = baudrate
        self.timeout: float | None = timeout
        self.is_open: bool = True
        self.bus: VirtualRadioBus | None = bus

        self._rx_buffer: bytearray = bytearray()
        self._tx_buffer: bytearray = bytearray()
        self._lock: threading.Lock = threading.Lock()
        self._cond: threading.Condition = threading.Condition(self._lock)
        self._cancelled: bool = False

        if self.bus is not None:
            self.bus.register_device(self)

    @property
    def in_waiting(self) -> int:
        """Number of bytes currently available in receive buffer."""
        with self._lock:
            return len(self._rx_buffer)

    def open(self) -> None:
        """Open the mock serial interface."""
        with self._lock:
            self.is_open = True
            self._cancelled = False

    def close(self) -> None:
        """Close the mock serial interface and wake up any waiting readers."""
        with self._cond:
            self.is_open = False
            self._cancelled = True
            self._cond.notify_all()

    def cancel_read(self) -> None:
        """Cancel any ongoing blocking read operations."""
        with self._cond:
            self._cancelled = True
            self._cond.notify_all()

    def reset_input_buffer(self) -> None:
        """Flush the receive buffer."""
        with self._lock:
            self._rx_buffer.clear()

    def reset_output_buffer(self) -> None:
        """Flush the transmit buffer."""
        with self._lock:
            self._tx_buffer.clear()

    def flush(self) -> None:
        """No-op for in-memory stream compatibility."""

    def inject_rx_bytes(self, data: bytes) -> None:
        """Inject raw bytes into the device's receive buffer (dongle-to-host)."""
        with self._cond:
            self._rx_buffer.extend(data)
            self._cond.notify_all()

    def inject_message(self, msg_type: int, msg_body: bytes) -> None:
        """Encode and inject a dongle-to-host message frame."""
        wire_frame = encode_msg(msg_type, msg_body)
        self.inject_rx_bytes(wire_frame)

    def write(self, data: bytes) -> int:
        """Accept host-to-dongle data, parsing complete Base64 lines."""
        if not self.is_open:
            raise RuntimeError("Cannot write to closed serial interface")

        with self._lock:
            self._tx_buffer.extend(data)

        # Process complete lines terminated by \n
        while True:
            with self._lock:
                idx = self._tx_buffer.find(b"\n")
                if idx == -1:
                    break
                line = bytes(self._tx_buffer[: idx + 1])
                del self._tx_buffer[: idx + 1]

            self._process_command_line(line)

        return len(data)

    def _process_command_line(self, line: bytes) -> None:
        """Decode and handle a host command line."""
        try:
            _, opcode, args = decode_cmd(line)
        except ValueError:
            return

        if self.bus is not None:
            self.bus.handle_command(self, bytes([opcode, *args]))

    def read(self, size: int = 1) -> bytes:
        """Read up to `size` bytes from receive buffer, respecting timeout."""
        if size <= 0:
            return b""

        deadline = None
        if self.timeout is not None and self.timeout > 0:
            deadline = time.monotonic() + self.timeout

        with self._cond:
            self._cancelled = False
            while self.is_open and not self._cancelled and len(self._rx_buffer) < size:
                if self.timeout == 0:
                    break
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._cond.wait(timeout=remaining)
                else:
                    self._cond.wait()

            if not self.is_open or self._cancelled:
                return b""

            chunk_len = min(size, len(self._rx_buffer))
            result = bytes(self._rx_buffer[:chunk_len])
            del self._rx_buffer[:chunk_len]
            return result

    def readline(self) -> bytes:
        """Read a single line terminated by \\n, respecting timeout."""
        deadline = None
        if self.timeout is not None and self.timeout > 0:
            deadline = time.monotonic() + self.timeout

        with self._cond:
            self._cancelled = False
            while self.is_open and not self._cancelled:
                idx = self._rx_buffer.find(b"\n")
                if idx != -1:
                    result = bytes(self._rx_buffer[: idx + 1])
                    del self._rx_buffer[: idx + 1]
                    return result

                if self.timeout == 0:
                    break
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._cond.wait(timeout=remaining)
                else:
                    self._cond.wait()

            if not self.is_open or self._cancelled:
                return b""

            # Return whatever is left if timeout expired
            result = bytes(self._rx_buffer)
            self._rx_buffer.clear()
            return result


class DeviceRadioState:
    """State tracking for a simulated Sniffle radio dongle on the virtual bus."""

    def __init__(self) -> None:
        self.channel: int = 37
        self.hop3: bool = False
        self.state: int = STATE_STATIC
        self.mac_addr: bytes = bytes(6)
        self.mac_is_random: bool = True
        self.adv_interval_ms: int = 100
        self.adv_mode: int = 2
        self.adv_data: bytes = b""
        self.scan_rsp_data: bytes = b""
        self.rssi_filter: int = -128
        self.validate_crc: bool = True
        self.tx_power: int = 5
        self.follow_conns: bool = False


class VirtualRadioBus:
    """In-memory radio bus linking simulated Sniffle dongles.

    Routes transmitted advertisements and active scan frames between mock dongles,
    respecting channel tuning, RSSI thresholds, and firmware responses.
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._devices: dict[MockSerialInterface, DeviceRadioState] = {}
        self._simulated_clock_us: int = 1_000_000

    def register_device(self, dev: MockSerialInterface) -> None:
        """Attach a mock serial device to the virtual bus."""
        with self._lock:
            if dev not in self._devices:
                self._devices[dev] = DeviceRadioState()

    def unregister_device(self, dev: MockSerialInterface) -> None:
        """Detach a mock serial device from the virtual bus."""
        with self._lock:
            self._devices.pop(dev, None)

    def get_state(self, dev: MockSerialInterface) -> DeviceRadioState | None:
        """Get the radio state for a given mock device."""
        with self._lock:
            return self._devices.get(dev)

    def _now_us(self) -> int:
        """Return simulated microsecond timestamp."""
        with self._lock:
            self._simulated_clock_us += 1000
            return self._simulated_clock_us & 0xFFFFFFFF

    def handle_command(self, sender: MockSerialInterface, cmd_body: bytes) -> None:
        """Process a decoded command body received from a mock device."""
        if not cmd_body:
            return

        opcode = cmd_body[0]
        args = cmd_body[1:]

        with self._lock:
            st = self._devices.get(sender)
            if st is None:
                st = DeviceRadioState()
                self._devices[sender] = st

        # 0x18: COMMAND_MARKER
        if opcode == COMMAND_MARKER:
            ts = self._now_us()
            resp = MarkerMessage.pack(args, ts=ts)
            sender.inject_message(MESSAGE_MARKER, resp)
            return

        # 0x24: COMMAND_VERSION
        if opcode == COMMAND_VERSION:
            resp = MeasurementMessage.pack_version(major=1, minor=8, revision=0, api_level=1)
            sender.inject_message(MESSAGE_MEASURE, resp)
            return

        # 0x10: COMMAND_SETCHANAAPHY
        if opcode == COMMAND_SETCHANAAPHY:
            if len(args) >= 1:
                st.channel = args[0]
            st.state = STATE_STATIC
            sender.inject_message(MESSAGE_STATE, StateMessage.pack(STATE_STATIC))
            return

        # 0x14: COMMAND_ADVHOP
        if opcode == COMMAND_ADVHOP:
            st.hop3 = True
            return

        # 0x1B: COMMAND_SETADDR
        if opcode == COMMAND_SETADDR:
            if len(args) >= 7:
                st.mac_is_random = bool(args[0])
                st.mac_addr = args[1:7]
            return

        # 0x1D: COMMAND_ADVINTRVL
        if opcode == COMMAND_ADVINTRVL:
            if len(args) >= 2:
                st.adv_interval_ms = args[0] | (args[1] << 8)
            return

        # 0x27: COMMAND_TX_POWER
        if opcode == COMMAND_TX_POWER:
            if len(args) >= 1:
                st.tx_power = int.from_bytes(args[:1], byteorder="little", signed=True)
            return

        # 0x12: COMMAND_RSSIFILT
        if opcode == COMMAND_RSSIFILT:
            if len(args) >= 1:
                st.rssi_filter = int.from_bytes(args[:1], byteorder="little", signed=True)
            return

        # 0x26: COMMAND_CRC_VALID
        if opcode == COMMAND_CRC_VALID:
            if len(args) >= 1:
                st.validate_crc = bool(args[0])
            return

        # 0x15: COMMAND_FOLLOW
        if opcode == COMMAND_FOLLOW:
            if len(args) >= 1:
                st.follow_conns = bool(args[0])
            return

        # 0x17: COMMAND_RESET
        if opcode == COMMAND_RESET:
            with self._lock:
                self._devices[sender] = DeviceRadioState()
            return

        # 0x22: COMMAND_SCAN
        if opcode == COMMAND_SCAN:
            st.state = STATE_SCANNING
            sender.inject_message(MESSAGE_STATE, StateMessage.pack(STATE_SCANNING))
            return

        # 0x1C: COMMAND_ADVERTISE
        if opcode == COMMAND_ADVERTISE:
            # Layout: [mode:1] + [adv_len:1, 31B adv] + [scan_len:1, 31B scan_rsp]
            if len(args) >= 1:
                st.adv_mode = args[0]
            if len(args) >= 33:
                adv_len = args[1]
                st.adv_data = args[2 : 2 + adv_len]
            if len(args) >= 65:
                scan_len = args[33]
                st.scan_rsp_data = args[34 : 34 + scan_len]

            st.state = STATE_ADVERTISING
            sender.inject_message(MESSAGE_STATE, StateMessage.pack(STATE_ADVERTISING))

            # Trigger an immediate broadcast over the air
            self.broadcast_advertisement(sender)

    def broadcast_advertisement(
        self,
        sender: MockSerialInterface,
        channels: tuple[int, ...] = (37, 38, 39),
        rssi: int = -60,
    ) -> None:
        """Synthesize and broadcast an advertising PDU from sender to listening devices."""
        with self._lock:
            st = self._devices.get(sender)
            if st is None:
                return
            adv_data = st.adv_data
            mac_addr = st.mac_addr
            is_random = st.mac_is_random
            mode = st.adv_mode

        # Determine PDU type:
        # Mode 0 -> ADV_IND (0x00)
        # Mode 2 -> ADV_NONCONN_IND (0x02)
        # Mode 3 -> ADV_SCAN_IND (0x06)
        pdu_type = 0x02 if mode == 2 else (0x06 if mode == 3 else 0x00)
        tx_add = 1 if is_random else 0
        header_byte = (pdu_type & 0x0F) | ((tx_add & 1) << 6)
        payload_len = 6 + len(adv_data)
        pdu = bytes([header_byte, payload_len]) + mac_addr + adv_data

        # Deliver to listening devices
        for chan in channels:
            self.deliver_raw_packet(
                pdu=pdu,
                chan=chan,
                rssi=rssi,
                exclude_device=sender,
            )

    def deliver_raw_packet(
        self,
        pdu: bytes,
        chan: int,
        rssi: int = -60,
        phy: int = PHY_1M,
        exclude_device: MockSerialInterface | None = None,
        crc_err: bool = False,
    ) -> None:
        """Deliver a raw BLE packet to any registered devices currently listening on `chan`."""
        ts = self._now_us()
        with self._lock:
            targets = list(self._devices.items())

        for dev, st in targets:
            if dev is exclude_device:
                continue
            if not dev.is_open:
                continue

            # Check if device is listening on this channel
            # A device listens if locked to `chan`, or if `hop3` is active and chan in (37, 38, 39)
            channel_match = (st.channel == chan) or (st.hop3 and chan in (37, 38, 39))
            if not channel_match:
                continue

            # Check RSSI threshold
            if rssi < st.rssi_filter:
                continue

            # Check CRC validation setting
            if crc_err and st.validate_crc:
                continue

            packet_msg = PacketMessage.pack(
                body=pdu,
                ts=ts,
                chan=chan,
                rssi=rssi,
                phy=phy,
                crc_err=crc_err,
            )
            dev.inject_message(MESSAGE_BLEFRAME, packet_msg)
