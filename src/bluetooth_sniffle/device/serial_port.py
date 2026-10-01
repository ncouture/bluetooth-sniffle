"""Serial port discovery, baud rate negotiation, and hardware lifecycle management.

Handles auto-detection for Sonoff Zigbee Dongle Plus (CC2652P), TI XDS110 Debuggers,
and CatSniffer V3 devices, allocating non-conflicting ports for dual-device topologies.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import serial
import serial.tools.list_ports

from bluetooth_sniffle.protocol.wire import (
    COMMAND_MARKER,
    MESSAGE_MARKER,
    MarkerMessage,
    decode_msg,
    encode_cmd,
)

logger = logging.getLogger(__name__)

# Known Sniffle Hardware USB Vendor & Product IDs
SONOFF_VID: int = 0x10C4
SONOFF_PID: int = 0xEA60

TI_XDS110_VID: int = 0x0451
TI_XDS110_PID: int = 0xBEF3

CATSNIFFER_VID: int = 0x2E8A
CATSNIFFER_PID: int = 0x00C0

DEFAULT_BAUDRATE: int = 2_000_000
CP2102_FALLBACK_BAUDRATE: int = 921_600


def is_sniffle_device(port_info: Any) -> bool:
    """Determine if a serial port corresponds to a supported Sniffle radio dongle."""
    vid = getattr(port_info, "vid", None)
    pid = getattr(port_info, "pid", None)
    desc = (getattr(port_info, "description", "") or "").lower()
    prod = (getattr(port_info, "product", "") or "").lower()

    # 1. TI CC26x2 / CC1352 LaunchPad XDS110
    if vid == TI_XDS110_VID and pid == TI_XDS110_PID:
        return True

    # 2. Sonoff Zigbee 3.0 USB Dongle Plus (CP2102 / CP2102N)
    if vid == SONOFF_VID and pid == SONOFF_PID:
        if any(term in desc or term in prod for term in ["sonoff", "silicon labs", "cp210", "uart bridge", "itead"]):
            return True
        return True

    # 3. Electronic Cats CatSniffer V3 (RP2040 / CC1352)
    if vid == CATSNIFFER_VID and pid == CATSNIFFER_PID:
        return True
    return bool("catsniffer" in desc or "catsniffer" in prod)


def is_cp2102_non_n(port_info: Any) -> bool:
    """Check if the hardware bridge is a CP2102 (non-N) limited to 921,600 baud."""
    desc = (getattr(port_info, "description", "") or "").lower()
    prod = (getattr(port_info, "product", "") or "").lower()
    text = f"{desc} {prod}"
    if "cp2102n" in text:
        return False
    return bool("cp2102" in text or "sonoff" in text)


def discover_sniffle_ports() -> list[str]:
    """Scan and return a list of available serial device paths for Sniffle hardware.

    Returns:
        List of matching port paths (e.g. ['/dev/ttyUSB0', '/dev/ttyUSB1']).
    """
    found_ports: list[str] = []
    for port in serial.tools.list_ports.comports():
        if is_sniffle_device(port):
            found_ports.append(port.device)
    return list(dict.fromkeys(found_ports))


def detect_optimal_baudrate(port_name: str) -> int:
    """Determine optimal baud rate for a serial port, capping at 921,600 for CP2102.

    Args:
        port_name: Serial device path (e.g. '/dev/ttyUSB0').

    Returns:
        Optimal baud rate (2,000,000 or 921,600).
    """
    for port in serial.tools.list_ports.comports():
        if port.device == port_name:
            if is_cp2102_non_n(port):
                logger.info(
                    "CP2102 non-N bridge detected on %s; capping baud to %d",
                    port_name,
                    CP2102_FALLBACK_BAUDRATE,
                )
                return CP2102_FALLBACK_BAUDRATE
            break
    return DEFAULT_BAUDRATE


def allocate_dual_ports(
    dev1: str | None = None,
    dev2: str | None = None,
) -> tuple[str, str]:
    """Allocate distinct, non-conflicting serial ports for Device 1 and Device 2.

    Args:
        dev1: Optional explicit path for Device 1.
        dev2: Optional explicit path for Device 2.

    Returns:
        tuple (port1, port2) ensuring port1 != port2.

    Raises:
        ValueError: If both ports are explicitly specified as identical.
        RuntimeError: If insufficient physical Sniffle devices are found.
    """
    if dev1 and dev2:
        if dev1 == dev2:
            raise ValueError(f"Conflicting port allocation: Device 1 and Device 2 cannot share port {dev1!r}")
        return dev1, dev2

    available = list(dict.fromkeys(discover_sniffle_ports()))

    if dev1 and not dev2:
        candidates = [p for p in available if p != dev1]
        if not candidates:
            raise RuntimeError(
                f"Device 1 assigned to {dev1}, but no distinct secondary Sniffle port was found. "
                f"Available ports: {available}. (Use mock mode for offline simulation)."
            )
        return dev1, candidates[0]

    if dev2 and not dev1:
        candidates = [p for p in available if p != dev2]
        if not candidates:
            raise RuntimeError(
                f"Device 2 assigned to {dev2}, but no distinct primary Sniffle port was found. "
                f"Available ports: {available}. (Use mock mode for offline simulation)."
            )
        return candidates[0], dev2

    # Neither specified
    if len(available) < 2:
        raise RuntimeError(
            f"Dual-device topology requires 2 Sniffle dongles, but only {len(available)} detected: {available}. "
            "Connect both dongles or run with mock simulation mode."
        )

    port1, port2 = available[0], available[1]
    if port1 == port2:
        raise RuntimeError(f"Conflicting ports allocated: {port1!r} == {port2!r}")
    return port1, port2


def mark_and_flush(ser: Any, timeout: float = 1.0) -> bool:
    """Synchronize with Sniffle dongle and flush stale buffer contents.

    Sends COMMAND_MARKER with a random 4-byte token and waits for an echoing
    MESSAGE_MARKER containing that token.

    Args:
        ser: PySerial instance or MockSerialInterface.
        timeout: Maximum seconds to wait for echo.

    Returns:
        True if synchronization succeeded, False otherwise.
    """
    token = os.urandom(4)
    cmd = encode_cmd([COMMAND_MARKER, *token])

    try:
        ser.write(cmd)
    except (OSError, RuntimeError) as exc:
        logger.error("Failed to write sync marker to port: %s", exc)
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            line = ser.readline()
        except (OSError, RuntimeError):
            break

        if not line:
            time.sleep(0.01)
            continue

        try:
            _, msg_type, msg_body = decode_msg(line)
        except ValueError:
            continue

        if msg_type == MESSAGE_MARKER:
            try:
                marker = MarkerMessage(msg_body)
                if marker.marker_data == token:
                    return True
            except ValueError:
                logger.debug("Failed to decode marker payload, continuing...")
                continue

    logger.warning("Marker sync timed out after %.2f seconds", timeout)
    return False


def open_sniffle_serial(
    port: str,
    baudrate: int | None = None,
    timeout: float = 1.0,
) -> serial.Serial:
    """Open and configure a physical serial port for Sniffle communication.

    Args:
        port: Device port name (e.g. '/dev/ttyUSB0').
        baudrate: Optional baud rate. Defaults to auto-detected optimal rate.
        timeout: Read timeout in seconds.

    Returns:
        Configured and opened serial.Serial instance.
    """
    selected_baud = baudrate or detect_optimal_baudrate(port)
    ser = serial.Serial(
        port=port,
        baudrate=selected_baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        rtscts=False,
        dsrdtr=False,
        timeout=timeout,
    )
    return ser
