"""Device management, serial communication, and mock hardware emulation package."""

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import (
    DeviceRadioState,
    MockSerialInterface,
    VirtualRadioBus,
)
from bluetooth_sniffle.device.serial_port import (
    DEFAULT_BAUDRATE,
    allocate_dual_ports,
    detect_optimal_baudrate,
    discover_sniffle_ports,
    mark_and_flush,
    open_sniffle_serial,
)

__all__ = [
    "DEFAULT_BAUDRATE",
    "DeviceRadioState",
    "MockSerialInterface",
    "SniffleDeviceController",
    "VirtualRadioBus",
    "allocate_dual_ports",
    "detect_optimal_baudrate",
    "discover_sniffle_ports",
    "mark_and_flush",
    "open_sniffle_serial",
]
