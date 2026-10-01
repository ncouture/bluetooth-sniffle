"""Bluetooth Sniffle Testbed Framework

Dual-device Sniffle orchestration, active beacon synthesis, passive sniffing,
and protocol analysis for Bluetooth Low Energy tracking research (PoPETs 2025-0103).
"""

from bluetooth_sniffle.device import (
    MockSerialInterface,
    SniffleDeviceController,
    VirtualRadioBus,
)
from bluetooth_sniffle.topology import (
    ShutdownCoordinator,
    TopologyAOrchestrator,
    TopologyBOrchestrator,
)

__version__ = "0.1.0"

__all__ = [
    "MockSerialInterface",
    "ShutdownCoordinator",
    "SniffleDeviceController",
    "TopologyAOrchestrator",
    "TopologyBOrchestrator",
    "VirtualRadioBus",
    "__version__",
]

