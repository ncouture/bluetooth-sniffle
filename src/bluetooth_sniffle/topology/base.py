"""Base topology interface and abstraction for Sniffle testbed setups."""

from __future__ import annotations

import abc
import sys
import types
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from bluetooth_sniffle.device.controller import SniffleDeviceController


class BaseTopology(abc.ABC):
    """Abstract base class defining orchestration topology lifecycle and metrics."""

    def __init__(
        self,
        device1: SniffleDeviceController,
        device2: SniffleDeviceController,
    ) -> None:
        self.device1: SniffleDeviceController = device1
        self.device2: SniffleDeviceController = device2
        self.is_running: bool = False

    @abc.abstractmethod
    def start(self) -> None:
        """Initialize and start all device controllers in this topology."""
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self) -> None:
        """Gracefully terminate controllers and release hardware resources."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_stats(self) -> dict[str, Any]:
        """Return operational telemetry and packet statistics for this topology."""
        raise NotImplementedError

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.stop()

