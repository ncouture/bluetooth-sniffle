"""Process and thread lifecycle management and graceful shutdown coordination.

Safely handles SIGINT / SIGTERM signals, terminates background reader threads,
closes physical serial ports, and prevents hardware lockups or orphaned threads.
"""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class ShutdownCoordinator:
    """Coordinates graceful shutdown across background threads and serial hardware."""

    _instance: ShutdownCoordinator | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._callbacks: list[Callable[[], Any]] = []
        self._shutdown_event: threading.Event = threading.Event()
        self._is_shutting_down: bool = False
        self._handlers_installed: bool = False

    @classmethod
    def get_instance(cls) -> ShutdownCoordinator:
        """Obtain the global shutdown coordinator singleton."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @property
    def is_shutting_down(self) -> bool:
        """Return True if shutdown has been initiated."""
        return self._shutdown_event.is_set()

    def register(self, callback: Callable[[], Any]) -> None:
        """Register a cleanup callback to be invoked during shutdown.

        Callbacks are invoked in LIFO (last-in, first-out) order.
        """
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def unregister(self, callback: Callable[[], Any]) -> None:
        """Remove a previously registered cleanup callback."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def install_signal_handlers(self) -> None:
        """Attach signal handlers for SIGINT and SIGTERM."""
        with self._lock:
            if self._handlers_installed:
                return

            # Signal handling only works from main thread
            if threading.current_thread() is threading.main_thread():
                try:
                    signal.signal(signal.SIGINT, self._handle_signal)
                    signal.signal(signal.SIGTERM, self._handle_signal)
                    self._handlers_installed = True
                    logger.debug("ShutdownCoordinator signal handlers installed.")
                except (ValueError, AttributeError) as exc:
                    logger.warning("Could not register signal handlers: %s", exc)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Signal callback triggering coordinator shutdown."""
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received shutdown signal %s, initiating graceful cleanup...", sig_name)
        self.shutdown()

    def shutdown(self) -> None:
        """Execute all registered cleanup callbacks in reverse order."""
        with self._lock:
            if self._is_shutting_down:
                return
            self._is_shutting_down = True
            self._shutdown_event.set()
            callbacks_to_run = list(reversed(self._callbacks))

        logger.info("Executing %d cleanup handlers...", len(callbacks_to_run))
        for cb in callbacks_to_run:
            try:
                cb()
            except Exception as exc:
                logger.error("Error executing cleanup callback %r: %s", cb, exc)

        logger.info("Graceful shutdown completed.")

    def wait(self, timeout: float | None = None) -> bool:
        """Block until shutdown is signaled or timeout expires."""
        return self._shutdown_event.wait(timeout=timeout)

    def reset(self) -> None:
        """Reset coordinator state (primarily for isolated unit tests)."""
        with self._lock:
            self._callbacks.clear()
            self._shutdown_event.clear()
            self._is_shutting_down = False
