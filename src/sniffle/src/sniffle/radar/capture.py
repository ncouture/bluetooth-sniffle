"""
BLE RSSI Radar - Hardware Ingestion & Channel Locking Layer.

Provides:
- LinkSample: Immutable, frozen dataclass for over-the-air packet samples.
- SnifflePacketSource: Abstract base class for packet sources.
- HardwareSniffleSource: Driver for physical Sonoff CC2652P USB Dongles (Channel 37/38 locked).
- MockSniffleSource: Physics-based synthetic BLE packet generator for simulation and fallback.
- DualSnifferManager: Orchestrator for concurrent dual-receiver streams with auto-fallback.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
import math
import os
from pathlib import Path
import queue
from queue import Queue
import random
import sys
import threading
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Sequence, Tuple

try:
    from ..sniffle_hw import make_sniffle_hw, SnifferMode, SniffleHW
    from ..packet_decoder import str_mac
    from ..errors import UsageError, SniffleHWPacketError
except ImportError:
    try:
        from sniffle.sniffle_hw import make_sniffle_hw, SnifferMode, SniffleHW
        from sniffle.packet_decoder import str_mac
        from sniffle.errors import UsageError, SniffleHWPacketError
    except ImportError:
        make_sniffle_hw = None  # type: ignore
        SnifferMode = None  # type: ignore
        SniffleHW = None  # type: ignore
        UsageError = Exception  # type: ignore
        SniffleHWPacketError = Exception  # type: ignore

        def str_mac(mac: bytes) -> str:
            return ":".join(["%02X" % b for b in reversed(mac)])


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Data Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LinkSample:
    """
    Immutable representation of an over-the-air BLE advertising packet sample.

    Attributes:
        timestamp: Unix epoch timestamp in seconds.
        rssi: Received Signal Strength Indication in dBm.
        rx_id: Receiver identifier (e.g., 'R1' or 'R2').
        tx_mac: Advertiser MAC address formatted as 'AA:BB:CC:DD:EE:FF'.
        channel: BLE primary advertising channel (37, 38, or 39).
    """
    timestamp: float
    rssi: float
    rx_id: str
    tx_mac: str
    channel: int


# ---------------------------------------------------------------------------
# 2. Packet Source Base Interface
# ---------------------------------------------------------------------------

class SnifflePacketSource(ABC):
    """Abstract base class for BLE packet ingestion sources."""

    @abstractmethod
    def start(self) -> None:
        """Start packet acquisition in a background thread."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop packet acquisition and release underlying resources."""
        pass

    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the source is currently actively ingesting/streaming."""
        pass

    @property
    @abstractmethod
    def queue(self) -> Queue:
        """Thread-safe queue holding LinkSample instances."""
        pass

    def get_queue(self) -> Queue:
        """Convenience accessor for the thread-safe sample queue."""
        return self.queue


# ---------------------------------------------------------------------------
# 3. Hardware Sniffle Source (Physical CC2652P USB Dongles)
# ---------------------------------------------------------------------------

class HardwareSniffleSource(SnifflePacketSource):
    """
    Ingests live over-the-air BLE packets from a physical Sonoff CC2652P USB Dongle.

    Key Hardware Guarantees:
    - Locked to fixed advertising channel (Ch 37 for R1, Ch 38 for R2) with hop3=False.
    - Eliminates 'Must specify a target for advertising channel hop' UsageError.
    - Communicates at 921,600 baud (standard CP2102 UART bridge hardware cap).
    - Extracts advertiser MAC from msg.AdvA via str_mac across all Sniffle packet types.
    """

    def __init__(
        self,
        port: str = "/dev/ttyUSB0",
        baudrate: int = 921600,
        channel: int = 37,
        rx_id: str = "R1",
        out_queue: Optional[queue.Queue] = None,
        rssi_min: int = -128,
        validate_crc: bool = True,
        source_logger: Optional[Any] = None,
    ):
        if channel not in (37, 38, 39):
            raise ValueError(f"Invalid primary advertising channel: {channel}. Must be 37, 38, or 39.")

        self.port = port
        self.baudrate = baudrate
        self.channel = channel
        self.rx_id = rx_id
        self._queue: queue.Queue = out_queue if out_queue is not None else queue.Queue()
        self.rssi_min = rssi_min
        self.validate_crc = validate_crc
        self._logger = source_logger or logger

        self.hw: Optional[Any] = None
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

    @property
    def queue(self) -> queue.Queue:
        return self._queue

    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Connect to hardware, configure fixed channel lock, and begin ingestion thread."""
        if self._running:
            return

        if make_sniffle_hw is None or SnifferMode is None:
            raise RuntimeError("Sniffle hardware library is not available.")

        self._logger.info(
            "Connecting to Sniffle dongle %s on %s at %d baud (Channel %d locked, hop3=False)...",
            self.rx_id, self.port, self.baudrate, self.channel
        )

        self.hw = make_sniffle_hw(self.port, baudrate=self.baudrate, logger=self._logger)

        self.hw.setup_sniffer(
            mode=SnifferMode.PASSIVE_SCAN,
            chan=self.channel,
            hop3=False,
            targ_mac=None,
            targ_irk=None,
            validate_crc=self.validate_crc,
            rssi_min=self.rssi_min,
        )

        self.hw.mark_and_flush()

        self._running = True
        self._worker_thread = threading.Thread(
            target=self._ingestion_loop,
            name=f"HWSniffle-{self.rx_id}-Ch{self.channel}",
            daemon=True,
        )
        self._worker_thread.start()

    def _ingestion_loop(self) -> None:
        """Continuous background loop calling recv_and_decode() and pushing LinkSample."""
        while self._running:
            try:
                if self.hw is None:
                    break

                msg = self.hw.recv_and_decode()
                if msg is None:
                    continue

                if hasattr(msg, "AdvA") and msg.AdvA:
                    mac_str = str_mac(msg.AdvA)
                    rssi_val = getattr(msg, "rssi", None)
                    if rssi_val is None:
                        continue

                    sample = LinkSample(
                        timestamp=time.time(),
                        rssi=float(rssi_val),
                        rx_id=self.rx_id,
                        tx_mac=mac_str,
                        channel=self.channel,
                    )
                    self._queue.put(sample)

            except (OSError, IOError) as err:
                if self._running:
                    self._logger.warning(
                        "HardwareSniffleSource [%s on %s] serial IO error: %s",
                        self.rx_id, self.port, err
                    )
                    self._running = False
                break
            except Exception as err:
                if not self._running:
                    break
                self._logger.debug(
                    "HardwareSniffleSource [%s] packet processing exception: %s",
                    self.rx_id, err
                )

    def stop(self) -> None:
        """Cancel reception, close serial connection, and terminate background thread."""
        self._running = False
        if self.hw is not None:
            try:
                self.hw.cancel_recv()
            except Exception:
                pass
            try:
                if hasattr(self.hw, "ser") and self.hw.ser and self.hw.ser.is_open:
                    self.hw.ser.close()
            except Exception:
                pass

        if self._worker_thread is not None and self._worker_thread.is_alive():
            if threading.current_thread() != self._worker_thread:
                self._worker_thread.join(timeout=1.5)
        self.hw = None


# ---------------------------------------------------------------------------
# 4. Mock Sniffle Source (Simulation & Seamless Fallback)
# ---------------------------------------------------------------------------

DEFAULT_MOCK_TRANSMITTERS: List[Dict[str, Any]] = [
    {"mac": "AA:BB:CC:11:22:01", "name": "Beacon_North_1", "pos": (4.0, 8.5), "interval": 0.10, "tx_power": -42.0},
    {"mac": "AA:BB:CC:11:22:02", "name": "Beacon_North_2", "pos": (8.0, 9.0), "interval": 0.15, "tx_power": -40.0},
    {"mac": "AA:BB:CC:11:22:03", "name": "Beacon_North_3", "pos": (12.0, 8.5), "interval": 0.10, "tx_power": -42.0},
    {"mac": "AA:BB:CC:11:22:04", "name": "Beacon_North_4", "pos": (16.0, 9.0), "interval": 0.20, "tx_power": -41.0},
    {"mac": "AA:BB:CC:11:22:05", "name": "SmartPlug_Desk1", "pos": (3.0, 3.0), "interval": 0.25, "tx_power": -44.0},
    {"mac": "AA:BB:CC:11:22:06", "name": "SmartPlug_Desk2", "pos": (7.0, 2.5), "interval": 0.20, "tx_power": -44.0},
    {"mac": "AA:BB:CC:11:22:07", "name": "Display_Hall", "pos": (11.0, 3.5), "interval": 0.30, "tx_power": -40.0},
    {"mac": "AA:BB:CC:11:22:08", "name": "Thermometer_Wall", "pos": (15.0, 2.0), "interval": 0.50, "tx_power": -45.0},
    {"mac": "AA:BB:CC:11:22:09", "name": "Beacon_South_1", "pos": (5.0, 1.0), "interval": 0.10, "tx_power": -42.0},
    {"mac": "AA:BB:CC:11:22:0A", "name": "Beacon_South_2", "pos": (10.0, 1.2), "interval": 0.12, "tx_power": -40.0},
    {"mac": "AA:BB:CC:11:22:0B", "name": "Beacon_South_3", "pos": (15.0, 1.0), "interval": 0.10, "tx_power": -42.0},
    {"mac": "AA:BB:CC:11:22:0C", "name": "Printer_BT", "pos": (2.0, 6.0), "interval": 0.35, "tx_power": -43.0},
    {"mac": "AA:BB:CC:11:22:0D", "name": "Audio_Speaker", "pos": (18.0, 6.5), "interval": 0.18, "tx_power": -41.0},
    {"mac": "AA:BB:CC:11:22:0E", "name": "Vending_Machine", "pos": (9.0, 5.0), "interval": 0.25, "tx_power": -42.0},
]


def default_human_trajectory(t: float) -> Tuple[float, float]:
    """Default simulated walking motion traversing the 20m x 10m sensing space."""
    x = 10.0 + 4.0 * math.sin(0.4 * t)
    y = 5.0 + 3.0 * math.cos(0.4 * t)
    return (x, y)


def point_to_segment_distance(
    pt: Tuple[float, float],
    seg_start: Tuple[float, float],
    seg_end: Tuple[float, float],
) -> Tuple[float, float]:
    """
    Computes Euclidean distance from a point to a line segment [seg_start, seg_end].
    Returns (perpendicular_distance, projection_param_u).
    """
    px, py = pt
    ax, ay = seg_start
    bx, by = seg_end

    vx = bx - ax
    vy = by - ay
    v_sq = vx * vx + vy * vy
    if v_sq == 0.0:
        return math.hypot(px - ax, py - ay), 0.0

    u = ((px - ax) * vx + (py - ay) * vy) / v_sq
    if u <= 0.0:
        return math.hypot(px - ax, py - ay), u
    elif u >= 1.0:
        return math.hypot(px - bx, py - by), u
    else:
        proj_x = ax + u * vx
        proj_y = ay + u * vy
        return math.hypot(px - proj_x, py - proj_y), u


class MockSniffleSource(SnifflePacketSource):
    """
    Simulates RF packet generation from 10+ ambient BLE transmitters.

    Features:
    - Emits across Channel 37 and/or Channel 38 with realistic intervals (20ms - 500ms).
    - Log-distance path loss based on 2D receiver geometry (R1 at (0, 5), R2 at (20, 5)).
    - Constructive and destructive multipath noise.
    - Simulates moving target RF attenuation (>= 3.0 sigma drop and PDR drop).
    - Deterministic mode via optional random seed.
    - Thread-safe output queue streaming.
    """

    def __init__(
        self,
        rx_id: str = "R1",
        channel: Optional[int] = None,
        channels: Optional[Sequence[int]] = None,
        rx_pos: Optional[Tuple[float, float]] = None,
        transmitters: Optional[List[Dict[str, Any]]] = None,
        out_queue: Optional[queue.Queue] = None,
        seed: Optional[int] = None,
        target_pos: Optional[Tuple[float, float]] = None,
        target_trajectory: Optional[Callable[[float], Optional[Tuple[float, float]]]] = None,
        simulate_target: bool = True,
        path_loss_exponent: float = 2.2,
        noise_std: float = 1.5,
        target_sigma: float = 0.8,
        max_target_attenuation: float = 16.0,
        pdr_drop_radius: float = 0.5,
        pdr_drop_prob: float = 0.8,
        tick_interval: float = 0.01,
    ):
        self.rx_id = rx_id

        if channels is not None:
            self.channels: Tuple[int, ...] = tuple(channels)
        elif channel is not None:
            self.channels = (channel,)
        else:
            self.channels = (37, 38)

        self.channel = self.channels[0]

        if rx_pos is not None:
            self.rx_pos = rx_pos
        elif rx_id == "R2":
            self.rx_pos = (20.0, 5.0)
        else:
            self.rx_pos = (0.0, 5.0)

        tx_template = transmitters if transmitters is not None else DEFAULT_MOCK_TRANSMITTERS
        self.transmitters: List[Dict[str, Any]] = [dict(t) for t in tx_template]
        for tx in self.transmitters:
            tx["next_tx_time"] = 0.0

        self._queue: queue.Queue = out_queue if out_queue is not None else queue.Queue()
        self.seed = seed
        self.rng = random.Random(seed)

        self.target_pos = target_pos
        self.target_trajectory = target_trajectory
        self.simulate_target = simulate_target
        if self.simulate_target and self.target_pos is None and self.target_trajectory is None:
            self.target_trajectory = default_human_trajectory

        self.path_loss_exponent = path_loss_exponent
        self.noise_std = noise_std
        self.target_sigma = target_sigma
        self.max_target_attenuation = max_target_attenuation
        self.pdr_drop_radius = pdr_drop_radius
        self.pdr_drop_prob = pdr_drop_prob
        self.tick_interval = tick_interval

        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._sim_start_time = time.time()

    @property
    def queue(self) -> queue.Queue:
        return self._queue

    def is_running(self) -> bool:
        return self._running

    def set_target_pos(self, pos: Optional[Tuple[float, float]]) -> None:
        """Explicitly set or clear the target position."""
        self.target_pos = pos

    def set_simulate_target(self, enabled: bool) -> None:
        """Enable or disable target shadowing simulation."""
        self.simulate_target = enabled

    def get_current_target_pos(self, t: float) -> Optional[Tuple[float, float]]:
        """Resolve current target coordinates given simulation time."""
        if not self.simulate_target:
            return None
        if self.target_pos is not None:
            return self.target_pos
        if self.target_trajectory is not None:
            return self.target_trajectory(t)
        return None

    def _compute_sample(
        self,
        tx: Dict[str, Any],
        ch: int,
        now: float,
        target_xy: Optional[Tuple[float, float]],
    ) -> Optional[LinkSample]:
        """Calculates path loss, multipath, and target occlusion for a single transmission."""
        tx_pos = tx["pos"]
        tx_power = tx.get("tx_power", -42.0)

        dist = math.hypot(tx_pos[0] - self.rx_pos[0], tx_pos[1] - self.rx_pos[1])
        dist = max(0.1, dist)

        path_loss = 10.0 * self.path_loss_exponent * math.log10(dist)
        base_rssi = tx_power - path_loss

        noise = self.rng.gauss(0.0, self.noise_std)

        target_atten = 0.0
        pdr_dropped = False

        if target_xy is not None:
            d_perp, u = point_to_segment_distance(target_xy, tx_pos, self.rx_pos)
            if 0.0 <= u <= 1.0:
                if d_perp < 1.5:
                    atten_factor = math.exp(-(d_perp * d_perp) / (2.0 * (self.target_sigma * self.target_sigma)))
                    target_atten = self.max_target_attenuation * atten_factor

                    if d_perp < self.pdr_drop_radius:
                        if self.rng.random() < self.pdr_drop_prob:
                            pdr_dropped = True

                elif 1.5 <= d_perp <= 2.8:
                    if self.rng.random() < 0.25:
                        noise += 3.5 * math.exp(-((d_perp - 2.0) ** 2) / 0.5)

        if pdr_dropped:
            return None

        total_rssi = base_rssi + noise - target_atten
        total_rssi = max(-100.0, min(-10.0, total_rssi))

        return LinkSample(
            timestamp=now,
            rssi=round(total_rssi, 1),
            rx_id=self.rx_id,
            tx_mac=tx["mac"],
            channel=ch,
        )

    def generate_samples(
        self,
        count: int = 50,
        dt: float = 0.05,
        start_time: Optional[float] = None,
    ) -> List[LinkSample]:
        """
        Synchronously generates a batch of LinkSample objects.
        Useful for deterministic testing and reproducible benchmarks.
        """
        samples: List[LinkSample] = []
        if start_time is not None:
            sim_time = start_time
        elif self.seed is not None:
            sim_time = 0.0
        else:
            sim_time = self._sim_start_time

        while len(samples) < count:
            sim_time += dt
            target_xy = self.get_current_target_pos(sim_time)
            for tx in self.transmitters:
                for ch in self.channels:
                    s = self._compute_sample(tx, ch, sim_time, target_xy)
                    if s is not None:
                        samples.append(s)
                        if len(samples) >= count:
                            break
                if len(samples) >= count:
                    break

        return samples

    def start(self) -> None:
        """Start real-time simulation background thread."""
        if self._running:
            return

        self._running = True
        self._sim_start_time = time.time()
        for tx in self.transmitters:
            tx["next_tx_time"] = self._sim_start_time + self.rng.uniform(0.0, tx.get("interval", 0.1))

        self._worker_thread = threading.Thread(
            target=self._simulation_loop,
            name=f"MockSniffle-{self.rx_id}",
            daemon=True,
        )
        self._worker_thread.start()

    def _simulation_loop(self) -> None:
        """Background thread generating packets according to device advertising schedules."""
        while self._running:
            now = time.time()
            target_xy = self.get_current_target_pos(now)

            for tx in self.transmitters:
                if now >= tx["next_tx_time"]:
                    tx["next_tx_time"] = now + tx.get("interval", 0.1) * self.rng.uniform(0.9, 1.1)
                    for ch in self.channels:
                        sample = self._compute_sample(tx, ch, now, target_xy)
                        if sample is not None:
                            self._queue.put(sample)

            time.sleep(self.tick_interval)

    def stop(self) -> None:
        """Stop simulation background thread."""
        self._running = False
        if self._worker_thread is not None and self._worker_thread.is_alive():
            if threading.current_thread() != self._worker_thread:
                self._worker_thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# 5. Dual Sniffer Manager (Concurrent Ingestion & Fallback)
# ---------------------------------------------------------------------------

class DualSnifferManager:
    """
    Orchestrates dual-channel RF packet ingestion across two static receivers:
    - R1 on Channel 37 (Port 1, e.g. /dev/ttyUSB0)
    - R2 on Channel 38 (Port 2, e.g. /dev/ttyUSB1)

    Features:
    - Aggregated FIFO queue combining samples from both receivers.
    - Automatic, seamless fallback to MockSniffleSource if physical serial ports
      cannot be opened, or if simulate=True is specified.
    - Full start/stop lifecycle and Python context manager support.
    - Clean sample streaming generator with timeout support.
    """

    def __init__(
        self,
        port1: Optional[str] = "/dev/ttyUSB0",
        port2: Optional[str] = "/dev/ttyUSB1",
        baudrate: int = 921600,
        simulate: bool = False,
        fallback_to_mock: bool = True,
        rx1_id: str = "R1",
        rx2_id: str = "R2",
        channel1: int = 37,
        channel2: int = 38,
        rx_pos1: Tuple[float, float] = (0.0, 5.0),
        rx_pos2: Tuple[float, float] = (20.0, 5.0),
        seed: Optional[int] = None,
        manager_logger: Optional[Any] = None,
    ):
        self.port1 = port1
        self.port2 = port2
        self.baudrate = baudrate
        self.simulate = simulate
        self.fallback_to_mock = fallback_to_mock
        self.rx1_id = rx1_id
        self.rx2_id = rx2_id
        self.channel1 = channel1
        self.channel2 = channel2
        self.rx_pos1 = rx_pos1
        self.rx_pos2 = rx_pos2
        self.seed = seed
        self._logger = manager_logger or logger

        self.queue: queue.Queue = queue.Queue()
        self.source1: Optional[SnifflePacketSource] = None
        self.source2: Optional[SnifflePacketSource] = None
        self.using_mock: bool = False
        self._running: bool = False

    def is_running(self) -> bool:
        return self._running

    def _start_mock_sources(self) -> None:
        """Spins up MockSniffleSource for both R1 (Ch 37) and R2 (Ch 38)."""
        self.source1 = MockSniffleSource(
            rx_id=self.rx1_id,
            channel=self.channel1,
            rx_pos=self.rx_pos1,
            out_queue=self.queue,
            seed=self.seed,
        )
        self.source2 = MockSniffleSource(
            rx_id=self.rx2_id,
            channel=self.channel2,
            rx_pos=self.rx_pos2,
            out_queue=self.queue,
            seed=self.seed + 1 if self.seed is not None else None,
        )
        self.source1.start()
        self.source2.start()
        self.using_mock = True
        self._running = True

    def start(self) -> None:
        """Start both receiver sources (hardware or simulated fallback)."""
        if self._running:
            return

        if self.simulate:
            self._logger.info("Simulation mode requested. Launching MockSniffleSource for R1 and R2.")
            self._start_mock_sources()
            return

        try:
            if not self.port1 or not self.port2:
                raise ValueError("Both port1 and port2 must be specified for hardware mode.")

            s1 = HardwareSniffleSource(
                port=self.port1,
                baudrate=self.baudrate,
                channel=self.channel1,
                rx_id=self.rx1_id,
                out_queue=self.queue,
                source_logger=self._logger,
            )
            s2 = HardwareSniffleSource(
                port=self.port2,
                baudrate=self.baudrate,
                channel=self.channel2,
                rx_id=self.rx2_id,
                out_queue=self.queue,
                source_logger=self._logger,
            )

            s1.start()
            try:
                s2.start()
            except Exception:
                s1.stop()
                raise

            self.source1 = s1
            self.source2 = s2
            self.using_mock = False
            self._running = True
            self._logger.info(
                "Successfully connected physical Sniffle dongles: %s (%s, Ch %d) and %s (%s, Ch %d).",
                self.rx1_id, self.port1, self.channel1, self.rx2_id, self.port2, self.channel2
            )

        except Exception as err:
            if self.fallback_to_mock:
                self._logger.warning(
                    "Physical hardware initialization failed (%s); falling back seamlessly to MockSniffleSource.",
                    err
                )
                self._start_mock_sources()
            else:
                raise

    def stop(self) -> None:
        """Stop both receiver streams and terminate background threads."""
        self._running = False
        if self.source1 is not None:
            self.source1.stop()
            self.source1 = None
        if self.source2 is not None:
            self.source2.stop()
            self.source2 = None

    def stream_samples(self, timeout: Optional[float] = None) -> Generator[LinkSample, None, None]:
        """
        Generator yielding LinkSample instances from the aggregated queue.
        If timeout is given, breaks when no samples arrive for timeout seconds.
        """
        while self._running:
            try:
                wait_time = timeout if timeout is not None else 0.1
                sample = self.queue.get(timeout=wait_time)
                yield sample
            except queue.Empty:
                if timeout is not None:
                    break

    def __enter__(self) -> "DualSnifferManager":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
