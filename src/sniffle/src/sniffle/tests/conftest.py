"""
Shared Pytest Fixtures for BLE RSSI Radar Test Suite.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple
import numpy as np
import pytest

_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from tests.harness import (
    RobustAnomalyEngine,
    SpatialTomography2D,
    TargetTracker,
    MxNLinkMatrixManager,
    PublicDeviceManager,
    create_synthetic_adv_packet,
    LinkSample,
)


@pytest.fixture
def standard_geometry() -> Dict[str, Any]:
    """
    Returns standard 20m x 10m room geometry with R1 (Ch 37), R2 (Ch 38),
    and 12 ambient transmitters generating 24 spatial chords.
    """
    room_dim = (20.0, 10.0)
    r1 = np.array([0.5, 0.5], dtype=np.float32)
    r2 = np.array([19.5, 0.5], dtype=np.float32)
    
    tx_nodes = [
        np.array([2.0, 9.0], dtype=np.float32),
        np.array([6.0, 9.5], dtype=np.float32),
        np.array([10.0, 9.5], dtype=np.float32),
        np.array([14.0, 9.5], dtype=np.float32),
        np.array([18.0, 9.0], dtype=np.float32),
        np.array([1.0, 5.0], dtype=np.float32),
        np.array([19.0, 5.0], dtype=np.float32),
        np.array([5.0, 4.0], dtype=np.float32),
        np.array([10.0, 4.5], dtype=np.float32),
        np.array([15.0, 4.0], dtype=np.float32),
        np.array([7.0, 7.0], dtype=np.float32),
        np.array([13.0, 7.0], dtype=np.float32),
    ]

    links: List[Tuple[np.ndarray, np.ndarray]] = []
    for tx in tx_nodes:
        links.append((r1, tx))
        links.append((r2, tx))

    rx_configs = {
        "R1": (37, (0.5, 0.5)),
        "R2": (38, (19.5, 0.5)),
    }

    return {
        "room_dim": room_dim,
        "r1": r1,
        "r2": r2,
        "tx_nodes": tx_nodes,
        "links": links,
        "rx_configs": rx_configs,
    }


@pytest.fixture
def anomaly_engine() -> RobustAnomalyEngine:
    """Returns a pristine instance of RobustAnomalyEngine."""
    return RobustAnomalyEngine(history_len=30, min_mad=0.5, alpha_reg=0.05)


@pytest.fixture
def tomography_solver(standard_geometry) -> SpatialTomography2D:
    """Returns a pre-configured SpatialTomography2D solver."""
    solver = SpatialTomography2D(room_dim=standard_geometry["room_dim"], resolution=0.2)
    solver.update_geometry(standard_geometry["links"])
    return solver


@pytest.fixture
def alpha_beta_tracker() -> TargetTracker:
    """Returns an Alpha-Beta TargetTracker."""
    return TargetTracker(alpha=0.65, beta=0.15)


@pytest.fixture
def matrix_manager(standard_geometry) -> MxNLinkMatrixManager:
    """Returns a pristine MxNLinkMatrixManager."""
    return MxNLinkMatrixManager(
        rx_configs=standard_geometry["rx_configs"],
        inactivity_timeout=30.0,
        occlusion_timeout=3.0,
        min_activation_pkts=3,
        window_size=10,
        room_dim=standard_geometry["room_dim"],
    )


@pytest.fixture
def device_manager() -> PublicDeviceManager:
    """Returns a PublicDeviceManager."""
    return PublicDeviceManager(room_dim=(20.0, 10.0), inactivity_timeout=30.0)


@pytest.fixture
def synthetic_packet_factory() -> Callable[..., Any]:
    """Factory creating raw BLE advertising packets."""
    return create_synthetic_adv_packet


@pytest.fixture
def virtual_clock():
    """Provides monotonically increasing timestamps for fast deterministic lifecycle testing."""
    class VirtualClock:
        def __init__(self, start_t: float = 1000.0):
            self.t = start_t

        def advance(self, dt: float) -> float:
            self.t += dt
            return self.t

        def now(self) -> float:
            return self.t

    return VirtualClock()
