"""
Comprehensive Tier 2 Boundary & Corner Case Test Suite for BLE RSSI Radar.

Tests extreme values, singular matrices, empty states, zero variance,
out-of-bounds coordinates, deep occlusion, and high churn (25+ tests).
"""

from __future__ import annotations

import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pytest

_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from sniffle.radar.capture import (
    LinkSample,
    MockSniffleSource,
    point_to_segment_distance,
)
from sniffle.radar.matrix import (
    AddressType,
    classify_ble_mac,
    LinkState,
    LinkRecord,
    MxNLinkMatrixManager,
    PublicDeviceManager,
)
from sniffle.radar.anomaly import (
    compute_wilson_hilferty,
    RobustAnomalyEngine,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
)


# ============================================================================
# 1. Zero Active Devices / Empty Room Handling
# ============================================================================

def test_boundary_01_empty_room_zero_active_devices_tomography():
    """Verify tomography solver with zero links returns zero heatmap and None position."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry([])
    hm = tomo.solve_attenuation_field(np.array([]))
    assert hm.shape == (50, 100)
    assert np.max(hm) == 0.0
    pos = tomo.estimate_target_position(hm)
    assert pos is None


def test_boundary_02_empty_room_anomaly_engine_empty_snapshot(anomaly_engine):
    """Verify Mahalanobis anomaly detector with empty link list returns zeros safely."""
    dm, zm, diff = anomaly_engine.compute_mahalanobis_anomaly([], np.array([]))
    assert dm == 0.0
    assert zm == 0.0
    assert len(diff) == 0


def test_boundary_03_empty_room_matrix_manager_empty_snapshot(matrix_manager):
    """Verify MxNLinkMatrixManager with 0 packets returns empty snapshot lists."""
    keys, curr, pdr, base = matrix_manager.get_active_matrix_snapshot()
    assert len(keys) == 0
    assert len(curr) == 0
    assert len(pdr) == 0
    assert len(base) == 0


def test_boundary_04_empty_room_device_manager_empty(device_manager):
    """Verify PublicDeviceManager with no packets returns empty active dict."""
    nodes = device_manager.get_active_nodes()
    assert len(nodes) == 0
    pruned = device_manager.prune_inactive(100.0)
    assert len(pruned) == 0


# ============================================================================
# 2. Single Link Fallback Handling
# ============================================================================

def test_boundary_05_single_link_fallback_tomography():
    """Verify tomography solver works with a single link without dimension errors."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    link = (np.array([1.0, 5.0]), np.array([19.0, 5.0]))
    tomo.update_geometry([link])
    assert tomo.W is not None
    assert tomo.W.shape[0] == 1
    hm = tomo.solve_attenuation_field(np.array([8.0]))
    assert hm.shape == (50, 100)
    assert np.max(hm) > 0.0
    pos = tomo.estimate_target_position(hm)
    assert pos is not None
    assert pytest.approx(pos[1], abs=0.5) == 5.0


def test_boundary_06_single_link_fallback_mahalanobis(anomaly_engine):
    """Verify Mahalanobis distance handles single link K=1 scalar covariance safely."""
    keys = [("R1", "SOLO_TX", 37)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0]))
    dm, zm, diff = anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-75.0]))
    assert not np.isnan(dm)
    assert not np.isnan(zm)
    assert zm >= 3.0


def test_boundary_07_single_link_fallback_matrix():
    """Verify MxNLinkMatrixManager handles a single active link correctly."""
    rx_configs = {"R1": (37, (0.5, 0.5))}
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs, min_activation_pkts=2)
    for _ in range(3):
        mgr.register_packet(1.0, -58.0, "R1", "TX_ONLY", 37)
    mat, txs, rxs = mgr.get_matrix()
    assert mat.shape == (1, 1)
    assert txs == ["TX_ONLY"]
    assert rxs == ["R1"]


# ============================================================================
# 3. Singular Covariance Matrix Handling
# ============================================================================

def test_boundary_08_singular_covariance_n_less_than_k(anomaly_engine):
    """Verify rank-deficient history (N=2 < K=12) is inverted safely via shrinkage."""
    K = 12
    keys = [("R1", f"DEV_{i}", 37) for i in range(K)]
    for _ in range(2):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(K) * -60.0)
    test_vec = np.ones(K) * -60.0
    test_vec[0] = -75.0
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, test_vec)
    assert not np.isnan(dm)
    assert not np.isnan(zm)


def test_boundary_09_singular_covariance_collinear_identical_links(anomaly_engine):
    """Verify multiple links with perfectly collinear identical RSSI vectors."""
    keys = [("R1", "L1", 37), ("R1", "L2", 37), ("R1", "L3", 37)]
    for step in range(10):
        val = -60.0 + np.sin(step) * 2.0
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([val, val, val]))
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-75.0, -60.0, -60.0]))
    assert not np.isnan(dm)
    assert not np.isinf(dm)


def test_boundary_10_singular_covariance_all_zero_eigenvalues(anomaly_engine):
    """Verify all-zero sample covariance (constant identical history) handles shrinkage."""
    keys = [("R1", f"DEV_{i}", 37) for i in range(5)]
    for _ in range(10):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(5) * -60.0)
    assert anomaly_engine.last_sigma_reg is not None
    assert np.all(np.diag(anomaly_engine.last_sigma_reg) > 0.0)


# ============================================================================
# 4. Zero-Variance Streams & MAD Noise Floor
# ============================================================================

def test_boundary_11_zero_variance_mad_floor_active(anomaly_engine):
    """Verify 0.5 dBm MAD floor prevents divide-by-zero on perfectly flat RSSI streams."""
    for _ in range(20):
        anomaly_engine.update_link_sample("R1", "DEV_FLAT", 37, -65.0)
    z_rob, z_drop, _ = anomaly_engine.compute_link_robust_z("R1", "DEV_FLAT", 37, -67.0)
    assert not np.isnan(z_rob)
    assert not np.isinf(z_rob)
    expected_z = 0.6745 * (2.0 / 0.5)
    assert pytest.approx(z_rob, rel=1e-2) == expected_z


def test_boundary_12_zero_variance_identical_input_gives_zero_z(anomaly_engine):
    """Verify identical current sample to flat history yields exact 0.0 sigma."""
    for _ in range(10):
        anomaly_engine.update_link_sample("R1", "DEV_ZERO", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z("R1", "DEV_ZERO", 37, -60.0)
    assert z_rob == 0.0
    assert z_drop == 0.0
    assert combined == 0.0


# ============================================================================
# 5. Deep Occlusion & 100% Packet Loss
# ============================================================================

def test_boundary_13_deep_occlusion_zero_pdr_penalty_6_sigma(anomaly_engine):
    """Verify 100% packet loss (PDR = 0.0) injects full 6.0 sigma penalty."""
    for _ in range(10):
        anomaly_engine.update_link_sample("R1", "DEV_OCC", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z(
        "R1", "DEV_OCC", 37, -60.0, pdr=0.0
    )
    assert combined >= 6.0


def test_boundary_14_deep_occlusion_matrix_manager_15db_penalty(matrix_manager):
    """Verify matrix manager applies full 15.0 dB penalty when PDR drops to 0."""
    t0 = 100.0
    for i in range(4):
        matrix_manager.register_packet(t0 + i * 0.1, -60.0, "R1", "TX_DEEP", 37)
    rec = matrix_manager.links[("TX_DEEP", "R1")]
    matrix_manager._update_link_features(rec, current_time=t0 + 5.0)
    assert rec.pdr == 0.0
    assert rec.state == LinkState.DEGRADED
    assert rec.activity_score >= 15.0


def test_boundary_15_deep_occlusion_total_packet_loss_recovery(matrix_manager):
    """Verify degraded/stale link recovers immediately when packet delivery resumes."""
    t0 = 100.0
    for i in range(4):
        matrix_manager.register_packet(t0 + i * 0.1, -60.0, "R1", "TX_RECOV", 37)
    rec = matrix_manager.links[("TX_RECOV", "R1")]
    matrix_manager._update_link_features(rec, current_time=t0 + 5.0)
    assert rec.state == LinkState.DEGRADED

    rec_after = matrix_manager.register_packet(t0 + 5.1, -60.0, "R1", "TX_RECOV", 37)
    assert rec_after.state == LinkState.ACTIVE


# ============================================================================
# 6. Target Boundary Clamping & Coordinates
# ============================================================================

def test_boundary_16_boundary_clamping_negative_target_coords():
    """Verify target coordinates cannot be negative (clamped to room origin)."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    heatmap = np.zeros((50, 100), dtype=np.float32)
    heatmap[0:5, 0:5] = 10.0
    pos = tomo.estimate_target_position(heatmap)
    assert pos is not None
    assert pos[0] >= 0.0
    assert pos[1] >= 0.0


def test_boundary_17_boundary_clamping_excess_target_coords():
    """Verify target coordinates cannot exceed room dimensions (20m x 10m)."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    heatmap = np.zeros((50, 100), dtype=np.float32)
    heatmap[-5:, -5:] = 10.0
    pos = tomo.estimate_target_position(heatmap)
    assert pos is not None
    assert pos[0] <= 20.0
    assert pos[1] <= 10.0


def test_boundary_18_boundary_clamping_corner_coordinates():
    """Verify target detection works cleanly when target is exactly in room corners."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    corners = [(0.0, 0.0), (20.0, 0.0), (0.0, 10.0), (20.0, 10.0)]
    for cx, cy in corners:
        heatmap = np.zeros((50, 100), dtype=np.float32)
        dist_sq = (tomo.gx - cx)**2 + (tomo.gy - cy)**2
        heatmap = np.exp(-dist_sq / 0.5).astype(np.float32)
        pos = tomo.estimate_target_position(heatmap)
        assert pos is not None
        assert 0.0 <= pos[0] <= 20.0
        assert 0.0 <= pos[1] <= 10.0


# ============================================================================
# 7. Rapid MAC Churn & Inactivity Stress
# ============================================================================

def test_boundary_19_rapid_mac_churn_pruning_stress_under_30s(matrix_manager):
    """Verify rotating RPA MACs (100 distinct addresses) are pruned completely after 30s."""
    t0 = 10.0
    for i in range(100):
        mac = f"40:00:00:00:{i//256:02X}:{i%256:02X}"
        matrix_manager.register_packet(t0 + i * 0.05, -65.0, "R1", mac, 37, tx_add=1)

    assert len(matrix_manager.tx_nodes) == 100

    pruned = matrix_manager.prune_inactive(current_time=50.0)
    assert len(pruned) == 100
    assert len(matrix_manager.tx_nodes) == 0
    assert len(matrix_manager.links) == 0


def test_boundary_20_rapid_mac_churn_active_links_remain_unpruned(matrix_manager):
    """Verify persistent devices remain active while transient RPAs are pruned."""
    t0 = 100.0
    for p in range(5):
        pmac = f"00:11:22:33:44:{p:02X}"
        for step in range(4):
            matrix_manager.register_packet(t0 + step * 0.1, -60.0, "R1", pmac, 37)

    for tr in range(30):
        trmac = f"40:99:99:99:{tr//256:02X}:{tr%256:02X}"
        matrix_manager.register_packet(t0, -65.0, "R1", trmac, 37, tx_add=1)

    for p in range(5):
        pmac = f"00:11:22:33:44:{p:02X}"
        matrix_manager.register_packet(135.0, -60.0, "R1", pmac, 37)

    pruned = matrix_manager.prune_inactive(current_time=135.0)
    assert len(pruned) == 30
    assert len(matrix_manager.tx_nodes) == 5


# ============================================================================
# 8. Extreme Signal Levels & Numerical Stability
# ============================================================================

def test_boundary_21_extreme_attenuation_below_receiver_sensitivity(anomaly_engine):
    """Verify extreme signal drop (-105 dBm) is processed without numerical overflow."""
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "TX_EXTR", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z("R1", "TX_EXTR", 37, -105.0)
    assert not np.isnan(z_rob)
    assert not np.isinf(z_rob)
    assert z_rob >= 30.0


def test_boundary_22_extreme_high_rssi_direct_proximity(anomaly_engine):
    """Verify high signal (-15 dBm) from 10cm antenna proximity is handled cleanly."""
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "TX_PROX", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z("R1", "TX_PROX", 37, -15.0)
    assert not np.isnan(z_rob)
    assert not np.isinf(z_rob)
    assert z_drop == 0.0
    assert z_rob > 10.0


def test_boundary_23_sub_millimeter_target_motion():
    """Verify tracker and tomography handle tiny movements (0.001 m) without precision collapse."""
    tracker = TargetTracker(alpha=0.6, beta=0.15)
    tracker.update((10.000, 5.000), dt=0.1)
    pos2 = tracker.update((10.001, 5.000), dt=0.1)
    assert pos2 is not None
    assert pytest.approx(pos2[0], abs=1e-3) == 10.0006


def test_boundary_24_tracker_uninitialized_none_measurement():
    """Verify tracker update with None measurement before any observations returns None."""
    tracker = TargetTracker()
    assert tracker.update(None, dt=0.1) is None


def test_boundary_25_tracker_dt_near_zero():
    """Verify tracker with near-zero dt does not raise ZeroDivisionError."""
    tracker = TargetTracker()
    tracker.update((5.0, 5.0), dt=1e-7)
    res = tracker.update((5.1, 5.0), dt=1e-7)
    assert res is not None


def test_boundary_26_tomography_nan_resilience():
    """Verify tomography solver handles zero-norm rows or near-zero anomalies safely."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    link = (np.array([5.0, 5.0]), np.array([5.0, 5.0]))
    tomo.update_geometry([link])
    hm = tomo.solve_attenuation_field(np.array([1.0]))
    assert not np.any(np.isnan(hm))


def test_boundary_27_high_frequency_packet_burst(matrix_manager):
    """Verify multiple packets arriving at exact same timestamp (dt = 0) do not cause ZeroDivisionError."""
    for _ in range(10):
        rec = matrix_manager.register_packet(100.0, -60.0, "R1", "BURST_MAC", 37)
    assert rec.packet_count == 10
    assert rec.expected_interval_s >= 0.01
