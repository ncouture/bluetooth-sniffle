"""
Comprehensive Tier 3 Pairwise Interaction Test Suite for BLE RSSI Radar.

Tests multi-feature interactions: joint RSSI + PDR drops, pruning during
active crossing, high device density (30+ devices), fast motion link transitions,
and headless mock pipeline integration (15+ tests).
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
    DualSnifferManager,
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
    RobustAnomalyEngine,
    LinkAnomalyVector,
    compute_wilson_hilferty,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
)
from sniffle.radar.visualizer import (
    RadarVisualizer,
    RadarFrameProcessor,
    run_single_frame,
    run_radar_pipeline,
)


# ============================================================================
# Pairwise Interaction Tests
# ============================================================================

def test_pairwise_01_joint_rssi_and_pdr_drop_additive_scoring(anomaly_engine):
    """Verify simultaneous RSSI drop and PDR drop produce strictly additive higher anomaly."""
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "DEV_JOINT", 37, -60.0)

    z_rob1, z_drop1, score_rssi_only = anomaly_engine.compute_link_robust_z(
        "R1", "DEV_JOINT", 37, -72.0, pdr=1.0
    )

    _, _, score_pdr_only = anomaly_engine.compute_link_robust_z(
        "R1", "DEV_JOINT", 37, -60.0, pdr=0.2
    )

    _, _, score_joint = anomaly_engine.compute_link_robust_z(
        "R1", "DEV_JOINT", 37, -72.0, pdr=0.2
    )

    assert score_joint > score_rssi_only
    assert score_joint > score_pdr_only
    expected_pdr_penalty = (1.0 - 0.2) * 6.0
    assert pytest.approx(score_joint, rel=1e-2) == score_rssi_only + expected_pdr_penalty


def test_pairwise_02_device_pruning_during_active_human_crossing(standard_geometry):
    """Verify background device pruning during active tracking does not crash solver."""
    mgr = MxNLinkMatrixManager(rx_configs=standard_geometry["rx_configs"], inactivity_timeout=10.0)
    engine = RobustAnomalyEngine(history_len=20)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)

    for i in range(5):
        mac = f"00:11:22:33:44:{i:02X}"
        for step in range(4):
            mgr.register_packet(10.0 + step * 0.1, -60.0, "R1", mac, 37)
            mgr.register_packet(10.0 + step * 0.1, -62.0, "R2", mac, 38)

    ephemeral = "00:11:22:33:44:EE"
    mgr.register_packet(10.0, -65.0, "R1", ephemeral, 37)

    mgr.register_packet(25.0, -78.0, "R1", "00:11:22:33:44:00", 37)
    for i in range(1, 5):
        mgr.register_packet(25.0, -60.0, "R1", f"00:11:22:33:44:{i:02X}", 37)
        mgr.register_packet(25.0, -62.0, "R2", f"00:11:22:33:44:{i:02X}", 38)

    pruned = mgr.prune_inactive(current_time=25.0)
    assert ephemeral in pruned
    assert "00:11:22:33:44:00" not in pruned

    keys, curr, pdr, base = mgr.get_active_matrix_snapshot()
    for _ in range(3):
        engine.compute_mahalanobis_anomaly(keys, base)
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, curr)

    links = []
    for k in keys:
        parts = k.split("_")
        rx_id = parts[0]
        tx_mac = parts[1]
        links.append((standard_geometry["rx_configs"][rx_id][1], mgr.tx_nodes[tx_mac]))

    tomo.update_geometry(links)
    anom_scores = np.abs(diff)
    heatmap = tomo.solve_attenuation_field(anom_scores)
    pos = tomo.estimate_target_position(heatmap)
    assert pos is not None
    assert heatmap.shape == (50, 100)


def test_pairwise_03_high_device_density_30_plus_devices_dual_tikhonov():
    """Verify dual-space solver with 32 transmitters (64 links) solves in < 20 ms."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    r1 = np.array([0.5, 0.5])
    r2 = np.array([19.5, 0.5])

    tx_nodes = [np.array([i * 0.6 + 0.5, 9.0]) for i in range(32)]
    links = []
    for tx in tx_nodes:
        links.append((r1, tx))
        links.append((r2, tx))

    K = len(links)
    assert K == 64

    tomo.update_geometry(links)
    assert tomo.Gram_inv is not None
    assert tomo.Gram_inv.shape == (64, 64)

    anom = np.random.uniform(0.0, 2.0, K)
    anom[5] = 12.0
    anom[6] = 10.0

    t0 = time.perf_counter()
    heatmap = tomo.solve_attenuation_field(anom)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert elapsed_ms < 20.0
    assert heatmap.shape == (50, 100)
    assert np.max(heatmap) > 0.0


def test_pairwise_04_headless_runner_with_mock_feeder_pipeline(capsys):
    """Verify headless runner integration with MockSniffleSource streaming and authentic telemetry."""
    now = time.time()
    mock = MockSniffleSource(rx_id="R1", channels=[37, 38], seed=42)
    samples = mock.generate_samples(count=30, start_time=now)

    exit_code = run_radar_pipeline(samples, headless=True)
    assert exit_code == 0

    captured = capsys.readouterr()
    frame_lines = [ln for ln in captured.out.splitlines() if "[RADAR FRAME" in ln]
    assert len(frame_lines) == 6
    assert "Links:" in captured.out
    assert "Target:" in captured.out
    assert "Sigma: 4.2" not in captured.out

    frame = run_single_frame(samples[:10], headless=True)
    assert frame["active_links"] > 0
    assert isinstance(frame["heatmap"], np.ndarray)
    assert frame["heatmap"].shape == (50, 100)
    assert np.all(frame["heatmap"] >= 0.0)
    assert math.isclose(frame["max_intensity"], float(np.max(frame["heatmap"])), rel_tol=1e-5)
    assert frame["max_intensity"] != 5.2


def test_pairwise_05_fast_motion_crossing_link_transitions(standard_geometry):
    """Verify fast human motion (2.5 m/s) across adjacent links updates smoothly."""
    tracker = TargetTracker(alpha=0.6, beta=0.15)
    dt = 0.2
    true_traj = [(5.0 + i * 0.5, 4.0 + i * 0.2) for i in range(10)]
    tracked_traj = []

    for pos in true_traj:
        meas = (pos[0] + np.random.normal(0, 0.05), pos[1] + np.random.normal(0, 0.05))
        est = tracker.update(meas, dt=dt)
        tracked_traj.append(est)

    assert len(tracked_traj) == 10
    speed = float(np.linalg.norm(tracker.vel))
    assert 1.5 < speed < 3.5


def test_pairwise_06_dynamic_link_appearance_during_active_tracking(anomaly_engine):
    """Verify adding links dynamically does not reset or corrupt anomaly tracking."""
    keys_5 = [("R1", f"DEV_{i}", 37) for i in range(5)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys_5, np.ones(5) * -60.0)

    keys_8 = keys_5 + [("R2", f"DEV_{i}", 38) for i in range(5, 8)]
    dm, zm, diff = anomaly_engine.compute_mahalanobis_anomaly(keys_8, np.ones(8) * -60.0)
    assert not np.isnan(dm)
    assert len(diff) == 8


def test_pairwise_07_asymmetric_reception_dual_channel(matrix_manager):
    """Verify transmitter received strongly on Ch 37 but degraded on Ch 38."""
    mac = "DEV_ASYMM_CH"
    for i in range(5):
        matrix_manager.register_packet(10.0 + i * 0.1, -55.0, "R1", mac, 37)
    for i in range(3):
        matrix_manager.register_packet(10.0 + i * 0.1, -85.0, "R2", mac, 38)

    matrix_manager.register_packet(14.0, -55.0, "R1", mac, 37)
    matrix_manager._update_link_features(matrix_manager.links[(mac, "R2")], 14.0)

    rec_r1 = matrix_manager.links[(mac, "R1")]
    rec_r2 = matrix_manager.links[(mac, "R2")]

    assert rec_r1.state == LinkState.ACTIVE
    assert rec_r2.state == LinkState.DEGRADED


def test_pairwise_08_selective_freezing_with_rapid_alternating_bursts(anomaly_engine):
    """Verify baseline updates strictly during nominal bursts and freezes during anomaly bursts."""
    keys = [("R1", "DEV_ALT", 37)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0]))

    for _ in range(3):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.1]))
    len_nominal_1 = len(anomaly_engine.multivariate_history)
    assert len_nominal_1 == 8

    for _ in range(4):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-78.0]))
    assert len(anomaly_engine.multivariate_history) == len_nominal_1

    for _ in range(2):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0]))
    assert len(anomaly_engine.multivariate_history) == len_nominal_1 + 2


def test_pairwise_09_dense_grid_0_1m_with_dual_space_solver():
    """Verify dual-space Tikhonov solver handles high-res 0.1m grid (20,000 pixels)."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.1)
    assert tomo.nx == 200
    assert tomo.ny == 100
    assert tomo.P == 20000

    links = [(np.array([0.5, 0.5]), np.array([19.5, 9.5]))]
    tomo.update_geometry(links)

    t0 = time.perf_counter()
    heatmap = tomo.solve_attenuation_field(np.array([10.0]))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert elapsed_ms < 15.0
    assert heatmap.shape == (100, 200)
    assert np.max(heatmap) > 0.0


def test_pairwise_10_concurrent_multi_link_shadow_with_unequal_attenuation():
    """Verify multiple links with unequal attenuation reconstruct peak towards heavier drop."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    l1 = (np.array([1.0, 3.0]), np.array([19.0, 3.0]))
    l2 = (np.array([1.0, 7.0]), np.array([19.0, 7.0]))
    tomo.update_geometry([l1, l2])

    hm = tomo.solve_attenuation_field(np.array([12.0, 3.0]))
    pos = tomo.estimate_target_position(hm)
    assert pos is not None
    assert pos[1] < 4.5


def test_pairwise_11_target_tracker_with_intermittent_missing_frames():
    """Verify tracker coasts across missing frames (None) and smoothly reconnects."""
    tracker = TargetTracker(alpha=0.6, beta=0.15)
    tracker.update((5.0, 5.0), dt=0.5)
    tracker.update((6.0, 5.0), dt=0.5)

    coast1 = tracker.update(None, dt=0.5)
    coast2 = tracker.update(None, dt=0.5)
    assert coast1 is not None and coast2 is not None
    assert coast2[0] > coast1[0]

    reconnected = tracker.update((8.0, 5.0), dt=0.5)
    assert reconnected is not None
    assert 7.0 < reconnected[0] <= 8.0


def test_pairwise_12_rotating_rpa_replacement_under_matrix_snapshot(matrix_manager):
    """Verify rotating RPA MAC transition updates matrix snapshot cleanly."""
    t0 = 100.0
    old_mac = "40:00:00:00:00:01"
    for _ in range(4):
        matrix_manager.register_packet(t0, -60.0, "R1", old_mac, 37, tx_add=1)

    keys1, _, _, _ = matrix_manager.get_active_matrix_snapshot()
    assert any(old_mac in k for k in keys1)

    new_mac = "40:00:00:00:00:02"
    for _ in range(4):
        matrix_manager.register_packet(t0 + 35.0, -60.0, "R1", new_mac, 37, tx_add=1)
    matrix_manager.prune_inactive(t0 + 35.0)

    keys2, _, _, _ = matrix_manager.get_active_matrix_snapshot()
    assert not any(old_mac in k for k in keys2)
    assert any(new_mac in k for k in keys2)


def test_pairwise_13_pdr_drop_dominating_weak_rssi_link(anomaly_engine):
    """Verify weak RSSI links (-88 dBm) trigger anomaly primarily via PDR penalty."""
    for _ in range(10):
        anomaly_engine.update_link_sample("R1", "DEV_WEAK", 37, -88.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z(
        "R1", "DEV_WEAK", 37, -90.0, pdr=0.0
    )
    assert z_drop < 3.0
    assert combined >= 6.0


def test_pairwise_14_constructive_reflection_paired_with_destructive_shadow():
    """Verify both shadow link and reflection link contribute to localization."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    l1 = (np.array([2.0, 2.0]), np.array([18.0, 2.0]))
    l2 = (np.array([2.0, 8.0]), np.array([18.0, 8.0]))
    tomo.update_geometry([l1, l2])

    hm = tomo.solve_attenuation_field(np.array([8.0, 4.0]))
    assert np.max(hm) > 0.0
    pos = tomo.estimate_target_position(hm)
    assert pos is not None


def test_pairwise_15_dual_receiver_spatial_diversity():
    """Verify spatial intersection of R1 and R2 links localizes target near intersection."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    r1 = np.array([0.5, 0.5])
    r2 = np.array([19.5, 0.5])
    tx1 = np.array([10.0, 9.0])

    l1 = (r1, tx1)
    l2 = (r2, tx1)
    tomo.update_geometry([l1, l2])

    hm = tomo.solve_attenuation_field(np.array([8.0, 8.0]))
    pos = tomo.estimate_target_position(hm)
    assert pos is not None
    assert pytest.approx(pos[0], abs=2.0) == 10.0


def test_pairwise_16_real_time_pipeline_latency_budget(standard_geometry):
    """Verify complete frame pipeline executes under 10 ms budget per frame."""
    mgr = MxNLinkMatrixManager(rx_configs=standard_geometry["rx_configs"])
    engine = RobustAnomalyEngine(history_len=20)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tracker = TargetTracker()

    t0 = 10.0
    for i in range(8):
        mac = f"00:11:22:33:44:{i:02X}"
        for step in range(4):
            mgr.register_packet(t0 + step * 0.1, -60.0, "R1", mac, 37)
            mgr.register_packet(t0 + step * 0.1, -60.0, "R2", mac, 38)

    keys, curr, pdr, base = mgr.get_active_matrix_snapshot()
    links = [(standard_geometry["rx_configs"][k.split("_")[0]][1], mgr.tx_nodes[k.split("_")[1]]) for k in keys]
    tomo.update_geometry(links)

    times = []
    for frame in range(10):
        t_start = time.perf_counter()
        mgr.register_packet(12.0 + frame * 0.1, -72.0, "R1", "00:11:22:33:44:00", 37)
        k, c, p, b = mgr.get_active_matrix_snapshot()
        dm, zm, diff = engine.compute_mahalanobis_anomaly(k, c)
        hm = tomo.solve_attenuation_field(np.abs(diff))
        raw_pos = tomo.estimate_target_position(hm)
        tracked_pos = tracker.update(raw_pos, dt=0.1)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        times.append(elapsed_ms)

    mean_latency = float(np.mean(times))
    assert mean_latency < 10.0
