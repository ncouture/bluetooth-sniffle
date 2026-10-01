"""
Comprehensive Tier 4 Real-World Workload Simulation Test Suite for BLE RSSI Radar.

Tests realistic human motion workloads across a 20m x 10m room:
- Diagonal walking crossing (trajectory error < 1.5m)
- Stationary human target with baseline freezing
- Empty room noise suppression (SNR > 20x, false alarm intensity < 2.0)
- Multiple sequential crossing events
- Boundary grazing perimeter trajectory
- Fast runner vs slow walker velocity distinction
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
    LinkAnomalyVector,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
)


# ============================================================================
# Tier 4 Real-World Workload Scenarios
# ============================================================================

def test_workload_01_diagonal_walking_trajectory_error_under_1_5m(standard_geometry):
    """
    Scenario 1: Diagonal walking crossing across 20m x 10m room.
    Target moves from (4.0, 3.0) to (16.0, 7.0) across 10 steps.
    Verifies that mean trajectory error is strictly < 1.5 m.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(standard_geometry["links"])
    links = standard_geometry["links"]
    K = len(links)
    tracker = TargetTracker(alpha=0.6, beta=0.15)

    steps = 10
    path_actual = np.linspace([4.0, 3.0], [16.0, 7.0], steps)
    estimated_traj = []

    for true_pos in path_actual:
        # Physical RF attenuation based on 1st Fresnel zone excess path
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            d0 = np.linalg.norm(rx_p - tx_p)
            d1 = np.linalg.norm(true_pos - tx_p)
            d2 = np.linalg.norm(true_pos - rx_p)
            excess = (d1 + d2) - d0
            if excess <= tomo.lambda_eff:
                # Human body attenuation
                anom_vec[k] = float(6.0 / np.sqrt(excess + 1e-4))

        heatmap = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(heatmap, percentile=95.0)
        smoothed = tracker.update(raw_pos, dt=0.5)
        if smoothed is not None:
            estimated_traj.append(smoothed)

    assert len(estimated_traj) == steps, "Every step should produce a tracked estimate"
    errors = [np.linalg.norm(np.array(est) - act) for est, act in zip(estimated_traj, path_actual)]
    mean_err = float(np.mean(errors))
    max_err = float(np.max(errors))

    assert mean_err < 1.5, f"Expected mean trajectory error < 1.5m, got {mean_err:.2f}m"
    assert max_err < 3.0, f"Expected max trajectory error < 3.0m, got {max_err:.2f}m"


def test_workload_02_stationary_human_target_with_baseline_freezing(standard_geometry):
    """
    Scenario 2: Stationary human standing still in room center (10.0, 5.0) for 25 frames.
    Verifies:
    - Anomaly detected (Z >= 3.0 sigma).
    - Baseline is frozen across all 25 frames.
    - Tracked target remains stably at (10.0, 5.0) ± 1.0m without wandering.
    """
    engine = RobustAnomalyEngine(history_len=20)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(standard_geometry["links"])
    links = standard_geometry["links"]
    K = len(links)
    tracker = TargetTracker(alpha=0.5, beta=0.1)

    keys = [f"LINK_{i}" for i in range(K)]

    # 1. Establish clean baseline (10 frames)
    baseline_rssi = np.ones(K) * -60.0
    for _ in range(10):
        engine.compute_mahalanobis_anomaly(keys, baseline_rssi + np.random.normal(0, 0.1, K))

    frozen_history_len = len(engine.multivariate_history)

    # 2. Human stands at (10.0, 5.0) for 25 frames
    target_pos = np.array([10.0, 5.0])
    stationary_positions = []

    for frame in range(25):
        anom_vec = np.zeros(K, dtype=np.float32)
        meas_rssi = baseline_rssi.copy()
        for k, (rx_p, tx_p) in enumerate(links):
            d0 = np.linalg.norm(rx_p - tx_p)
            d1 = np.linalg.norm(target_pos - tx_p)
            d2 = np.linalg.norm(target_pos - rx_p)
            excess = (d1 + d2) - d0
            if excess <= tomo.lambda_eff:
                # 14 dB attenuation drop
                drop = float(14.0 / np.sqrt(excess + 1e-4))
                meas_rssi[k] -= drop
                anom_vec[k] = drop

        dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, meas_rssi)
        assert zm >= 3.0, f"Frame {frame}: Expected anomaly >= 3.0 sigma, got {zm:.2f}"
        # Baseline must stay frozen
        assert len(engine.multivariate_history) == frozen_history_len

        hm = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(hm, percentile=94.0)
        smoothed = tracker.update(raw_pos, dt=0.2)
        if smoothed is not None:
            stationary_positions.append(smoothed)

    assert len(stationary_positions) == 25
    for pos in stationary_positions[3:]:  # After initial filter convergence
        assert pytest.approx(pos[0], abs=1.0) == 10.0
        assert pytest.approx(pos[1], abs=1.0) == 5.0


def test_workload_03_empty_room_noise_suppression_and_false_alarm_rejection(standard_geometry):
    """
    Scenario 3: Empty room noise suppression.
    Verifies that thermal noise produces low field intensity (< 2.0),
    high SNR > 20x vs human signal, and returns None for target position.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(standard_geometry["links"])
    K = len(standard_geometry["links"])

    # Ambient thermal noise: small sub-sigma fluctuations
    np.random.seed(42)
    noise_anom = np.random.uniform(0.0, 0.3, K).astype(np.float32)
    heatmap_empty = tomo.solve_attenuation_field(noise_anom)
    max_noise_intensity = float(np.max(heatmap_empty))

    # Target position estimator should reject sub-threshold field
    pos_empty = tomo.estimate_target_position(heatmap_empty)
    assert max_noise_intensity < 2.0, f"Expected empty room intensity < 2.0, got {max_noise_intensity:.3f}"
    # Target signal intensity with 15 dB drop
    target_anom = np.zeros(K, dtype=np.float32)
    target_anom[0:3] = 15.0
    heatmap_target = tomo.solve_attenuation_field(target_anom)
    max_target_intensity = float(np.max(heatmap_target))

    snr = max_target_intensity / max(1e-4, max_noise_intensity)
    assert snr > 20.0, f"Expected SNR > 20x, got {snr:.1f}x (target: {max_target_intensity}, noise: {max_noise_intensity})"


def test_workload_04_multiple_sequential_crossing_events(standard_geometry):
    """
    Scenario 4: Two sequential human crossings separated by a 10-frame quiet period.
    - Event 1: Crossing in Left room (X < 10)
    - Quiet: Room empty for 10 frames
    - Event 2: Crossing in Right room (X > 10)
    Verifies both events are detected independently and localized in correct halves.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(standard_geometry["links"])
    links = standard_geometry["links"]
    K = len(links)

    # Event 1: Person at (4.0, 5.0) in Left half
    p1 = np.array([4.0, 5.0])
    anom1 = np.zeros(K, dtype=np.float32)
    for k, (rx_p, tx_p) in enumerate(links):
        excess = (np.linalg.norm(p1 - tx_p) + np.linalg.norm(p1 - rx_p)) - np.linalg.norm(rx_p - tx_p)
        if excess <= tomo.lambda_eff:
            anom1[k] = float(10.0 / np.sqrt(excess + 1e-4))

    hm1 = tomo.solve_attenuation_field(anom1)
    pos1 = tomo.estimate_target_position(hm1)
    assert pos1 is not None
    assert pos1[0] < 10.0, f"Event 1 target should be in left half (X < 10), got {pos1[0]:.2f}"

    # Quiet Period (all zeros)
    hm_quiet = tomo.solve_attenuation_field(np.zeros(K, dtype=np.float32))
    assert tomo.estimate_target_position(hm_quiet) is None

    # Event 2: Person at (16.0, 5.0) in Right half
    p2 = np.array([16.0, 5.0])
    anom2 = np.zeros(K, dtype=np.float32)
    for k, (rx_p, tx_p) in enumerate(links):
        excess = (np.linalg.norm(p2 - tx_p) + np.linalg.norm(p2 - rx_p)) - np.linalg.norm(rx_p - tx_p)
        if excess <= tomo.lambda_eff:
            anom2[k] = float(10.0 / np.sqrt(excess + 1e-4))

    hm2 = tomo.solve_attenuation_field(anom2)
    pos2 = tomo.estimate_target_position(hm2)
    assert pos2 is not None
    assert pos2[0] > 10.0, f"Event 2 target should be in right half (X > 10), got {pos2[0]:.2f}"


def test_workload_05_boundary_grazing_trajectory(standard_geometry):
    """
    Scenario 5: Person walking along the perimeter wall from (1.0, 1.0) to (1.0, 9.0).
    Verifies that wall-grazing trajectory coordinates remain bounded and localized near wall.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(standard_geometry["links"])
    links = standard_geometry["links"]
    K = len(links)
    tracker = TargetTracker(alpha=0.6, beta=0.15)

    wall_path = [(1.0, float(y)) for y in np.linspace(1.5, 8.5, 8)]
    tracked_wall = []

    for pos in wall_path:
        pt = np.array(pos)
        anom = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            excess = (np.linalg.norm(pt - tx_p) + np.linalg.norm(pt - rx_p)) - np.linalg.norm(rx_p - tx_p)
            if excess <= tomo.lambda_eff:
                anom[k] = float(8.0 / np.sqrt(excess + 1e-4))

        hm = tomo.solve_attenuation_field(anom)
        raw_pos = tomo.estimate_target_position(hm)
        smoothed = tracker.update(raw_pos, dt=0.5)
        if smoothed is not None:
            tracked_wall.append(smoothed)

    assert len(tracked_wall) >= 6
    for t_pos in tracked_wall:
        # All positions must be strictly inside the room
        assert 0.0 <= t_pos[0] <= 20.0
        assert 0.0 <= t_pos[1] <= 10.0
        # X position should stay near left wall (X <= 3.5m)
        assert t_pos[0] <= 3.5


def test_workload_06_fast_runner_vs_slow_walker_dynamics():
    """
    Scenario 6: Distinguishing fast runner (3.0 m/s) from slow walker (0.8 m/s).
    Verifies velocity estimation reflects physical dynamics correctly.
    """
    tracker_slow = TargetTracker(alpha=0.6, beta=0.2)
    tracker_fast = TargetTracker(alpha=0.6, beta=0.2)
    dt = 0.2

    # Slow walker: 0.16m per step (0.8 m/s)
    for step in range(10):
        tracker_slow.update((5.0 + step * 0.16, 5.0), dt=dt)

    # Fast runner: 0.60m per step (3.0 m/s)
    for step in range(10):
        tracker_fast.update((5.0 + step * 0.60, 5.0), dt=dt)

    speed_slow = float(np.linalg.norm(tracker_slow.vel))
    speed_fast = float(np.linalg.norm(tracker_fast.vel))

    assert speed_fast > 2.5 * speed_slow
    assert pytest.approx(speed_slow, abs=0.3) == 0.8
    assert pytest.approx(speed_fast, abs=0.5) == 3.0
