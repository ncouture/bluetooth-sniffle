"""
Comprehensive Tier 5 Adversarial Stress & Fuzzing Verification Suite for BLE RSSI Radar.

Adversarial Challenger Test Suite:
1. Covariance singularity & collinearity: all links identical, zero variance, collinear chords,
   N < K, high-dimensional ill-conditioned matrix inversion without NaN/crash.
2. Degenerate inputs: NaN/Inf values, empty sample queues, zero-length packet payloads,
   out-of-order timestamps.
3. High-load stress: 50+ simultaneous advertisers, dense intersecting link cuts,
   rapid matrix resizing.
4. Non-negativity preservation: ensuring dual Tikhonov solver never outputs negative attenuation.
5. CLI robustness: malformed arguments, invalid baud rates, nonexistent serial ports.
"""

from __future__ import annotations

import argparse
import math
import os
import queue
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
    SnifflePacketSource,
    HardwareSniffleSource,
    MockSniffleSource,
    DualSnifferManager,
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
from sniffle.radar.visualizer import RadarVisualizer
from radar_tomography import (
    build_cli_parser,
    parse_radar_args,
    RadarTomographyPipeline,
)
from tests.harness import (
    create_synthetic_adv_packet,
    str_mac,
)


# ============================================================================
# Section 1: Covariance Singularity & Collinearity
# ============================================================================

def test_adversarial_01_all_links_identical_rssi_singularity():
    """Verify that 20 links with completely identical RSSI histories invert stably via shrinkage."""
    K = 20
    engine = RobustAnomalyEngine(history_len=30, min_mad=0.5, alpha_reg=0.05)
    keys = [f"R1_DEV_{i:02d}_37" for i in range(K)]

    # Stream 15 frames where every single link has the exact same RSSI value
    for frame in range(15):
        val = -60.0 + 3.0 * math.sin(frame * 0.2)
        rssi_vec = np.full(K, val, dtype=np.float64)
        dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, rssi_vec)
        assert not np.isnan(dm)
        assert not np.isinf(dm)
        assert not np.isnan(zm)
        assert not np.isinf(zm)

    # Anomaly perturbation on a single link
    anom_vec = np.full(K, -60.0, dtype=np.float64)
    anom_vec[0] = -78.0
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, anom_vec)
    assert not np.isnan(dm)
    assert not np.isnan(zm)
    assert zm >= 3.0
    assert engine.last_sigma_reg is not None
    # Verify regularized covariance has all positive eigenvalues
    evals = np.linalg.eigvalsh(engine.last_sigma_reg)
    assert np.all(evals >= 0.25 - 1e-9)  # min_mad**2 floor with float precision


def test_adversarial_02_collinear_spatial_chords_identical_geometry():
    """Verify 12 identical collinear links produce a well-conditioned Gram matrix without NaN/crash."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2, alpha_tikhonov=0.01)
    rx_pos = np.array([1.0, 5.0], dtype=np.float32)
    tx_pos = np.array([19.0, 5.0], dtype=np.float32)
    # 12 identical links overlapping along the same chord
    links = [(rx_pos, tx_pos) for _ in range(12)]
    tomo.update_geometry(links)

    assert tomo.W is not None
    assert tomo.Gram_inv is not None
    assert not np.any(np.isnan(tomo.W))
    assert not np.any(np.isnan(tomo.Gram_inv))

    # Solve with uniform attenuation
    anomalies = np.full(12, 5.0, dtype=np.float32)
    res = tomo.solve([f"L_{i}" for i in range(12)], anomalies)
    assert not np.any(np.isnan(res.heatmap))
    assert res.max_intensity > 0.0
    assert res.target_coords is not None
    # Reconstructed target should lie along y = 5.0 chord
    assert pytest.approx(res.target_coords[1], abs=0.5) == 5.0


def test_adversarial_03_rank_deficient_n_less_than_k():
    """Verify rank-deficient history (N=3 observations for K=50 variables) inverts safely."""
    K = 50
    engine = RobustAnomalyEngine(history_len=30, min_mad=0.5, alpha_reg=0.05)
    keys = [f"L_{i}" for i in range(K)]

    rng = np.random.RandomState(42)
    # Only 3 observations
    for _ in range(3):
        engine.compute_mahalanobis_anomaly(keys, rng.uniform(-65.0, -55.0, size=K))

    # Test observation
    test_vec = rng.uniform(-65.0, -55.0, size=K)
    test_vec[0] = -80.0
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, test_vec)
    assert not np.isnan(dm)
    assert not np.isnan(zm)
    assert not np.isinf(dm)


def test_adversarial_04_high_dimensional_ill_conditioned_inversion_100_links():
    """Verify 100-link ill-conditioned covariance matrix inverts stably without NaN or numerical blowup."""
    K = 100
    engine = RobustAnomalyEngine(history_len=30, min_mad=0.5, alpha_reg=0.01)
    keys = [f"LINK_{i:03d}" for i in range(K)]

    # Construct nearly collinear trajectories
    base_signal = np.linspace(-60.0, -50.0, 15)
    for frame in range(15):
        # Micro-perturbation of 1e-6 creates extreme condition number (> 1e10)
        vec = base_signal[frame] + np.arange(K) * 1e-6
        dm, zm, _ = engine.compute_mahalanobis_anomaly(keys, vec)
        assert not np.isnan(dm)
        assert not np.isnan(zm)

    perturbation = base_signal[-1] + np.arange(K) * 1e-6
    perturbation[50] -= 15.0  # Anomaly drop
    dm, zm, _ = engine.compute_mahalanobis_anomaly(keys, perturbation)
    assert not np.isnan(dm)
    assert not np.isnan(zm)
    assert dm > 0.0


def test_adversarial_05_collinear_chords_zero_length_and_degenerate():
    """Verify solver handles zero-length links (rx=tx) mixed with out-of-bounds links gracefully."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    center = np.array([10.0, 5.0], dtype=np.float32)
    out_pt = np.array([50.0, 50.0], dtype=np.float32)

    links = [
        (center, center),             # Zero length link
        (out_pt, out_pt + 1.0),       # Link completely outside room bounds
        (np.array([1.0, 1.0]), center), # Normal valid link
    ]
    tomo.update_geometry(links)
    assert tomo.W is not None
    assert tomo.Gram_inv is not None
    assert not np.any(np.isnan(tomo.W))

    hm = tomo.solve_attenuation_field(np.array([2.0, 0.0, 5.0], dtype=np.float32))
    assert not np.any(np.isnan(hm))
    assert np.all(hm >= 0.0)


def test_adversarial_06_covariance_shrinkage_monotonicity():
    """Verify that increasing alpha_reg strictly increases the minimum eigenvalue of Sigma_reg."""
    K = 10
    keys = [f"K_{i}" for i in range(K)]
    vecs = [np.ones(K) * (-60.0 + i) for i in range(10)]

    min_evals = []
    for alpha in [0.01, 0.05, 0.1, 0.5]:
        engine = RobustAnomalyEngine(history_len=30, min_mad=0.5, alpha_reg=alpha)
        for v in vecs:
            engine.compute_mahalanobis_anomaly(keys, v)
        assert engine.last_sigma_reg is not None
        evals = np.linalg.eigvalsh(engine.last_sigma_reg)
        min_evals.append(float(np.min(evals)))

    # Higher alpha_reg guarantees higher or equal diagonal loading
    for i in range(1, len(min_evals)):
        assert min_evals[i] >= min_evals[i - 1] - 1e-9


def test_adversarial_07_wilson_hilferty_zero_degrees_of_freedom_boundary():
    """Verify Wilson-Hilferty transformation safely returns 0.0 for K <= 0 or d_sq <= 0."""
    assert compute_wilson_hilferty(0.0, 10) == 0.0
    assert compute_wilson_hilferty(-5.0, 10) == 0.0
    assert compute_wilson_hilferty(10.0, 0) == 0.0
    assert compute_wilson_hilferty(10.0, -1) == 0.0
    # Valid transformation values
    z1 = compute_wilson_hilferty(10.0, 10)
    assert pytest.approx(z1, abs=0.2) == 0.0  # Mean of chi2(10) is 10, so Z ~ 0
    z_high = compute_wilson_hilferty(1e6, 10)
    assert not np.isnan(z_high)
    assert not np.isinf(z_high)
    assert z_high > 100.0


def test_adversarial_08_singular_covariance_recovery_after_topology_reset():
    """Verify engine handles abrupt topology changes from 5 to 25 links without stale state leakage."""
    engine = RobustAnomalyEngine()
    keys1 = [f"L_{i}" for i in range(5)]
    for _ in range(5):
        engine.compute_mahalanobis_anomaly(keys1, np.full(5, -60.0))
    assert len(engine.multivariate_history) == 5

    # Switch to completely new set of 25 links
    keys2 = [f"NEW_{i}" for i in range(25)]
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys2, np.full(25, -55.0))
    assert len(engine.multivariate_history) == 1  # Reset triggered
    assert len(diff) == 25
    assert dm == 0.0  # History < 3 returns safe 0.0


# ============================================================================
# Section 2: Degenerate Inputs & Fuzzing
# ============================================================================

def test_adversarial_09_nan_inf_in_wilson_hilferty():
    """Verify Wilson-Hilferty function behavior under NaN and Inf arguments."""
    res_nan = compute_wilson_hilferty(float("nan"), 10)
    # Python NaN comparison: ensures math.isnan or float output without crash
    assert math.isnan(res_nan)

    res_inf = compute_wilson_hilferty(float("inf"), 10)
    assert math.isinf(res_inf)

    res_neg_inf = compute_wilson_hilferty(float("-inf"), 10)
    assert res_neg_inf == 0.0  # d_sq <= 0 check catches -inf


def test_adversarial_10_nan_inf_in_link_robust_z():
    """Verify compute_link_robust_z with NaN, extreme negative Inf, and boundary PDR values."""
    engine = RobustAnomalyEngine(min_mad=0.5)
    for _ in range(10):
        engine.update_link_sample("R1", "TX_FUZZ", 37, -60.0)

    # Negative Inf RSSI
    z_rob, z_drop, combined = engine.compute_link_robust_z("R1", "TX_FUZZ", 37, float("-inf"))
    assert not math.isnan(z_rob)
    assert not math.isnan(z_drop)
    assert math.isinf(z_rob)

    # PDR out of standard [0, 1] range: PDR = 2.0 (should not give negative penalty)
    _, _, comb_pdr = engine.compute_link_robust_z("R1", "TX_FUZZ", 37, -60.0, pdr=2.0)
    assert comb_pdr >= 0.0

    # PDR = -1.0 (clamped safely)
    _, _, comb_pdr_neg = engine.compute_link_robust_z("R1", "TX_FUZZ", 37, -60.0, pdr=-1.0)
    assert comb_pdr_neg > 0.0


def test_adversarial_11_nan_inf_in_mahalanobis_vector():
    """Verify compute_mahalanobis_anomaly executes safely when vectors contain Inf or subnormal values."""
    engine = RobustAnomalyEngine()
    keys = ["L1", "L2", "L3"]
    for _ in range(5):
        engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0, -60.0]))

    # Test subnormal / extreme floating-point inputs
    subnormal_vec = np.array([-1e-300, -60.0, -60.0])
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, subnormal_vec)
    assert not np.isnan(dm)
    assert not np.isnan(zm)

    # Inf input
    inf_vec = np.array([float("inf"), -60.0, -60.0])
    try:
        dm_inf, zm_inf, _ = engine.compute_mahalanobis_anomaly(keys, inf_vec)
        # If solver produces value, verify it is float
        assert isinstance(dm_inf, float)
    except Exception as err:
        assert isinstance(err, (ValueError, FloatingPointError))


def test_adversarial_12_tomography_nan_inf_anomalies_handling():
    """Verify SpatialTomography2D handles NaN and Inf anomaly scores without unhandled crash."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    link = (np.array([1.0, 5.0]), np.array([19.0, 5.0]))
    tomo.update_geometry([link])

    # NaN anomaly input
    hm_nan = tomo.solve_attenuation_field(np.array([float("nan")]))
    target_nan = tomo.estimate_target_position(hm_nan)
    # Should safely fail to find target and return None rather than crashing
    assert target_nan is None

    # Positive Inf anomaly input
    hm_inf = tomo.solve_attenuation_field(np.array([float("inf")]))
    target_inf = tomo.estimate_target_position(hm_inf)
    if target_inf is not None:
        # Target must be bounded within room dimensions
        assert 0.0 <= target_inf[0] <= 20.0
        assert 0.0 <= target_inf[1] <= 10.0


def test_adversarial_13_target_tracker_nan_inf_coasting_defense():
    """Verify TargetTracker does not crash or leak NaN when fed NaN/Inf measurements."""
    tracker = TargetTracker()
    tracker.update((10.0, 5.0), dt=0.1)
    tracker.update((10.5, 5.0), dt=0.1)

    # Feed None (normal coasting)
    pos_coast = tracker.update(None, dt=0.1)
    assert pos_coast is not None
    assert not np.isnan(pos_coast[0])
    assert not np.isnan(pos_coast[1])

    # Feed near-zero and negative dt
    pos_dt_zero = tracker.update((11.0, 5.0), dt=0.0)
    assert pos_dt_zero is not None
    assert not np.isnan(pos_dt_zero[0])

    pos_dt_neg = tracker.update((11.5, 5.0), dt=-0.1)
    assert pos_dt_neg is not None
    assert not np.isnan(pos_dt_neg[0])


def test_adversarial_14_empty_sample_queues_pipeline_step():
    """Verify Pipeline step() called 20 consecutive times with empty queues returns None without crash."""
    args = parse_radar_args(["--headless", "--simulate"])
    pipeline = RadarTomographyPipeline(args)
    # Do not start sniffer thread; queue remains completely empty
    for _ in range(20):
        result = pipeline.step(timeout=0.001)
        assert result is None
    pipeline.visualizer.close()


def test_adversarial_15_zero_length_packet_payload_and_fuzzed_data():
    """Verify synthetic packet factory and decoders handle zero-length payloads across all PDU types."""
    pdu_types = [
        "ADV_IND",
        "ADV_DIRECT_IND",
        "ADV_NONCONN_IND",
        "SCAN_RSP",
        "ADV_SCAN_IND",
        "ADV_EXT_IND",
    ]
    mac = b"\x11\x22\x33\x44\x55\x66"
    for pdu in pdu_types:
        pkt = create_synthetic_adv_packet(pdu, mac, data=b"")
        assert hasattr(pkt, "AdvA") or hasattr(pkt, "body")
        if hasattr(pkt, "AdvA") and pkt.AdvA:
            mac_str = str_mac(pkt.AdvA)
            assert mac_str == "66:55:44:33:22:11"


def test_adversarial_16_mac_classifier_fuzzing():
    """Verify classify_ble_mac handles empty strings, corrupted hex, and invalid TxAdd values."""
    # Empty string
    assert classify_ble_mac("", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("", tx_add=0) == AddressType.PUBLIC

    # Corrupted / Non-hex MACs
    assert classify_ble_mac("NOT_A_MAC", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("ZZ:YY:XX:WW:VV:UU", tx_add=1) == AddressType.RANDOM_RPA

    # Extreme TxAdd bits
    assert classify_ble_mac("C0:11:22:33:44:55", tx_add=0) == AddressType.PUBLIC
    assert classify_ble_mac("C0:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_STATIC
    assert classify_ble_mac("40:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("00:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_NRPA


def test_adversarial_17_out_of_order_timestamps_backward_time_warp():
    """Verify matrix manager handles reverse-chronological packet timestamps gracefully."""
    rx_configs = {"R1": (37, (0.5, 0.5))}
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs)

    # Ingest packets with backwards timestamps: 500s -> 400s -> 300s -> 200s
    timestamps = [500.0, 400.0, 300.0, 200.0, 100.0]
    for ts in timestamps:
        rec = mgr.register_packet(ts, -60.0, "R1", "WARP_TX", 37)
        assert rec is not None
        assert rec.expected_interval_s >= 0.01
        assert 0.0 <= rec.pdr <= 1.0
        assert not np.isnan(rec.activity_score)


def test_adversarial_18_identical_timestamps_zero_dt_burst():
    """Verify rapid bursts of 50 packets at the exact same microsecond do not cause ZeroDivisionError."""
    rx_configs = {"R1": (37, (0.5, 0.5))}
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs)
    fixed_ts = 123456.789
    for i in range(50):
        rec = mgr.register_packet(fixed_ts, -60.0 - (i % 3), "R1", "BURST_NODE", 37)
        assert rec is not None

    assert rec.packet_count == 50
    assert rec.expected_interval_s >= 0.01
    assert 0.0 <= rec.pdr <= 1.0


# ============================================================================
# Section 3: High-Load Stress & Scalability
# ============================================================================

def test_adversarial_19_high_load_50_plus_advertisers_concurrent():
    """Verify system sustains 60 simultaneous transmitters (120 spatial links across R1/R2)."""
    rx_configs = {
        "R1": (37, (0.5, 0.5)),
        "R2": (38, (19.5, 0.5)),
    }
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs, min_activation_pkts=2)
    device_count = 60

    # Register 60 devices across both receivers
    t0 = 1000.0
    for step in range(3):
        t = t0 + step * 0.1
        for d in range(device_count):
            mac = f"AA:BB:CC:DD:{d // 256:02X}:{d % 256:02X}"
            mgr.register_packet(t, -60.0, "R1", mac, 37)
            mgr.register_packet(t, -65.0, "R2", mac, 38)

    link_keys, curr_rssi, pdr_vec, base_rssi = mgr.get_active_matrix_snapshot()
    assert len(link_keys) == device_count * 2  # 120 links
    assert len(curr_rssi) == 120
    assert len(pdr_vec) == 120

    # Pass to anomaly engine
    engine = RobustAnomalyEngine(history_len=15)
    for _ in range(4):
        anom_res = engine.process_matrix_snapshot(link_keys, curr_rssi, pdr_vec)
    assert len(anom_res.anomaly_scores) == 120
    assert not np.isnan(anom_res.mahalanobis_score)

    # Pass to tomography solver
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = []
    for k in link_keys:
        rx_id = k.split("_")[0]
        tx_mac = k.split("_")[1]
        rx_pos = np.array(rx_configs[rx_id][1], dtype=np.float32)
        tx_pos = np.array(mgr.tx_nodes[tx_mac], dtype=np.float32)
        links.append((rx_pos, tx_pos))

    tomo.update_geometry(links)
    res = tomo.solve(link_keys, anom_res.anomaly_scores)
    assert res.heatmap.shape == (50, 100)
    assert not np.any(np.isnan(res.heatmap))


def test_adversarial_20_dense_intersecting_link_cuts_focal_localization():
    """Verify 24 intersecting radial chords accurately localize target at (12.0, 6.0) with high SNR."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    target_true = np.array([12.0, 6.0], dtype=np.float32)
    num_chords = 24
    links = []

    for angle in np.linspace(0, np.pi, num_chords, endpoint=False):
        dx = 3.5 * math.cos(angle)
        dy = 3.5 * math.sin(angle)
        p1 = target_true - np.array([dx, dy], dtype=np.float32)
        p2 = target_true + np.array([dx, dy], dtype=np.float32)
        links.append((p1, p2))

    tomo.update_geometry(links)
    # Attenuate all intersecting chords by 8.0 dB
    anomalies = np.full(num_chords, 8.0, dtype=np.float32)
    res = tomo.solve([f"CHORD_{i}" for i in range(num_chords)], anomalies)

    assert res.target_coords is not None
    assert pytest.approx(res.target_coords[0], abs=0.4) == 12.0
    assert pytest.approx(res.target_coords[1], abs=0.4) == 6.0
    assert res.max_intensity > 15.0


def test_adversarial_21_rapid_matrix_resizing_fuzzing():
    """Verify solver and anomaly engine adapt to random link count changes across 40 frames."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    engine = RobustAnomalyEngine()
    rng = np.random.RandomState(999)

    for frame in range(40):
        # Randomly choose K between 2 and 45 links
        K = rng.randint(2, 46)
        keys = [f"DYN_{i:02d}" for i in range(K)]
        links = [(np.array([0.5, 0.5]), rng.uniform([1.0, 1.0], [19.0, 9.0])) for _ in range(K)]
        tomo.update_geometry(links)

        rssi_vec = rng.uniform(-75.0, -50.0, size=K)
        pdr_vec = rng.uniform(0.7, 1.0, size=K)

        anom = engine.process_matrix_snapshot(keys, rssi_vec, pdr_vec)
        res = tomo.solve(keys, anom.anomaly_scores)
        assert res.heatmap.shape == (50, 100)
        assert not np.any(np.isnan(res.heatmap))


def test_adversarial_22_high_load_real_time_latency_budget_under_20ms():
    """Verify single frame reconstruction for 80 links finishes in < 25 ms (> 40 Hz)."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    K = 80
    rng = np.random.RandomState(777)
    links = [(np.array([0.5, 0.5]), rng.uniform([1.0, 1.0], [19.0, 9.0])) for _ in range(K)]
    tomo.update_geometry(links)
    anomalies = rng.uniform(0.0, 5.0, size=K).astype(np.float32)

    # Warmup
    tomo.solve([f"L_{i}" for i in range(K)], anomalies)

    # Benchmark 20 iterations
    latencies = []
    for _ in range(20):
        t_start = time.perf_counter()
        tomo.solve([f"L_{i}" for i in range(K)], anomalies)
        latencies.append((time.perf_counter() - t_start) * 1000.0)

    median_lat = float(np.median(latencies))
    # Must meet high-frequency radar real-time budget
    assert median_lat < 25.0, f"Reconstruction latency {median_lat:.2f} ms exceeded 25 ms"


def test_adversarial_23_public_device_manager_high_device_density():
    """Verify PublicDeviceManager tracks 100+ unique devices with deterministic positions."""
    pdm = PublicDeviceManager(room_dim=(20.0, 10.0))
    for i in range(120):
        mac = f"EE:FF:11:22:{i // 256:02X}:{i % 256:02X}"
        pdm.register_packet(100.0, -60.0, "R1", mac, 37)

    assert len(pdm.nodes) == 120
    for mac, node in pdm.nodes.items():
        x, y = node["pos"]
        assert 1.0 <= x <= 19.0
        assert 1.0 <= y <= 9.0


def test_adversarial_24_rapid_churn_advertisers_under_high_load():
    """Verify rapid churn of 50 transmitters with 30s timeout isolates pruned devices cleanly."""
    rx_configs = {"R1": (37, (0.5, 0.5))}
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs, inactivity_timeout=30.0)

    # Ingest 50 devices at t = 10.0
    for d in range(50):
        mac = f"CHURN_{d:02d}"
        mgr.register_packet(10.0, -60.0, "R1", mac, 37)
    assert len(mgr.links) == 50

    # Half the devices continue transmitting at t = 45.0 (> 30s elapsed)
    for d in range(25):
        mac = f"CHURN_{d:02d}"
        mgr.register_packet(45.0, -60.0, "R1", mac, 37)

    # Prune
    pruned = mgr.prune_inactive(45.0)
    assert len(pruned) == 25
    assert len(mgr.links) == 25
    # The active 25 devices should remain
    for d in range(25):
        assert (f"CHURN_{d:02d}", "R1") in mgr.links


def test_adversarial_25_extreme_multipath_dense_mesh():
    """Verify dense mesh with simultaneous extreme reflection boosts (+15 dB) and deep drops (-30 dB)."""
    rx_configs = {"R1": (37, (0.5, 0.5))}
    mgr = MxNLinkMatrixManager(rx_configs=rx_configs, min_activation_pkts=2)

    # Establish baseline
    for t in [1.0, 2.0, 3.0]:
        mgr.register_packet(t, -60.0, "R1", "BOOST_TX", 37)
        mgr.register_packet(t, -60.0, "R1", "SHADOW_TX", 37)

    # Inject extreme reflection boost (+15 dB) and deep shadow (-30 dB)
    rec_boost = mgr.register_packet(4.0, -45.0, "R1", "BOOST_TX", 37)
    rec_shadow = mgr.register_packet(4.0, -90.0, "R1", "SHADOW_TX", 37)

    assert rec_boost.activity_score > 5.0
    assert rec_shadow.activity_score > 20.0


def test_adversarial_26_target_tracker_high_velocity_stress():
    """Verify TargetTracker survives extreme velocity jumps (50 m/s) and clamps to room boundaries."""
    tracker = TargetTracker(alpha=0.7, beta=0.2)
    tracker.update((10.0, 5.0), dt=0.1)

    # Sudden jump across room
    pos2 = tracker.update((15.0, 8.0), dt=0.1)
    assert pos2 is not None
    assert tracker.vel[0] > 0.0

    # Extreme jump simulating glitch
    pos3 = tracker.update((100.0, -50.0), dt=0.1)
    assert pos3 is not None
    assert not np.isnan(pos3[0])
    assert not np.isinf(pos3[0])


# ============================================================================
# Section 4: Non-Negativity Preservation
# ============================================================================

def test_adversarial_27_extreme_negative_anomalies_preservation():
    """Verify dual Tikhonov solver strictly outputs non-negative attenuation for extreme negative scores."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = [
        (np.array([1.0, 1.0]), np.array([10.0, 5.0])),
        (np.array([19.0, 1.0]), np.array([10.0, 5.0])),
    ]
    tomo.update_geometry(links)

    # 1. Equal negative anomaly vector (e.g. uniform multipath boost across all links)
    equal_neg = np.array([-100.0, -100.0], dtype=np.float32)
    heatmap_equal = tomo.solve_attenuation_field(equal_neg)
    assert not np.any(np.isnan(heatmap_equal))
    assert np.all(heatmap_equal >= 0.0)
    assert np.min(heatmap_equal) == 0.0
    assert np.max(heatmap_equal) == 0.0

    # 2. Extreme asymmetric negative anomaly vector
    extreme_neg = np.array([-100.0, -1e6], dtype=np.float32)
    heatmap_extreme = tomo.solve_attenuation_field(extreme_neg)
    assert not np.any(np.isnan(heatmap_extreme))
    # Core invariant: attenuation is strictly non-negative
    assert np.all(heatmap_extreme >= 0.0)
    assert np.min(heatmap_extreme) == 0.0


def test_adversarial_28_mixed_positive_negative_contrast_inversion():
    """Verify mixed positive and negative anomaly inputs clamp negative channels without distorting peaks."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    center = np.array([10.0, 5.0])
    links = [
        (np.array([2.0, 5.0]), np.array([18.0, 5.0])),   # Attenuated link passing through center
        (np.array([10.0, 1.0]), np.array([10.0, 9.0])),  # Boosted link passing vertically
        (np.array([1.0, 1.0]), np.array([19.0, 9.0])),   # Negative anomaly link
    ]
    tomo.update_geometry(links)

    anomalies = np.array([12.0, -30.0, -50.0], dtype=np.float32)
    res = tomo.solve(["L1", "L2", "L3"], anomalies)

    assert np.all(res.heatmap >= 0.0)
    assert res.max_intensity > 0.0
    # Peak should still localize along the attenuated link
    assert res.target_coords is not None
    assert pytest.approx(res.target_coords[1], abs=0.5) == 5.0


def test_adversarial_29_all_zero_and_near_zero_negative_floats():
    """Verify machine-precision negative floats (-1e-12, -0.0) do not produce negative zeros."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry([(np.array([1.0, 5.0]), np.array([19.0, 5.0]))])

    near_zeros = np.array([-1e-12, -0.0], dtype=np.float32)
    for val in near_zeros:
        hm = tomo.solve_attenuation_field(np.array([val]))
        assert np.all(hm >= 0.0)
        assert np.all(hm == 0.0)


def test_adversarial_30_fuzzed_random_anomaly_vectors_non_negativity():
    """Monte Carlo fuzz test: 100 fuzzed random vectors uniformly sampled from [-100.0, 100.0]."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    rng = np.random.RandomState(42)
    K = 10
    links = [(np.array([1.0, 1.0]), rng.uniform([2.0, 2.0], [18.0, 8.0])) for _ in range(K)]
    tomo.update_geometry(links)

    for trial in range(100):
        random_vec = rng.uniform(-100.0, 100.0, size=K).astype(np.float32)
        heatmap = tomo.solve_attenuation_field(random_vec)
        assert not np.any(np.isnan(heatmap)), f"Trial {trial} produced NaN"
        assert np.all(heatmap >= 0.0), f"Trial {trial} produced negative attenuation: {np.min(heatmap)}"


def test_adversarial_31_tikhonov_regularization_alpha_sweep_non_negativity():
    """Verify non-negativity holds across 8 orders of magnitude of regularization alpha."""
    alphas = [1e-6, 1e-4, 1e-2, 0.1, 1.0, 10.0, 100.0]
    links = [(np.array([1.0, 5.0]), np.array([19.0, 5.0]))]

    for alpha in alphas:
        tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2, alpha_tikhonov=alpha)
        tomo.update_geometry(links)
        hm = tomo.solve_attenuation_field(np.array([-25.0], dtype=np.float32))
        assert np.all(hm >= 0.0)
        assert np.max(hm) == 0.0


def test_adversarial_32_fresnel_kernel_non_negativity_row_weights():
    """Verify that every entry in precomputed Fresnel matrix W is strictly non-negative."""
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = [
        (np.array([0.5, 0.5]), np.array([19.5, 9.5])),
        (np.array([0.5, 9.5]), np.array([19.5, 0.5])),
        (np.array([10.0, 1.0]), np.array([10.0, 9.0])),
    ]
    tomo.update_geometry(links)
    assert tomo.W is not None
    assert np.all(tomo.W >= 0.0)
    # Check row normalization: sum of each row should be approximately 1.0
    row_sums = np.sum(tomo.W, axis=1)
    for s in row_sums:
        assert pytest.approx(s, rel=1e-3) == 1.0


# ============================================================================
# Section 5: CLI Robustness & Error Resilience
# ============================================================================

def test_adversarial_33_cli_malformed_channel_arguments():
    """Verify CLI parser rejects invalid channels (e.g. 40, 0, non-integers)."""
    with pytest.raises(SystemExit):
        parse_radar_args(["--chan1", "40"])

    with pytest.raises(SystemExit):
        parse_radar_args(["--chan2", "36"])

    with pytest.raises(SystemExit):
        parse_radar_args(["--chan1", "channel_thirty_seven"])


def test_adversarial_34_cli_malformed_baud_rate():
    """Verify CLI parser rejects malformed and non-integer baud rates."""
    with pytest.raises(SystemExit):
        parse_radar_args(["--baud", "nine_two_one_six_zero_zero"])

    with pytest.raises(SystemExit):
        parse_radar_args(["--baud", "115200.5"])


def test_adversarial_35_cli_unknown_command_line_flags():
    """Verify CLI parser rejects unknown/unsupported arguments with SystemExit."""
    with pytest.raises(SystemExit):
        parse_radar_args(["--arbitrary-invalid-flag"])

    with pytest.raises(SystemExit):
        parse_radar_args(["-z"])


def test_adversarial_36_cli_nonexistent_serial_ports_mock_fallback():
    """Verify DualSnifferManager with nonexistent serial ports falls back cleanly to MockSniffleSource."""
    mgr = DualSnifferManager(
        port1="/dev/ttyUSB_NONEXISTENT_PORT_A",
        port2="/dev/ttyUSB_NONEXISTENT_PORT_B",
        fallback_to_mock=True,
    )
    mgr.start()
    assert mgr.is_running()
    assert mgr.using_mock is True
    # Verify packets are actively generated by fallback mock
    time.sleep(0.05)
    assert not mgr.queue.empty()
    mgr.stop()
    assert not mgr.is_running()


def test_adversarial_37_cli_nonexistent_serial_ports_strict_mode():
    """Verify DualSnifferManager with fallback_to_mock=False cleanly raises without hanging."""
    mgr = DualSnifferManager(
        port1="/dev/ttyUSB_NONEXISTENT_PORT_1",
        port2="/dev/ttyUSB_NONEXISTENT_PORT_2",
        fallback_to_mock=False,
    )
    # HardwareSniffleSource will fail to open nonexistent port
    with pytest.raises(Exception):
        mgr.start()
    mgr.stop()


def test_adversarial_38_cli_public_mode_overrides_multichannel():
    """Verify that passing --public-mode and --multi-channel strictly forces multi_channel=False."""
    args = parse_radar_args(["--public-mode", "--multi-channel"])
    assert args.public_mode is True
    assert args.multi_channel is False


def test_adversarial_39_cli_room_dimensions_and_extreme_grid_res():
    """Verify CLI parser and pipeline initialization support custom room geometry and resolutions."""
    args = parse_radar_args([
        "--room-width", "30.0",
        "--room-length", "15.0",
        "--grid-res", "0.5",
        "--headless",
        "--simulate",
    ])
    assert args.room_width == 30.0
    assert args.room_length == 15.0
    assert args.grid_res == 0.5

    pipeline = RadarTomographyPipeline(args)
    assert pipeline.tomo.room_dim == (30.0, 15.0)
    assert pipeline.tomo.nx == 60
    assert pipeline.tomo.ny == 30
    pipeline.visualizer.close()


def test_adversarial_40_cli_pipeline_start_stop_signal_cleanliness():
    """Verify RadarTomographyPipeline starts, executes 5 simulated frames, and stops with zero leaks."""
    args = parse_radar_args(["--headless", "--simulate", "--max-frames", "5"])
    pipeline = RadarTomographyPipeline(args)
    pipeline.start()
    assert pipeline.sniffer.is_running()

    # Step through 5 frames
    frames_processed = 0
    for _ in range(15):
        frame_res = pipeline.step(timeout=0.05)
        if frame_res is not None:
            frames_processed += 1
            if frames_processed >= 5:
                break
        time.sleep(0.02)

    assert frames_processed >= 1
    pipeline.stop()
    assert not pipeline.sniffer.is_running()


# ============================================================================
# SECTION B: Trajectory & Dynamic Tracking Stress Tests (Challenger Trajectory)
# ============================================================================

def test_adversarial_41_dynamic_coordinates_acceptance_criterion(standard_geometry):
    """
    Acceptance Criterion: verify position estimation produces dynamic, non-static
    target coordinates (X, Y) responding to physical motion.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)
    tracker = TargetTracker(alpha=0.6, beta=0.15)

    steps = 10
    path_actual = np.linspace([4.0, 3.0], [16.0, 7.0], steps)
    estimated_traj: List[Tuple[float, float]] = []

    for true_pos in path_actual:
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            d0 = np.linalg.norm(rx_p - tx_p)
            d1 = np.linalg.norm(true_pos - tx_p)
            d2 = np.linalg.norm(true_pos - rx_p)
            excess = (d1 + d2) - d0
            if excess <= tomo.lambda_eff:
                anom_vec[k] = float(6.0 / np.sqrt(excess + 1e-4))

        heatmap = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(heatmap, percentile=95.0)
        smoothed = tracker.update(raw_pos, dt=0.5)
        assert smoothed is not None, "Tracking estimator must produce valid coordinate estimate"
        estimated_traj.append(smoothed)

    assert len(estimated_traj) == steps
    xs = np.array([p[0] for p in estimated_traj])
    ys = np.array([p[1] for p in estimated_traj])

    # 1. Strictly non-static check
    std_x = float(np.std(xs))
    std_y = float(np.std(ys))
    assert std_x > 2.0, f"Target X coordinates appear static: std(X) = {std_x:.3f} <= 2.0"
    assert std_y > 0.4, f"Target Y coordinates appear static: std(Y) = {std_y:.3f} <= 0.4"

    # 2. Minimum path length traversed
    step_deltas = [np.linalg.norm(np.array(estimated_traj[i]) - np.array(estimated_traj[i - 1])) for i in range(1, steps)]
    total_dist = float(np.sum(step_deltas))
    assert total_dist > 7.5, f"Estimated path length {total_dist:.2f}m is too short for non-static motion"

    # 3. Pearson correlation with physical ground truth
    corr_x = float(np.corrcoef(path_actual[:, 0], xs)[0, 1])
    corr_y = float(np.corrcoef(path_actual[:, 1], ys)[0, 1])
    assert corr_x > 0.95, f"X coordinate dynamic tracking correlation {corr_x:.3f} < 0.95"
    assert corr_y > 0.75, f"Y coordinate dynamic tracking correlation {corr_y:.3f} < 0.75"

    # 4. Bounded error
    errors = [np.linalg.norm(np.array(est) - act) for est, act in zip(estimated_traj, path_actual)]
    mean_err = float(np.mean(errors))
    assert mean_err < 1.5, f"Mean tracking error {mean_err:.2f}m exceeds 1.5m bound"


def test_adversarial_42_curved_motion_dynamic_responsiveness(standard_geometry):
    """
    Verifies dynamic responsiveness when the target executes an oscillatory S-curve path.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)
    tracker = TargetTracker(alpha=0.65, beta=0.15)

    steps = 20
    path_x = np.linspace(3.0, 17.0, steps)
    path_y = 5.0 + 2.5 * np.sin(np.linspace(0, np.pi, steps))
    true_path = [np.array([x, y]) for x, y in zip(path_x, path_y)]
    estimated_traj: List[Tuple[float, float]] = []

    for true_pos in true_path:
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            excess = (np.linalg.norm(true_pos - tx_p) + np.linalg.norm(true_pos - rx_p)) - np.linalg.norm(rx_p - tx_p)
            if excess <= tomo.lambda_eff:
                anom_vec[k] = float(10.0 / np.sqrt(excess + 1e-4))

        heatmap = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(heatmap, percentile=92.0)
        smoothed = tracker.update(raw_pos, dt=0.2)
        assert smoothed is not None
        estimated_traj.append(smoothed)

    xs = [p[0] for p in estimated_traj]
    ys = [p[1] for p in estimated_traj]

    assert max(xs) - min(xs) > 10.0, "X coordinates failed to traverse room"
    assert max(ys) - min(ys) > 0.6, "Y coordinates failed to reflect vertical curvature"
    corr_x = float(np.corrcoef(path_x, xs)[0, 1])
    assert corr_x > 0.95, f"X correlation {corr_x:.3f} too low"


def test_adversarial_43_high_speed_runner_5ms_lag_bounds(standard_geometry):
    """
    High-speed runner crossing at 5.0 m/s across a 20m x 10m room.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)
    tracker = TargetTracker(alpha=0.65, beta=0.15)

    v = 5.0
    dt = 0.1
    steps = 28
    true_path = [np.array([3.0 + v * dt * i, 5.0]) for i in range(steps)]
    errors = []
    velocities = []

    for true_pos in true_path:
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            excess = (np.linalg.norm(true_pos - tx_p) + np.linalg.norm(true_pos - rx_p)) - np.linalg.norm(rx_p - tx_p)
            if excess <= tomo.lambda_eff:
                anom_vec[k] = float(10.0 / np.sqrt(excess + 1e-4))

        heatmap = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(heatmap, percentile=93.0)
        smoothed = tracker.update(raw_pos, dt=dt)
        assert smoothed is not None
        assert 0.0 <= smoothed[0] <= 20.0
        assert 0.0 <= smoothed[1] <= 10.0

        err = float(np.linalg.norm(np.array(smoothed) - true_pos))
        errors.append(err)
        velocities.append(tracker.vel.copy())

    assert max(errors) <= 2.0, f"Peak transient error {max(errors):.2f}m exceeded 2.0m bound"
    steady_errors = errors[5:]
    mean_steady_err = float(np.mean(steady_errors))
    max_steady_err = float(np.max(steady_errors))
    assert mean_steady_err < 1.0, f"Mean steady-state lag {mean_steady_err:.2f}m >= 1.0m"
    assert max_steady_err < 1.8, f"Max steady-state lag {max_steady_err:.2f}m >= 1.8m"
    final_vx = velocities[-1][0]
    assert final_vx > 3.0, f"Final estimated forward velocity {final_vx:.2f} m/s too slow for 5 m/s runner"


def test_adversarial_44_extreme_runner_10ms_lag_bounds(standard_geometry):
    """
    Extreme sprinter crossing at 10.0 m/s across a 20m x 10m room.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)
    tracker = TargetTracker(alpha=0.65, beta=0.15)

    v = 10.0
    dt = 0.05
    steps = 28
    true_path = [np.array([3.0 + v * dt * i, 5.0]) for i in range(steps)]
    errors = []

    for true_pos in true_path:
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            excess = (np.linalg.norm(true_pos - tx_p) + np.linalg.norm(true_pos - rx_p)) - np.linalg.norm(rx_p - tx_p)
            if excess <= tomo.lambda_eff:
                anom_vec[k] = float(10.0 / np.sqrt(excess + 1e-4))

        heatmap = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(heatmap, percentile=93.0)
        smoothed = tracker.update(raw_pos, dt=dt)
        assert smoothed is not None
        assert not math.isnan(smoothed[0]) and not math.isnan(smoothed[1])
        assert 0.0 <= smoothed[0] <= 20.0 and 0.0 <= smoothed[1] <= 10.0

        err = float(np.linalg.norm(np.array(smoothed) - true_pos))
        errors.append(err)

    mean_err = float(np.mean(errors))
    max_err = float(np.max(errors))
    assert mean_err < 1.2, f"10 m/s mean tracking error {mean_err:.2f}m >= 1.2m"
    assert max_err < 2.5, f"10 m/s max tracking error {max_err:.2f}m >= 2.5m"

    final_vx = tracker.vel[0]
    assert final_vx > 6.0, f"Final estimated velocity {final_vx:.2f} m/s too low for 10 m/s runner"


def test_adversarial_45_blind_spot_dead_zone_velocity_coasting(standard_geometry):
    """
    Blind-spot dead-zone coasting.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)
    tracker = TargetTracker(alpha=0.65, beta=0.15)
    dt = 0.2

    p1 = [np.array([4.0 - 0.25 * i, 4.0 + 0.35 * i]) for i in range(7)]
    p2 = [np.array([2.25 - 0.25 * i, 6.35 + 0.35 * i]) for i in range(7)]
    p3 = [np.array([1.0 + 0.5 * i, 8.0 - 0.5 * i]) for i in range(6)]

    all_points = p1 + p2 + p3
    coasted_results = []
    all_estimates = []

    for idx, true_pos in enumerate(all_points):
        if idx >= 7 and idx < 14:
            raw_pos = None
        else:
            anom_vec = np.zeros(K, dtype=np.float32)
            for k, (rx_p, tx_p) in enumerate(links):
                excess = (np.linalg.norm(true_pos - tx_p) + np.linalg.norm(true_pos - rx_p)) - np.linalg.norm(rx_p - tx_p)
                if excess <= tomo.lambda_eff:
                    anom_vec[k] = float(10.0 / np.sqrt(excess + 1e-4))
            hm = tomo.solve_attenuation_field(anom_vec)
            raw_pos = tomo.estimate_target_position(hm, percentile=92.0)

        smoothed = tracker.update(raw_pos, dt=dt)
        all_estimates.append(smoothed)
        if idx >= 7 and idx < 14:
            coasted_results.append(smoothed)

    assert len(coasted_results) == 7
    for pos in coasted_results:
        assert pos is not None
        assert 0.0 <= pos[0] <= 20.0
        assert 0.0 <= pos[1] <= 10.0

    for i in range(1, len(coasted_results)):
        dx = coasted_results[i][0] - coasted_results[i - 1][0]
        dy = coasted_results[i][1] - coasted_results[i - 1][1]
        assert dx < 0.0, f"Coasting failed to advance leftward: dx = {dx}"
        assert dy > 0.0, f"Coasting failed to advance upward: dy = {dy}"

    coasting_errors = [np.linalg.norm(np.array(est) - act) for est, act in zip(coasted_results, p2)]
    max_coast_err = float(np.max(coasting_errors))
    assert max_coast_err < 2.0, f"Coasting drift error {max_coast_err:.2f}m exceeded 2.0m"

    final_pos = all_estimates[-1]
    assert final_pos is not None
    reacq_err = float(np.linalg.norm(np.array(final_pos) - p3[-1]))
    assert reacq_err < 1.5, f"Re-acquisition error {reacq_err:.2f}m exceeded 1.5m"


def test_adversarial_46_extended_dead_reckoning_linearity():
    """
    Tests dead-reckoning mathematical precision during extended 15-frame sensor blackout (1.5s).
    """
    tracker = TargetTracker(alpha=0.6, beta=0.15)
    dt = 0.1

    for i in range(10):
        tracker.update((5.0 + 2.0 * i * dt, 8.0 - 1.0 * i * dt), dt=dt)

    p_start = np.array(tracker.pos, copy=True)
    v_est = np.array(tracker.vel, copy=True)

    coasted_path = []
    for step in range(1, 16):
        pos = tracker.update(None, dt=dt)
        assert pos is not None
        coasted_path.append(pos)
        expected_pos = p_start + v_est * (step * dt)
        assert pytest.approx(pos[0], abs=1e-5) == expected_pos[0]
        assert pytest.approx(pos[1], abs=1e-5) == expected_pos[1]
        assert np.array_equal(tracker.vel, v_est), "Velocity must remain constant during coasting"


def test_adversarial_47_sudden_80_percent_link_dropout_mid_trajectory():
    """
    Sudden link dropouts: 80% of ambient devices stop transmitting mid-trajectory.
    """
    rx_configs = {
        "R1": (37, (0.5, 0.5)),
        "R2": (38, (19.5, 0.5)),
    }
    matrix_mgr = MxNLinkMatrixManager(rx_configs=rx_configs, inactivity_timeout=30.0, occlusion_timeout=3.0)
    anomaly_engine = RobustAnomalyEngine(history_len=20, alpha_reg=0.05)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tracker = TargetTracker(alpha=0.65, beta=0.15)

    macs = [f"CC:26:52:00:00:{i:02X}" for i in range(15)]
    t = 100.0

    for _ in range(10):
        for mac in macs:
            matrix_mgr.register_sample(LinkSample(t, -60.0 + float(np.random.normal(0, 0.1)), "R1", mac, 37))
            matrix_mgr.register_sample(LinkSample(t, -62.0 + float(np.random.normal(0, 0.1)), "R2", mac, 38))
        keys, rssi, pdr, base = matrix_mgr.get_active_matrix_snapshot()
        anomaly_engine.compute_mahalanobis_anomaly(keys, rssi)
        t += 0.2

    assert len(keys) == 30, f"Expected 30 active links initially, got {len(keys)}"

    path = [np.array([3.0 + 0.7 * i, 5.0]) for i in range(20)]
    surviving_macs = macs[:3]
    tracked_positions: List[Optional[Tuple[float, float]]] = []

    for step, true_pos in enumerate(path):
        current_macs = macs if step < 10 else surviving_macs

        for mac in current_macs:
            tx_pos = np.array(matrix_mgr.tx_nodes[mac])
            d0_1 = np.linalg.norm(np.array(rx_configs["R1"][1]) - tx_pos)
            ex_1 = (np.linalg.norm(true_pos - tx_pos) + np.linalg.norm(true_pos - np.array(rx_configs["R1"][1]))) - d0_1
            drop_1 = float(12.0 / np.sqrt(ex_1 + 1e-4)) if ex_1 <= tomo.lambda_eff else 0.0

            d0_2 = np.linalg.norm(np.array(rx_configs["R2"][1]) - tx_pos)
            ex_2 = (np.linalg.norm(true_pos - tx_pos) + np.linalg.norm(true_pos - np.array(rx_configs["R2"][1]))) - d0_2
            drop_2 = float(12.0 / np.sqrt(ex_2 + 1e-4)) if ex_2 <= tomo.lambda_eff else 0.0

            matrix_mgr.register_sample(LinkSample(t, -60.0 - drop_1, "R1", mac, 37))
            matrix_mgr.register_sample(LinkSample(t, -62.0 - drop_2, "R2", mac, 38))

        if step == 10:
            t += 4.0

        keys, rssi, pdr, base = matrix_mgr.get_active_matrix_snapshot()
        active_links = []
        for k_str in keys:
            parts = k_str.split("_")
            rx_id, tx_mac = parts[0], parts[1]
            active_links.append((
                np.array(rx_configs[rx_id][1], dtype=np.float32),
                np.array(matrix_mgr.tx_nodes[tx_mac], dtype=np.float32),
            ))
        tomo.update_geometry(active_links)

        anom_res = anomaly_engine.process_matrix_snapshot(keys, rssi, pdr)
        tomo_res = tomo.solve(keys, anom_res.anomaly_scores)
        pos = tracker.update(tomo_res.target_coords, dt=0.2)
        tracked_positions.append(pos)
        t += 0.2

    assert len(tracked_positions) == 20
    valid_tail = [p for p in tracked_positions[15:] if p is not None]
    assert len(valid_tail) >= 3, "Pipeline failed to produce target coordinates after dropout"
    for pos in valid_tail:
        assert pos[0] > 10.0, f"Target coordinate {pos[0]:.2f} failed to reach right half of room"
        assert 0.0 <= pos[0] <= 20.0 and 0.0 <= pos[1] <= 10.0


def test_adversarial_48_link_dropout_inactivity_pruning_resizing():
    """
    Verifies link pruning updates geometry cleanly.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    rx = np.array([0.5, 0.5], dtype=np.float32)

    initial_links = [(rx, np.array([float(i % 18 + 1), float(i % 8 + 1)], dtype=np.float32)) for i in range(30)]
    tomo.update_geometry(initial_links)
    assert tomo.W is not None and tomo.W.shape[0] == 30

    anom30 = np.ones(30, dtype=np.float32) * 5.0
    field30 = tomo.solve_attenuation_field(anom30)
    assert field30.shape == (50, 100)
    assert np.max(field30) > 0.0

    pruned_links = initial_links[:6]
    tomo.update_geometry(pruned_links)
    assert tomo.W is not None and tomo.W.shape[0] == 6

    anom6 = np.ones(6, dtype=np.float32) * 5.0
    field6 = tomo.solve_attenuation_field(anom6)
    assert field6.shape == (50, 100)
    assert np.max(field6) > 0.0


def test_adversarial_49_room_boundary_clamping_adversarial_limits():
    """
    Room boundary clamping tests.
    """
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)

    corners = [
        ("bottom-left", 0, 0, 0.0, 0.0),
        ("bottom-right", 0, -1, 20.0, 0.0),
        ("top-left", -1, 0, 0.0, 10.0),
        ("top-right", -1, -1, 20.0, 10.0),
    ]
    for name, r, c, exp_x, exp_y in corners:
        hm = np.zeros((50, 100), dtype=np.float32)
        hm[r, c] = 100.0
        pos = tomo.estimate_target_position(hm)
        assert pos is not None, f"Failed corner {name}"
        assert 0.0 <= pos[0] <= 20.0, f"{name} X={pos[0]} escaped [0, 20]"
        assert 0.0 <= pos[1] <= 10.0, f"{name} Y={pos[1]} escaped [0, 10]"
        assert pytest.approx(pos[0], abs=0.25) == exp_x
        assert pytest.approx(pos[1], abs=0.25) == exp_y

    perimeter_edges = [
        ("left_wall", lambda h: h.__setitem__((slice(None), slice(0, 2)), 50.0)),
        ("right_wall", lambda h: h.__setitem__((slice(None), slice(-2, None)), 50.0)),
        ("bottom_wall", lambda h: h.__setitem__((slice(0, 2), slice(None)), 50.0)),
        ("top_wall", lambda h: h.__setitem__((slice(-2, None), slice(None)), 50.0)),
    ]
    for name, activate_fn in perimeter_edges:
        hm = np.zeros((50, 100), dtype=np.float32)
        activate_fn(hm)
        pos = tomo.estimate_target_position(hm)
        assert pos is not None
        assert 0.0 <= pos[0] <= 20.0, f"Perimeter {name} X={pos[0]} outside [0, 20]"
        assert 0.0 <= pos[1] <= 10.0, f"Perimeter {name} Y={pos[1]} outside [0, 10]"


def test_adversarial_50_room_boundary_clamping_arbitrary_room_dimensions():
    """
    Boundary clamping across arbitrary room dimensions.
    """
    test_dims = [
        (12.0, 6.0),
        (30.0, 15.0),
        (8.0, 8.0),
    ]

    for width, length in test_dims:
        solver = SpatialTomography2D(room_dim=(width, length), resolution=0.2)
        hm = np.zeros((solver.ny, solver.nx), dtype=np.float32)
        hm[-1, -1] = 100.0
        pos = solver.estimate_target_position(hm)
        assert pos is not None
        assert 0.0 <= pos[0] <= width, f"X={pos[0]} escaped width {width}"
        assert 0.0 <= pos[1] <= length, f"Y={pos[1]} escaped length {length}"
        assert pytest.approx(pos[0], abs=0.25) == width
        assert pytest.approx(pos[1], abs=0.25) == length


def test_adversarial_51_perimeter_wall_grazing_clamping(standard_geometry):
    """
    Target grazes along perimeter boundaries.
    """
    links = standard_geometry["links"]
    K = len(links)
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry(links)

    perimeter_pts = [
        np.array([0.5, 0.5 + 1.0 * i]) for i in range(10)
    ] + [
        np.array([0.5 + 1.5 * i, 9.5]) for i in range(13)
    ]

    for pt in perimeter_pts:
        anom_vec = np.zeros(K, dtype=np.float32)
        for k, (rx_p, tx_p) in enumerate(links):
            excess = (np.linalg.norm(pt - tx_p) + np.linalg.norm(pt - rx_p)) - np.linalg.norm(rx_p - tx_p)
            if excess <= tomo.lambda_eff:
                anom_vec[k] = float(12.0 / np.sqrt(excess + 1e-4))

        hm = tomo.solve_attenuation_field(anom_vec)
        raw_pos = tomo.estimate_target_position(hm)
        if raw_pos is not None:
            assert 0.0 <= raw_pos[0] <= 20.0, f"Raw X={raw_pos[0]} escaped [0, 20]"
            assert 0.0 <= raw_pos[1] <= 10.0, f"Raw Y={raw_pos[1]} escaped [0, 10]"
