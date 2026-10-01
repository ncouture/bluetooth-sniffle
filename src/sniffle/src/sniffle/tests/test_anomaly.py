"""
Unit Tests for Robust Anomaly Detection Engine (sniffle.radar.anomaly).
"""

import math
import numpy as np
import pytest

from sniffle.radar.anomaly import (
    compute_wilson_hilferty,
    RobustAnomalyEngine,
    LinkAnomalyVector,
)


def test_compute_wilson_hilferty():
    # Boundary checks
    assert compute_wilson_hilferty(0.0, 10) == 0.0
    assert compute_wilson_hilferty(-5.0, 10) == 0.0
    assert compute_wilson_hilferty(10.0, 0) == 0.0
    assert compute_wilson_hilferty(10.0, -2) == 0.0

    # Chi-square mean is K: when d_sq == K, Z should be approximately 0
    K = 12
    z_mean = compute_wilson_hilferty(float(K), K)
    assert abs(z_mean) < 0.2

    # High d_sq gives positive Z-score
    z_high = compute_wilson_hilferty(50.0, K)
    assert z_high > 3.0


def test_link_robust_z_minimum_samples():
    engine = RobustAnomalyEngine(history_len=20)
    # 0, 1, 2 samples should return (0.0, 0.0, 0.0)
    assert engine.compute_link_robust_z("R1", "AA:BB:CC:11:22:33", 37, -60.0) == (0.0, 0.0, 0.0)
    engine.update_link_sample("R1", "AA:BB:CC:11:22:33", 37, -60.0)
    assert engine.compute_link_robust_z("R1", "AA:BB:CC:11:22:33", 37, -60.0) == (0.0, 0.0, 0.0)
    engine.update_link_sample("R1", "AA:BB:CC:11:22:33", 37, -60.0)
    assert engine.compute_link_robust_z("R1", "AA:BB:CC:11:22:33", 37, -60.0) == (0.0, 0.0, 0.0)

    # 3rd sample enables robust z calculation
    engine.update_link_sample("R1", "AA:BB:CC:11:22:33", 37, -60.0)
    z_rob, z_drop, comb = engine.compute_link_robust_z("R1", "AA:BB:CC:11:22:33", 37, -60.0)
    assert z_rob == 0.0
    assert comb == 0.0


def test_link_robust_z_drop_and_reflection_boost():
    engine = RobustAnomalyEngine(history_len=30, min_mad=0.5)
    for _ in range(15):
        engine.update_link_sample("R1", "DEV_A", 37, -60.0)

    # 12 dB attenuation drop (-72 dBm)
    z_rob, z_drop, comb = engine.compute_link_robust_z("R1", "DEV_A", 37, -72.0)
    assert z_rob >= 3.0
    assert z_drop >= 3.0
    assert comb >= 3.0

    # 6 dB multipath reflection boost (-54 dBm)
    z_rob_boost, z_drop_boost, comb_boost = engine.compute_link_robust_z("R1", "DEV_A", 37, -54.0)
    assert z_rob_boost >= 3.0
    assert z_drop_boost == 0.0
    assert comb_boost >= 3.0


def test_link_robust_z_zero_variance_mad_floor():
    engine = RobustAnomalyEngine(history_len=20, min_mad=0.5)
    for _ in range(10):
        engine.update_link_sample("R1", "STATIC_MAC", 37, -65.0)

    # Deviation with MAD=0 must use min_mad floor (0.5 dBm), preventing division by zero
    z_rob, z_drop, _ = engine.compute_link_robust_z("R1", "STATIC_MAC", 37, -68.0)
    assert not math.isnan(z_rob)
    assert not math.isinf(z_rob)
    assert z_rob > 0.0


def test_link_robust_z_pdr_penalty():
    engine = RobustAnomalyEngine(history_len=20)
    for _ in range(10):
        engine.update_link_sample("R1", "MAC_PDR", 37, -60.0)

    # RSSI is nominal (-60.0), but PDR dropped to 0.0 (total occlusion)
    z_rob, z_drop, comb = engine.compute_link_robust_z("R1", "MAC_PDR", 37, -60.0, pdr=0.0)
    assert z_rob == 0.0
    assert comb >= 6.0


def test_mahalanobis_anomaly_basic_and_freeze():
    engine = RobustAnomalyEngine(history_len=20, alpha_reg=0.05)
    keys = [f"R1_DEV_{i}_37" for i in range(6)]

    rng = np.random.RandomState(42)
    for _ in range(15):
        vec = -60.0 + rng.randn(6) * 0.2
        dm, zm, _ = engine.compute_mahalanobis_anomaly(keys, vec)

    hist_len_before = len(engine.multivariate_history)
    assert hist_len_before >= 3

    anom_vec = -60.0 * np.ones(6)
    anom_vec[0] = -75.0
    anom_vec[1] = -74.0
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, anom_vec)

    assert zm >= 3.0
    assert dm > 0.0

    assert len(engine.multivariate_history) == hist_len_before


def test_mahalanobis_singular_covariance_handling():
    engine = RobustAnomalyEngine(history_len=20, alpha_reg=0.05)
    K = 10
    keys = [f"R1_DEV_{i}_37" for i in range(K)]

    for _ in range(3):
        vec = np.ones(K) * -60.0
        engine.compute_mahalanobis_anomaly(keys, vec)

    test_vec = np.ones(K) * -60.0
    test_vec[0] = -75.0
    dm, zm, diff = engine.compute_mahalanobis_anomaly(keys, test_vec)

    assert not math.isnan(dm)
    assert not math.isnan(zm)
    assert zm >= 3.0


def test_mahalanobis_dynamic_topology_change():
    engine = RobustAnomalyEngine(history_len=20)
    keys_initial = ["K1", "K2", "K3"]
    for _ in range(5):
        engine.compute_mahalanobis_anomaly(keys_initial, np.ones(3) * -60.0)

    assert len(engine.multivariate_history) == 5

    keys_new = ["K1", "K2", "K3", "K4", "K5"]
    dm, zm, _ = engine.compute_mahalanobis_anomaly(keys_new, np.ones(5) * -60.0)
    assert len(engine.multivariate_history) == 1
    assert dm == 0.0
    assert zm == 0.0


def test_process_matrix_snapshot():
    engine = RobustAnomalyEngine(history_len=20)
    keys = ["R1_AA:BB:CC:11:22:33_37", "R2_AA:BB:CC:11:22:33_38"]
    
    for _ in range(10):
        engine.process_matrix_snapshot(keys, np.array([-60.0, -60.0]), np.array([1.0, 1.0]))

    anom_res = engine.process_matrix_snapshot(keys, np.array([-75.0, -60.0]), np.array([0.5, 1.0]))
    assert isinstance(anom_res, LinkAnomalyVector)
    assert len(anom_res.link_keys) == 2
    assert anom_res.anomaly_scores[0] >= 3.0
    assert anom_res.is_anomaly is True
