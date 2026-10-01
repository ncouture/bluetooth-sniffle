"""
Comprehensive Tier 1 Feature Coverage Test Suite for BLE RSSI Radar.

Covers all 17 features from PROJECT.md § Feature Inventory (F1 to F17)
with at least 5 distinct, rigorous test cases per feature (85+ tests).
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
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

import sniffle
import sniffle.sniffle_hw
from sniffle.sniffle_hw import SniffleHW, SnifferMode, make_sniffle_hw
from sniffle.packet_decoder import (
    str_mac,
    AdvIndMessage,
    AdvNonconnIndMessage,
    ScanRspMessage,
    AdvScanIndMessage,
    AdvExtIndMessage,
)
from sniffle.errors import UsageError

from sniffle.radar.capture import (
    LinkSample,
    HardwareSniffleSource,
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
    compute_wilson_hilferty,
    RobustAnomalyEngine,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
)
from sniffle.radar.visualizer import (
    RadarVisualizer,
    RadarFrameProcessor,
    run_single_frame,
    run_radar_pipeline,
)
from radar_tomography import (
    build_cli_parser,
    parse_radar_args,
    RadarTomographyPipeline,
)
from tests.harness import create_synthetic_adv_packet


# ============================================================================
# F1: Dual Fixed-Channel Locking
# ============================================================================

def test_f1_01_r1_locked_to_channel_37():
    """Verify HardwareSniffleSource for R1 locks explicitly to Channel 37."""
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make:
        mock_hw = MagicMock()
        mock_make.return_value = mock_hw
        source = HardwareSniffleSource(port="/dev/ttyUSB0", channel=37, rx_id="R1")
        source.start()
        mock_hw.setup_sniffer.assert_called_once()
        _, kwargs = mock_hw.setup_sniffer.call_args
        assert kwargs["chan"] == 37
        assert kwargs["hop3"] is False
        source.stop()


def test_f1_02_r2_locked_to_channel_38():
    """Verify HardwareSniffleSource for R2 locks explicitly to Channel 38."""
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make:
        mock_hw = MagicMock()
        mock_make.return_value = mock_hw
        source = HardwareSniffleSource(port="/dev/ttyUSB1", channel=38, rx_id="R2")
        source.start()
        mock_hw.setup_sniffer.assert_called_once()
        _, kwargs = mock_hw.setup_sniffer.call_args
        assert kwargs["chan"] == 38
        assert kwargs["hop3"] is False
        source.stop()


def test_f1_03_default_baudrate_921600():
    """Verify default baudrate is set to 921600 for CP2102 hardware bridge throughput."""
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make:
        mock_hw = MagicMock()
        mock_make.return_value = mock_hw
        source = HardwareSniffleSource(port="/dev/ttyUSB0", channel=37, rx_id="R1")
        source.start()
        mock_make.assert_called_once_with("/dev/ttyUSB0", baudrate=921600, logger=source._logger)
        source.stop()


def test_f1_04_hop3_false_configuration():
    """Verify hop3=False is strictly enforced on hardware sniffer configuration."""
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make:
        mock_hw = MagicMock()
        mock_make.return_value = mock_hw
        source = HardwareSniffleSource(port="/dev/ttyUSB0", channel=37, rx_id="R1")
        source.start()
        mock_hw.setup_sniffer.assert_called_once()
        call_kwargs = mock_hw.setup_sniffer.call_args[1]
        assert call_kwargs.get("hop3") is False
        assert call_kwargs.get("targ_mac") is None
        source.stop()


def test_f1_05_invalid_primary_advertising_channels_rejected():
    """Verify channels outside BLE primary advertising channels (37, 38, 39) raise ValueError."""
    for invalid_ch in [0, 1, 36, 40, 50]:
        with pytest.raises(ValueError, match="Invalid primary advertising channel"):
            HardwareSniffleSource(port="/dev/ttyUSB0", channel=invalid_ch, rx_id="R1")


# ============================================================================
# F2: Channel-Hop Error Mitigation
# ============================================================================

def test_f2_01_hop3_false_prevents_usage_error_chan37():
    """Verify that chan=37 with hop3=False does not trigger UsageError on SniffleHW."""
    with patch("sniffle.sniffle_hw.Serial") as mock_ser:
        mock_ser.return_value = MagicMock()
        hw = SniffleHW(serport="/dev/ttyUSB0", baudrate=921600)
        hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=37, hop3=False)


def test_f2_02_hop3_false_prevents_usage_error_chan38():
    """Verify that chan=38 with hop3=False does not trigger UsageError on SniffleHW."""
    with patch("sniffle.sniffle_hw.Serial") as mock_ser:
        mock_ser.return_value = MagicMock()
        hw = SniffleHW(serport="/dev/ttyUSB1", baudrate=921600)
        hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=38, hop3=False)


def test_f2_03_hop3_true_without_target_raises_usage_error():
    """Reproduce the exact hardware error when hop3=True is supplied without target."""
    with patch("sniffle.sniffle_hw.Serial") as mock_ser:
        mock_ser.return_value = MagicMock()
        hw = SniffleHW(serport="/dev/ttyUSB0", baudrate=921600)
        with pytest.raises(UsageError, match="Must specify a target for advertising channel hop"):
            hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=37, hop3=True)


def test_f2_04_dual_sniffer_manager_initializes_both_sources_without_usage_error():
    """Verify DualSnifferManager configures both dongles safely without channel hop errors."""
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make:
        mock_hw1 = MagicMock()
        mock_hw2 = MagicMock()
        mock_make.side_effect = [mock_hw1, mock_hw2]

        mgr = DualSnifferManager(port1="/dev/ttyUSB0", port2="/dev/ttyUSB1", simulate=False)
        mgr.start()
        assert mgr.is_running()

        for mock_hw in [mock_hw1, mock_hw2]:
            mock_hw.setup_sniffer.assert_called_once()
            _, kwargs = mock_hw.setup_sniffer.call_args
            assert kwargs["hop3"] is False

        mgr.stop()


def test_f2_05_channel_lock_guard_in_public_mode():
    """Verify that public mode flag automatically locks channels and disables multi_channel hopping."""
    args = parse_radar_args(["--public-mode", "--multi-channel"])
    assert args.public_mode is True
    assert args.multi_channel is False


# ============================================================================
# F3: Correct Packet MAC Extraction
# ============================================================================

def _make_raw_packet(pdu_type: int, mac_bytes: bytes, rssi: int = -60):
    pkt = MagicMock()
    pkt.body = bytes([pdu_type, 6 + len(mac_bytes)]) + mac_bytes + b"\x00" * 4
    pkt.rssi = rssi
    return pkt


def test_f3_01_mac_extraction_adv_ind():
    mac_bytes = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
    pkt = _make_raw_packet(0x00, mac_bytes, -55)
    msg = AdvIndMessage(pkt)
    assert msg.AdvA == mac_bytes
    assert str_mac(msg.AdvA) == "BC:9A:78:56:34:12"


def test_f3_02_mac_extraction_adv_nonconn_ind():
    mac_bytes = bytes([0xAA, 0x11, 0x22, 0x33, 0x44, 0xBB])
    pkt = _make_raw_packet(0x02, mac_bytes, -62)
    msg = AdvNonconnIndMessage(pkt)
    assert str_mac(msg.AdvA) == "BB:44:33:22:11:AA"


def test_f3_03_mac_extraction_scan_rsp():
    mac_bytes = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    pkt = _make_raw_packet(0x04, mac_bytes, -70)
    msg = ScanRspMessage(pkt)
    assert str_mac(msg.AdvA) == "06:05:04:03:02:01"


def test_f3_04_mac_extraction_adv_scan_ind():
    mac_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
    pkt = _make_raw_packet(0x06, mac_bytes, -58)
    msg = AdvScanIndMessage(pkt)
    assert str_mac(msg.AdvA) == "FE:CA:EF:BE:AD:DE"


def test_f3_05_mac_extraction_adv_ext_ind():
    mac_bytes = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    pkt = MagicMock()
    pkt.body = bytes([0x07, 0x07, 0x07, 0x01]) + mac_bytes
    pkt.rssi = -68
    msg = AdvExtIndMessage(pkt)
    assert str_mac(msg.AdvA) == "66:55:44:33:22:11"


# ============================================================================
# F4: Mock/Demo Serial Feeder
# ============================================================================

def test_f4_01_mock_feeder_generates_10_plus_devices():
    mock = MockSniffleSource(rx_id="R1", channels=[37, 38], seed=42)
    samples = mock.generate_samples(count=120)
    unique_macs = {s.tx_mac for s in samples}
    assert len(unique_macs) >= 10


def test_f4_02_mock_feeder_log_distance_path_loss():
    custom_txs = [
        {"mac": "11:22:33:44:55:01", "name": "Near", "pos": (1.0, 5.0), "interval": 0.1, "tx_power": -40.0},
        {"mac": "11:22:33:44:55:02", "name": "Far", "pos": (16.0, 5.0), "interval": 0.1, "tx_power": -40.0},
    ]
    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=(0.0, 5.0),
        channel=37,
        transmitters=custom_txs,
        noise_std=0.0,
        simulate_target=False,
    )
    samples = mock.generate_samples(count=20)
    rssi_near = [s.rssi for s in samples if s.tx_mac == "11:22:33:44:55:01"][0]
    rssi_far = [s.rssi for s in samples if s.tx_mac == "11:22:33:44:55:02"][0]
    assert rssi_near > rssi_far + 15.0


def test_f4_03_mock_feeder_multipath_noise_variation():
    custom_txs = [{"mac": "AA:BB:CC:00:11:22", "name": "TX", "pos": (5.0, 5.0), "interval": 0.05, "tx_power": -40.0}]
    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=(0.0, 5.0),
        channel=37,
        transmitters=custom_txs,
        noise_std=2.0,
        simulate_target=False,
        seed=123,
    )
    samples = mock.generate_samples(count=40)
    rssis = [s.rssi for s in samples]
    assert np.std(rssis) > 0.8


def test_f4_04_mock_feeder_target_occlusion_drop():
    custom_txs = [{"mac": "AA:BB:CC:00:11:99", "name": "TX", "pos": (10.0, 5.0), "interval": 0.1, "tx_power": -40.0}]
    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=(0.0, 5.0),
        channel=37,
        transmitters=custom_txs,
        noise_std=1.0,
        max_target_attenuation=14.0,
        pdr_drop_prob=0.0,
        seed=42,
    )
    mock.set_simulate_target(False)
    base_samples = [s.rssi for s in mock.generate_samples(count=25)]
    base_mean = float(np.mean(base_samples))

    mock.set_simulate_target(True)
    mock.set_target_pos((5.0, 5.0))
    occ_samples = [s.rssi for s in mock.generate_samples(count=25)]
    occ_mean = float(np.mean(occ_samples))

    drop = base_mean - occ_mean
    assert drop >= 3.0 * 1.0


def test_f4_05_mock_feeder_seed_reproducibility():
    m1 = MockSniffleSource(rx_id="R1", seed=777)
    m2 = MockSniffleSource(rx_id="R1", seed=777)
    s1 = m1.generate_samples(count=30)
    s2 = m2.generate_samples(count=30)
    for a, b in zip(s1, s2):
        assert a.timestamp == b.timestamp
        assert a.rssi == b.rssi
        assert a.tx_mac == b.tx_mac


# ============================================================================
# F5: Ambient Device Discovery
# ============================================================================

def test_f5_01_ambient_discovery_tracks_10_plus_public_devices(device_manager):
    macs = [f"00:11:22:33:44:{i:02X}" for i in range(12)]
    t = 100.0
    for mac in macs:
        device_manager.register_packet(t, -60.0, "R1", mac, 37, tx_add=0)
    active = device_manager.get_active_nodes()
    assert len(active) == 12


def test_f5_02_mac_classification_public_address():
    addr_type = classify_ble_mac("AA:BB:CC:DD:EE:FF", tx_add=0)
    assert addr_type == AddressType.PUBLIC


def test_f5_03_mac_classification_random_types():
    assert classify_ble_mac("C1:22:33:44:55:66", tx_add=1) == AddressType.RANDOM_STATIC
    assert classify_ble_mac("45:22:33:44:55:66", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("0A:22:33:44:55:66", tx_add=1) == AddressType.RANDOM_NRPA


def test_f5_04_ambient_device_spatial_coordinates_within_bounds(device_manager):
    for i in range(15):
        mac = f"AA:BB:00:11:22:{i:02X}"
        device_manager.register_packet(100.0, -65.0, "R1", mac, 37)
    nodes = device_manager.get_active_nodes()
    for mac, data in nodes.items():
        x, y = data.position if hasattr(data, "position") else data["pos"]
        assert 0.0 <= x <= 20.0
        assert 0.0 <= y <= 10.0


def test_f5_05_ambient_device_packet_counter_increments(device_manager):
    mac = "AA:BB:CC:DD:EE:01"
    device_manager.register_packet(100.0, -65.0, "R1", mac, 37)
    device_manager.register_packet(101.5, -64.0, "R1", mac, 37)
    nodes = device_manager.nodes if hasattr(device_manager, "nodes") else device_manager.get_active_nodes()
    assert nodes[mac]["packet_count"] == 2
    assert nodes[mac]["last_seen"] == 101.5


# ============================================================================
# F6: M x 2 Link Matrix
# ============================================================================

def test_f6_01_m_by_2_link_matrix_tracking_2m_links(matrix_manager):
    M = 10
    macs = [f"10:00:00:00:00:{i:02X}" for i in range(M)]
    t = 100.0
    for mac in macs:
        matrix_manager.register_packet(t, -60.0, "R1", mac, 37)
        matrix_manager.register_packet(t, -62.0, "R2", mac, 38)

    assert len(matrix_manager.links) == 2 * M


def test_f6_02_link_matrix_dual_receiver_assignment(matrix_manager):
    matrix_manager.register_packet(10.0, -60.0, "R1", "AA:01", 37)
    matrix_manager.register_packet(10.0, -60.0, "R2", "AA:01", 38)
    assert matrix_manager.links[("AA:01", "R1")].channel == 37
    assert matrix_manager.links[("AA:01", "R2")].channel == 38


def test_f6_03_link_matrix_get_matrix_dense_shape(matrix_manager):
    for i in range(5):
        mac = f"DEV_{i}"
        for _ in range(3):
            matrix_manager.register_packet(1.0, -60.0, "R1", mac, 37)
            matrix_manager.register_packet(1.0, -60.0, "R2", mac, 38)
    mat, txs, rxs = matrix_manager.get_matrix()
    assert mat.shape == (5, 2)
    assert len(txs) == 5
    assert len(rxs) == 2


def test_f6_04_link_matrix_snapshot_vectors(matrix_manager):
    for i in range(4):
        mac = f"DEV_{i}"
        for _ in range(4):
            matrix_manager.register_packet(1.0, -55.0 - i, "R1", mac, 37)
            matrix_manager.register_packet(1.0, -57.0 - i, "R2", mac, 38)
    keys, curr, pdr, base = matrix_manager.get_active_matrix_snapshot()
    assert len(keys) == 8
    assert len(curr) == 8
    assert len(pdr) == 8
    assert len(base) == 8


def test_f6_05_link_matrix_asymmetric_reception(matrix_manager):
    for _ in range(4):
        matrix_manager.register_packet(1.0, -60.0, "R1", "DEV_ASYMM", 37)
    assert ("DEV_ASYMM", "R1") in matrix_manager.links
    assert ("DEV_ASYMM", "R2") not in matrix_manager.links


# ============================================================================
# F7: Link Lifecycle & Pruning
# ============================================================================

def test_f7_01_link_lifecycle_discovering_state(matrix_manager):
    rec = matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_DISC", 37)
    assert rec.state == LinkState.DISCOVERING


def test_f7_02_link_lifecycle_promotion_to_active(matrix_manager):
    for _ in range(matrix_manager.min_activation_pkts):
        rec = matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_PROM", 37)
    assert rec.state == LinkState.ACTIVE


def test_f7_03_link_lifecycle_occlusion_to_degraded(matrix_manager):
    for _ in range(3):
        matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_DEG", 37)
    assert matrix_manager.links[("MAC_DEG", "R1")].state == LinkState.ACTIVE

    matrix_manager._update_link_features(matrix_manager.links[("MAC_DEG", "R1")], current_time=14.0)
    assert matrix_manager.links[("MAC_DEG", "R1")].state == LinkState.DEGRADED


def test_f7_04_link_lifecycle_stale_to_pruned(matrix_manager):
    for _ in range(3):
        matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_STALE", 37)
    pruned = matrix_manager.prune_inactive(current_time=45.0)
    assert "MAC_STALE" in pruned
    assert ("MAC_STALE", "R1") not in matrix_manager.links


def test_f7_05_link_lifecycle_recovery_from_degraded(matrix_manager):
    for _ in range(3):
        matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_REC", 37)
    matrix_manager._update_link_features(matrix_manager.links[("MAC_REC", "R1")], current_time=14.0)
    assert matrix_manager.links[("MAC_REC", "R1")].state == LinkState.DEGRADED

    rec = matrix_manager.register_packet(14.5, -60.0, "R1", "MAC_REC", 37)
    assert rec.state == LinkState.ACTIVE


# ============================================================================
# F8: RF Sensing Guardrails
# ============================================================================

def test_f8_01_rf_sensing_guardrails_pdr_penalty_scale(matrix_manager):
    t0 = 10.0
    for i in range(4):
        matrix_manager.register_packet(t0 + i * 0.1, -60.0, "R1", "MAC_GUARD", 37)
    rec = matrix_manager.links[("MAC_GUARD", "R1")]
    assert rec.state == LinkState.ACTIVE

    matrix_manager._update_link_features(rec, current_time=t0 + 4.5)
    assert rec.state == LinkState.DEGRADED
    assert rec.pdr == 0.0
    assert rec.activity_score >= 15.0


def test_f8_02_rf_sensing_guardrails_max_15db_penalty_at_zero_pdr(matrix_manager):
    t0 = 20.0
    for i in range(4):
        matrix_manager.register_packet(t0 + i * 0.1, -60.0, "R1", "MAC_ZERO_PDR", 37)
    rec = matrix_manager.links[("MAC_ZERO_PDR", "R1")]
    matrix_manager._update_link_features(rec, current_time=t0 + 4.0)
    assert rec.pdr == 0.0
    assert rec.activity_score >= 15.0


def test_f8_03_rf_sensing_guardrails_absolute_multipath_reflection(matrix_manager):
    for _ in range(5):
        matrix_manager.register_packet(10.0, -60.0, "R1", "MAC_REFL", 37)
    matrix_manager.register_packet(10.1, -52.0, "R1", "MAC_REFL", 37)
    rec = matrix_manager.links[("MAC_REFL", "R1")]
    assert rec.activity_score > 0.0


def test_f8_04_rf_sensing_guardrails_turbulence_std_penalty(matrix_manager):
    for val in [-50.0, -70.0, -52.0, -68.0, -51.0]:
        matrix_manager.register_packet(10.0, val, "R1", "MAC_TURB", 37)
    rec = matrix_manager.links[("MAC_TURB", "R1")]
    assert rec.activity_score > 5.0


def test_f8_05_rf_sensing_guardrails_robust_z_pdr_drop_penalty(anomaly_engine):
    for _ in range(10):
        anomaly_engine.update_link_sample("R1", "MAC_PDR_ENG", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z(
        "R1", "MAC_PDR_ENG", 37, -60.0, pdr=0.0
    )
    assert combined >= 6.0


# ============================================================================
# F9: Robust Z-Score Engine
# ============================================================================

def test_f9_01_robust_z_median_mad_centering(anomaly_engine):
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "DEV_Z", 37, -60.0)
    anomaly_engine.update_link_sample("R1", "DEV_Z", 37, 20.0)

    z_rob, _, _ = anomaly_engine.compute_link_robust_z("R1", "DEV_Z", 37, -60.0)
    assert z_rob < 1.0


def test_f9_02_robust_z_mad_floor_0_5_dbm(anomaly_engine):
    for _ in range(10):
        anomaly_engine.update_link_sample("R1", "DEV_STATIC", 37, -65.0)
    z_rob, _, _ = anomaly_engine.compute_link_robust_z("R1", "DEV_STATIC", 37, -66.0)
    expected_z = 0.6745 * (1.0 / 0.5)
    assert pytest.approx(z_rob, rel=1e-2) == expected_z


def test_f9_03_robust_z_anomaly_detection_ge_3sigma(anomaly_engine):
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "DEV_CROSS", 37, -60.0)
    z_rob, z_drop, combined = anomaly_engine.compute_link_robust_z("R1", "DEV_CROSS", 37, -72.0)
    assert z_rob >= 3.0
    assert z_drop >= 3.0
    assert combined >= 3.0


def test_f9_04_robust_z_nominal_noise_under_3sigma(anomaly_engine):
    for _ in range(15):
        anomaly_engine.update_link_sample("R1", "DEV_NOM", 37, -60.0)
    z_rob, _, combined = anomaly_engine.compute_link_robust_z("R1", "DEV_NOM", 37, -61.0)
    assert z_rob < 3.0
    assert combined < 3.0


def test_f9_05_robust_z_insufficient_history_returns_zeros(anomaly_engine):
    anomaly_engine.update_link_sample("R1", "DEV_FEW", 37, -60.0)
    anomaly_engine.update_link_sample("R1", "DEV_FEW", 37, -60.0)
    assert anomaly_engine.compute_link_robust_z("R1", "DEV_FEW", 37, -70.0) == (0.0, 0.0, 0.0)


# ============================================================================
# F10: Regularized Mahalanobis Distance
# ============================================================================

def test_f10_01_mahalanobis_covariance_shrinkage_diagonal_loading(anomaly_engine):
    keys = [("R1", f"D{i}", 37) for i in range(4)]
    for _ in range(6):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(4) * -60.0)
    assert anomaly_engine.last_sigma_reg is not None
    assert np.all(np.diag(anomaly_engine.last_sigma_reg) > 0.0)


def test_f10_02_mahalanobis_singular_covariance_n_less_k(anomaly_engine):
    K = 10
    keys = [("R1", f"DEV_{i}", 37) for i in range(K)]
    for _ in range(3):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(K) * -60.0)
    test_vec = np.ones(K) * -60.0
    test_vec[0] = -75.0
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, test_vec)
    assert not np.isnan(dm)
    assert not np.isnan(zm)
    assert zm >= 3.0


def test_f10_03_mahalanobis_collinear_links_handled(anomaly_engine):
    keys = [("R1", "L1", 37), ("R1", "L2", 37)]
    for _ in range(5):
        val = np.random.randn()
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0 + val, -60.0 + val]))
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-75.0, -60.0]))
    assert not np.isnan(dm)


def test_f10_04_mahalanobis_zero_variance_channels(anomaly_engine):
    keys = [("R1", "L1", 37), ("R1", "L2", 37)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0]))
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0]))
    assert dm == 0.0


def test_f10_05_mahalanobis_distance_positive_semi_definite(anomaly_engine):
    keys = [("R1", "L1", 37), ("R2", "L2", 38)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -62.0]))
    dm, _, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-65.0, -68.0]))
    assert dm >= 0.0


# ============================================================================
# F11: Wilson-Hilferty Transformation
# ============================================================================

def test_f11_01_wilson_hilferty_transforms_chi_sq_to_normal_z():
    K = 10
    z = compute_wilson_hilferty(float(K), K)
    assert abs(z) < 0.3


def test_f11_02_wilson_hilferty_zero_input_returns_zero():
    assert compute_wilson_hilferty(0.0, 5) == 0.0
    assert compute_wilson_hilferty(-5.0, 5) == 0.0


def test_f11_03_wilson_hilferty_scaling_across_degrees_of_freedom():
    for K in [1, 5, 20]:
        z_nominal = compute_wilson_hilferty(float(K), K)
        assert abs(z_nominal) < 0.5
        z_anomaly = compute_wilson_hilferty(float(K * 16), K)
        assert z_anomaly >= 3.0


def test_f11_04_wilson_hilferty_monotonic_increase():
    K = 8
    z_prev = -999.0
    for d_sq in [1.0, 5.0, 10.0, 20.0, 50.0]:
        z = compute_wilson_hilferty(d_sq, K)
        assert z > z_prev
        z_prev = z


def test_f11_05_wilson_hilferty_negative_or_zero_k_safety():
    assert compute_wilson_hilferty(10.0, 0) == 0.0
    assert compute_wilson_hilferty(10.0, -3) == 0.0


# ============================================================================
# F12: Selective Baseline Freezing
# ============================================================================

def test_f12_01_selective_baseline_freezing_active_anomaly_held(anomaly_engine):
    keys = [("R1", f"DEV_{i}", 37) for i in range(4)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(4) * -60.0)
    baseline_len_before = len(anomaly_engine.multivariate_history)

    test_vec = np.array([-78.0, -60.0, -60.0, -60.0])
    dm, zm, _ = anomaly_engine.compute_mahalanobis_anomaly(keys, test_vec)
    assert zm >= 3.0

    assert len(anomaly_engine.multivariate_history) == baseline_len_before


def test_f12_02_selective_baseline_freezing_nominal_updated(anomaly_engine):
    keys = [("R1", f"DEV_{i}", 37) for i in range(4)]
    for _ in range(4):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(4) * -60.0)
    len_before = len(anomaly_engine.multivariate_history)

    anomaly_engine.compute_mahalanobis_anomaly(keys, np.ones(4) * -60.2)
    assert len(anomaly_engine.multivariate_history) == len_before + 1


def test_f12_03_selective_baseline_freezing_unfreezes_after_anomaly(anomaly_engine):
    keys = [("R1", "D1", 37), ("R2", "D2", 38)]
    for _ in range(5):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0]))
    anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-78.0, -60.0]))
    len_anom = len(anomaly_engine.multivariate_history)
    anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0]))
    assert len(anomaly_engine.multivariate_history) == len_anom + 1


def test_f12_04_selective_baseline_freezing_history_bounded(anomaly_engine):
    keys = [("R1", "D1", 37)]
    for _ in range(45):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0]))
    assert len(anomaly_engine.multivariate_history) <= anomaly_engine.history_len


def test_f12_05_selective_baseline_freezing_preserves_clean_covariance(anomaly_engine):
    keys = [("R1", "D1", 37), ("R2", "D2", 38)]
    for _ in range(10):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-60.0, -60.0]))
    clean_history = [v.copy() for v in anomaly_engine.multivariate_history]

    for _ in range(20):
        anomaly_engine.compute_mahalanobis_anomaly(keys, np.array([-80.0, -60.0]))

    for h_orig, h_now in zip(clean_history, anomaly_engine.multivariate_history):
        np.testing.assert_array_equal(h_orig, h_now)


# ============================================================================
# F13: 1st Fresnel Zone Kernel
# ============================================================================

def test_f13_01_fresnel_kernel_excess_path_length():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2, lambda_eff=0.25)
    r1 = np.array([0.0, 5.0])
    tx = np.array([10.0, 5.0])
    tomo.update_geometry([(r1, tx)])
    assert tomo.W is not None
    assert tomo.W.shape[0] == 1
    assert tomo.W.shape[1] == 50 * 100
    assert np.any(tomo.W > 0.0)


def test_f13_02_fresnel_kernel_grid_dimensions():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    assert tomo.nx == 100
    assert tomo.ny == 50
    assert tomo.P == 5000


def test_f13_03_fresnel_kernel_row_normalization():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = [
        (np.array([1.0, 1.0]), np.array([10.0, 8.0])),
        (np.array([18.0, 1.0]), np.array([5.0, 9.0])),
    ]
    tomo.update_geometry(links)
    assert tomo.W is not None
    row_sums = np.sum(tomo.W, axis=1)
    for s in row_sums:
        assert pytest.approx(s, rel=1e-3) == 1.0


def test_f13_04_fresnel_kernel_zero_weight_outside_fresnel_zone():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2, lambda_eff=0.2)
    link = (np.array([2.0, 1.0]), np.array([8.0, 1.0]))
    tomo.update_geometry([link])

    gx = tomo.gx.ravel()
    gy = tomo.gy.ravel()
    dist_corner = np.sqrt((gx - 19.0)**2 + (gy - 9.0)**2)
    corner_idx = int(np.argmin(dist_corner))
    assert tomo.W[0, corner_idx] == 0.0


def test_f13_05_fresnel_kernel_empty_links_handling():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0))
    tomo.update_geometry([])
    assert tomo.W is None
    assert tomo.Gram_inv is None


# ============================================================================
# F14: Dual-Space Tikhonov Solver
# ============================================================================

def test_f14_01_dual_tikhonov_non_negativity_max_zero():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0))
    link = (np.array([2.0, 2.0]), np.array([18.0, 8.0]))
    tomo.update_geometry([link])
    heatmap = tomo.solve_attenuation_field(np.array([-5.0]))
    assert np.all(heatmap >= 0.0)


def test_f14_02_dual_tikhonov_fast_inversion_gram_matrix():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    r1 = np.array([0.5, 0.5])
    r2 = np.array([19.5, 0.5])
    tx_nodes = [np.array([i * 1.5 + 1.0, 9.0]) for i in range(12)]
    links = []
    for tx in tx_nodes:
        links.append((r1, tx))
        links.append((r2, tx))
    tomo.update_geometry(links)

    anom = np.random.uniform(0.0, 5.0, len(links))
    t0 = time.perf_counter()
    heatmap = tomo.solve_attenuation_field(anom)
    elapsed = (time.perf_counter() - t0) * 1000.0
    assert elapsed < 15.0
    assert heatmap.shape == (50, 100)


def test_f14_03_dual_tikhonov_localization_near_attenuated_link():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    l1 = (np.array([1.0, 2.0]), np.array([19.0, 2.0]))
    l2 = (np.array([1.0, 8.0]), np.array([19.0, 8.0]))
    tomo.update_geometry([l1, l2])

    hm = tomo.solve_attenuation_field(np.array([10.0, 0.0]))
    pos = tomo.estimate_target_position(hm)
    assert pos is not None
    assert pos[1] < 5.0


def test_f14_04_dual_tikhonov_regularization_alpha_parameter():
    tomo_low = SpatialTomography2D(room_dim=(20.0, 10.0), alpha_tikhonov=0.001)
    tomo_high = SpatialTomography2D(room_dim=(20.0, 10.0), alpha_tikhonov=1.0)
    links = [(np.array([1.0, 5.0]), np.array([19.0, 5.0]))]
    tomo_low.update_geometry(links)
    tomo_high.update_geometry(links)

    anom = np.array([5.0])
    hm_low = tomo_low.solve_attenuation_field(anom)
    hm_high = tomo_high.solve_attenuation_field(anom)
    assert np.max(hm_low) > np.max(hm_high)


def test_f14_05_dual_tikhonov_zero_anomaly_produces_zero_field():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0))
    tomo.update_geometry([(np.array([1.0, 1.0]), np.array([10.0, 5.0]))])
    hm = tomo.solve_attenuation_field(np.array([0.0]))
    assert np.max(hm) == 0.0


# ============================================================================
# F15: Dynamic Target Tracking
# ============================================================================

def test_f15_01_dynamic_target_tracking_centroid_roi_extraction():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    x0, y0 = 12.0, 6.0
    dist_sq = (tomo.gx - x0)**2 + (tomo.gy - y0)**2
    heatmap = np.exp(-dist_sq / 1.0).astype(np.float32)
    pos = tomo.estimate_target_position(heatmap, percentile=90.0)
    assert pos is not None
    assert pytest.approx(pos[0], abs=0.4) == 12.0
    assert pytest.approx(pos[1], abs=0.4) == 6.0


def test_f15_02_dynamic_target_tracking_alpha_beta_filter_smoothing():
    tracker = TargetTracker(alpha=0.5, beta=0.1)
    tracker.update((10.0, 5.0))
    smoothed = tracker.update((12.0, 5.0), dt=0.1)
    assert smoothed is not None
    assert 10.0 < smoothed[0] < 12.0


def test_f15_03_dynamic_target_tracking_velocity_estimation():
    tracker = TargetTracker(alpha=0.7, beta=0.2)
    tracker.update((2.0, 2.0), dt=0.5)
    tracker.update((3.0, 2.0), dt=0.5)
    tracker.update((4.0, 2.0), dt=0.5)
    assert tracker.vel[0] > 0.5
    assert abs(tracker.vel[1]) < 0.2


def test_f15_04_dynamic_target_tracking_blindspot_coasting():
    tracker = TargetTracker(alpha=0.7, beta=0.2)
    tracker.update((5.0, 5.0), dt=1.0)
    tracker.update((6.0, 5.0), dt=1.0)
    pos_before_coast = tracker.pos[0]
    coasted = tracker.update(None, dt=1.0)
    assert coasted is not None
    assert coasted[0] > pos_before_coast


def test_f15_05_dynamic_target_tracking_boundary_clamping():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    heatmap = np.zeros((50, 100), dtype=np.float32)
    heatmap[:, -1] = 10.0
    pos = tomo.estimate_target_position(heatmap)
    assert pos is not None
    assert 0.0 <= pos[0] <= 20.0
    assert 0.0 <= pos[1] <= 10.0


# ============================================================================
# F16: CLI Runner Flags & Argument Parsing
# ============================================================================

def test_f16_01_cli_parser_defaults():
    args = parse_radar_args([])
    assert args.port1 == "/dev/ttyUSB0"
    assert args.port2 == "/dev/ttyUSB1"
    assert args.chan1 == 37
    assert args.chan2 == 38
    assert args.baud == 921600
    assert args.public_mode is True


def test_f16_02_cli_parser_custom_ports_and_channels():
    args = parse_radar_args([
        "--port1", "/dev/ttyUSB2",
        "--port2", "/dev/ttyUSB3",
        "--chan1", "38",
        "--chan2", "39",
        "--baud", "115200",
    ])
    assert args.port1 == "/dev/ttyUSB2"
    assert args.port2 == "/dev/ttyUSB3"
    assert args.chan1 == 38
    assert args.chan2 == 39
    assert args.baud == 115200


def test_f16_03_cli_parser_invalid_channel_raises_error():
    with pytest.raises((ValueError, SystemExit)):
        parse_radar_args(["--chan1", "36"])


def test_f16_04_cli_parser_public_mode_overrides_multi_channel():
    args = parse_radar_args(["--public-mode", "--multi-channel"])
    assert args.public_mode is True
    assert args.multi_channel is False


def test_f16_05_cli_parser_room_dimensions_and_grid_resolution():
    args = parse_radar_args([
        "--room-width", "25.0",
        "--room-length", "15.0",
        "--grid-res", "0.1",
        "--alpha-reg", "0.08",
    ])
    assert args.room_width == 25.0
    assert args.room_length == 15.0
    assert args.grid_res == 0.1
    assert args.alpha_reg == 0.08


# ============================================================================
# F17: Live Heatmap Rendering & Headless Mode Execution
# ============================================================================

def test_f17_01_visualizer_initialization_geometry():
    vis = RadarVisualizer(room_dim=(20.0, 10.0), headless=True)
    rxs = [{"pos": (0.5, 0.5)}, {"pos": (19.5, 0.5)}]
    txs = [{"pos": (5.0, 8.0)}, {"pos": (15.0, 8.0)}]
    links = [((0.5, 0.5), (5.0, 8.0)), ((19.5, 0.5), (15.0, 8.0))]
    vis.init_plot(receivers=rxs, transmitters=txs, links=links)
    assert len(vis.rx_artists) >= 2
    assert len(vis.tx_artists) >= 2
    assert len(vis.chord_artists) >= 2
    vis.close()


def test_f17_02_visualizer_target_trail_history():
    vis = RadarVisualizer(room_dim=(20.0, 10.0), headless=True)
    vis.update_target((5.0, 5.0))
    vis.update_target((5.5, 5.2))
    assert len(vis.trail_history) == 2
    assert vis.trail_history[-1] == (5.5, 5.2)
    vis.close()


def test_f17_03_single_frame_headless_mode():
    t_start = time.time()
    samples = [LinkSample(t_start, -60.0, "R1", "AA:BB:CC:11:22:33", 37)]
    frame = run_single_frame(samples, headless=True)

    assert isinstance(frame, dict)
    for expected_key in ("timestamp", "heatmap", "active_links", "target_coords", "max_intensity"):
        assert expected_key in frame

    assert isinstance(frame["timestamp"], float)
    assert frame["timestamp"] > 0.0
    assert abs(frame["timestamp"] - t_start) < 2.0

    assert isinstance(frame["active_links"], int)
    assert frame["active_links"] == 1

    heatmap = frame["heatmap"]
    assert isinstance(heatmap, np.ndarray)
    assert heatmap.ndim == 2
    assert heatmap.shape == (50, 100)
    assert np.all(heatmap >= 0.0)
    assert np.any(heatmap > 0.0)

    assert isinstance(frame["max_intensity"], (float, np.floating))
    assert frame["max_intensity"] > 0.0
    assert math.isclose(frame["max_intensity"], float(np.max(heatmap)), rel_tol=1e-5)
    assert frame["max_intensity"] != 5.2

    if frame["target_coords"] is not None:
        tx, ty = frame["target_coords"]
        assert 0.0 <= tx <= 20.0 and 0.0 <= ty <= 10.0
        assert frame["target_coords"] != (10.0, 5.0)


def test_f17_04_pipeline_headless_run_simulation(capsys):
    now = time.time()
    samples = [LinkSample(now + i * 0.05, -60.0, "R1", f"DEV_{i}", 37) for i in range(15)]
    res = run_radar_pipeline(samples, headless=True)

    assert res == 0

    captured = capsys.readouterr()
    frame_lines = [ln for ln in captured.out.splitlines() if "[RADAR FRAME" in ln]
    assert len(frame_lines) == 3

    assert "Links:  5" in frame_lines[0] or "Links: 5" in frame_lines[0]
    assert "Links: 10" in frame_lines[1]
    assert "Links: 15" in frame_lines[2]

    assert "Sigma: 4.2" not in captured.out
    assert "Sigma: 0.0" in captured.out or "Sigma:  0.0" in captured.out


def test_f17_05_single_frame_empty_samples_handling():
    frame = run_single_frame([], headless=True)

    assert isinstance(frame, dict)
    assert isinstance(frame["timestamp"], float) and frame["timestamp"] > 0.0
    assert frame["active_links"] == 0
    assert frame["target_coords"] is None
    assert frame["max_intensity"] == 0.0

    heatmap = frame["heatmap"]
    assert isinstance(heatmap, np.ndarray)
    assert heatmap.ndim == 2
    assert heatmap.shape == (50, 100)
    assert np.all(heatmap == 0.0)
    assert frame["max_intensity"] == float(np.max(heatmap))
