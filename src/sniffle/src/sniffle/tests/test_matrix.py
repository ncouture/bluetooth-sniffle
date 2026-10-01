"""
Unit Tests for Link Lifecycle & Ambient Device Matrix (sniffle.radar.matrix).
"""

import math
import numpy as np
import pytest

from sniffle.radar.capture import LinkSample
from sniffle.radar.matrix import (
    AddressType,
    NodeType,
    LinkState,
    LinkRecord,
    classify_ble_mac,
    MxNLinkMatrixManager,
    PublicDeviceManager,
)


def test_classify_ble_mac():
    assert classify_ble_mac("00:11:22:33:44:55", tx_add=0) == AddressType.PUBLIC
    assert classify_ble_mac("40:11:22:33:44:55", tx_add=0) == AddressType.PUBLIC
    assert classify_ble_mac("C0:11:22:33:44:55", tx_add=0) == AddressType.PUBLIC

    assert classify_ble_mac("C0:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_STATIC
    assert classify_ble_mac("E1:22:33:44:55:66", tx_add=1) == AddressType.RANDOM_STATIC

    assert classify_ble_mac("40:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("5A:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_RPA

    assert classify_ble_mac("00:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_NRPA
    assert classify_ble_mac("1F:11:22:33:44:55", tx_add=1) == AddressType.RANDOM_NRPA

    assert classify_ble_mac("INVALID_MAC", tx_add=1) == AddressType.RANDOM_RPA
    assert classify_ble_mac("", tx_add=1) == AddressType.RANDOM_RPA


def test_link_record_defaults():
    rec = LinkRecord(
        tx_mac="AA:BB:CC:11:22:33",
        rx_id="R1",
        channel=37,
        addr_type=AddressType.PUBLIC,
    )
    assert rec.tx_mac == "AA:BB:CC:11:22:33"
    assert rec.rx_id == "R1"
    assert rec.channel == 37
    assert rec.state == LinkState.DISCOVERING
    assert rec.packet_count == 0
    assert rec.pdr == 1.0


def test_matrix_manager_lifecycle_and_promotion(standard_geometry):
    mgr = MxNLinkMatrixManager(
        rx_configs=standard_geometry["rx_configs"],
        inactivity_timeout=30.0,
        occlusion_timeout=3.0,
        min_activation_pkts=3,
        window_size=10,
    )

    t = 100.0
    rec = mgr.register_packet(t, -60.0, "R1", "AA:BB:CC:00:00:01", 37, tx_add=0)
    assert rec is not None
    assert rec.state == LinkState.DISCOVERING
    assert rec.packet_count == 1

    rec = mgr.register_packet(t + 0.1, -61.0, "R1", "AA:BB:CC:00:00:01", 37, tx_add=0)
    assert rec.state == LinkState.DISCOVERING
    assert rec.packet_count == 2

    rec = mgr.register_packet(t + 0.2, -59.0, "R1", "AA:BB:CC:00:00:01", 37, tx_add=0)
    assert rec.state == LinkState.ACTIVE
    assert rec.packet_count == 3
    assert -61.0 <= rec.baseline_rssi <= -59.0


def test_matrix_manager_register_sample(standard_geometry):
    mgr = MxNLinkMatrixManager(rx_configs=standard_geometry["rx_configs"])
    s = LinkSample(timestamp=50.0, rssi=-65.0, rx_id="R1", tx_mac="11:22:33:44:55:66", channel=37)
    rec = mgr.register_sample(s, tx_add=0)
    assert rec is not None
    assert rec.tx_mac == "11:22:33:44:55:66"
    assert rec.current_rssi == -65.0


def test_matrix_manager_features_drop_and_reflection(standard_geometry):
    mgr = MxNLinkMatrixManager(
        rx_configs=standard_geometry["rx_configs"],
        min_activation_pkts=3,
        window_size=5,
    )

    mac = "AA:BB:CC:11:11:11"
    for i in range(5):
        mgr.register_packet(10.0 + i * 0.1, -60.0, "R1", mac, 37)

    rec = mgr.links[(mac, "R1")]
    assert rec.state == LinkState.ACTIVE

    for i in range(5):
        mgr.register_packet(10.5 + i * 0.1, -75.0, "R1", mac, 37)

    assert rec.activity_score > 10.0

    mac_boost = "AA:BB:CC:22:22:22"
    for i in range(5):
        mgr.register_packet(20.0 + i * 0.1, -60.0, "R1", mac_boost, 37)
    for i in range(5):
        mgr.register_packet(20.5 + i * 0.1, -52.0, "R1", mac_boost, 37)
    rec_boost = mgr.links[(mac_boost, "R1")]
    assert rec_boost.activity_score > 0.0


def test_matrix_manager_occlusion_and_inactivity_pruning(standard_geometry):
    mgr = MxNLinkMatrixManager(
        rx_configs=standard_geometry["rx_configs"],
        inactivity_timeout=10.0,
        occlusion_timeout=2.0,
        min_activation_pkts=3,
    )

    mac = "AA:BB:CC:33:33:33"
    t0 = 100.0
    for i in range(4):
        mgr.register_packet(t0 + i * 0.1, -60.0, "R1", mac, 37)

    rec = mgr.links[(mac, "R1")]
    assert rec.state == LinkState.ACTIVE

    mgr._update_link_features(rec, t0 + 3.5)
    assert rec.state == LinkState.DEGRADED
    assert rec.pdr == 0.0

    pruned = mgr.prune_inactive(t0 + 12.0)
    assert mac in pruned
    assert (mac, "R1") not in mgr.links


def test_matrix_manager_get_matrix_and_snapshot(standard_geometry):
    mgr = MxNLinkMatrixManager(rx_configs=standard_geometry["rx_configs"], min_activation_pkts=3)

    t0 = 50.0
    for i in range(12):
        mac = f"AA:BB:CC:00:00:{i:02X}"
        for step in range(3):
            mgr.register_packet(t0 + step * 0.1, -60.0 - i, "R1", mac, 37)
            mgr.register_packet(t0 + step * 0.1, -62.0 - i, "R2", mac, 38)

    mat, tx_list, rx_list = mgr.get_matrix()
    assert len(tx_list) == 12
    assert rx_list == ["R1", "R2"]
    assert mat.shape == (12, 2)

    keys, curr_rssi, pdr_vec, base_rssi = mgr.get_active_matrix_snapshot()
    assert len(keys) == 24
    assert len(curr_rssi) == 24
    assert len(pdr_vec) == 24
    assert len(base_rssi) == 24
    assert np.all(pdr_vec >= 0.0)


def test_public_device_manager():
    pdm = PublicDeviceManager(room_dim=(20.0, 10.0), inactivity_timeout=15.0)

    for i in range(12):
        mac = f"00:11:22:33:44:{i:02X}"
        pdm.register_packet(100.0, -55.0, "R1", mac, 37, tx_add=0)

    nodes = pdm.get_active_nodes()
    assert len(nodes) == 12

    pruned = pdm.prune_inactive(116.0)
    assert len(pruned) == 12
    assert len(pdm.get_active_nodes()) == 0
