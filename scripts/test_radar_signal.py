#/usr/bin/env python
#

import pytest
import numpy as np
import time

# Import radar modules (to be implemented)
from sniffle.radar.models import Node, RFLink, LinkSample, NodeType
from sniffle.radar.baseline import BaselineTracker
from sniffle.radar.features import FeatureExtractor


def test_node_models():
    rx1 = Node(node_id="R1", role=NodeType.RECEIVER, position=np.array([0.5, 0.5]))
    tx1 = Node(node_id="T1", role=NodeType.TRANSMITTER, position=np.array([1.0, 5.5]))

    assert rx1.node_id == "R1"
    assert rx1.role == NodeType.RECEIVER
    assert np.array_equal(rx1.position, np.array([0.5, 0.5]))

    link = RFLink(rx=rx1, tx=tx1)
    assert link.rx_id == "R1"
    assert link.tx_id == "T1"
    assert pytest.approx(link.distance, 0.01) == np.linalg.norm(rx1.position - tx1.position)


def test_link_sample():
    sample = LinkSample(
        timestamp=1000.0,
        rssi=-65.0,
        rx_id="R1",
        tx_mac="AA:BB:CC:DD:EE:FF",
        channel=37
    )
    assert sample.rssi == -65.0
    assert sample.tx_mac == "AA:BB:CC:DD:EE:FF"


def test_baseline_tracker():
    tracker = BaselineTracker(alpha=0.1, outlier_threshold=15.0)
    
    # Feeding steady -60 dBm signal
    for _ in range(20):
        tracker.update(rx_id="R1", tx_mac="T1", rssi=-60.0)

    baseline = tracker.get_baseline("R1", "T1")
    assert pytest.approx(baseline, 0.5) == -60.0

    # Outlier sample (-20 dBm spike) should be filtered by median/hampel outlier filter
    tracker.update(rx_id="R1", tx_mac="T1", rssi=-20.0)
    baseline_after_spike = tracker.get_baseline("R1", "T1")
    assert abs(baseline_after_spike - (-60.0)) < 3.0


def test_feature_extractor():
    extractor = FeatureExtractor(window_size=10, expected_rate_hz=20.0)

    # Simulate quiet baseline
    now = time.time()
    for i in range(10):
        extractor.add_sample("R1", "T1", rssi=-60.0, timestamp=now + i * 0.05)

    features = extractor.compute_features("R1", "T1", baseline_rssi=-60.0)
    assert pytest.approx(features.std_dev, 0.1) == 0.0
    assert pytest.approx(features.attenuation_drop, 0.1) == 0.0
    assert features.pdr > 0.8

    # Simulate disturbance (attenuation drop to -72 dBm and variance spike)
    for i in range(10, 20):
        # Oscillating between -68 and -76 dBm
        rssi_val = -68.0 if i % 2 == 0 else -76.0
        extractor.add_sample("R1", "T1", rssi=rssi_val, timestamp=now + i * 0.05)

    disturbed_features = extractor.compute_features("R1", "T1", baseline_rssi=-60.0)
    assert disturbed_features.std_dev > 2.0
    assert disturbed_features.attenuation_drop > 8.0
    assert disturbed_features.activity_score > 5.0


def test_robust_z_score_anomaly_detection():
    tracker = BaselineTracker(alpha=0.1)
    extractor = FeatureExtractor(window_size=10)
    now = time.time()

    # Establish baseline with small natural noise (std ~ 1.0)
    for i in range(10):
        val = -60.0 + (1.0 if i % 2 == 0 else -1.0)
        tracker.update("R1", "T1", val, channel=37)
        extractor.add_sample("R1", "T1", val, now + i * 0.05, channel=37)

    baseline = tracker.get_baseline("R1", "T1", channel=37)
    std_dev = tracker.get_std_dev("R1", "T1", channel=37)

    # Minor 1.5 dB fluctuation (z ~ 1.5 < 3.0) -> should NOT trigger anomaly
    minor_features = extractor.compute_features("R1", "T1", baseline, channel=37, baseline_std=std_dev, z_threshold=3.0)
    assert minor_features.activity_score == 0.0

    # Human shadowing event: attenuation drop of 12 dB (z ~ 12.0 >> 3.0) -> SHOULD trigger anomaly
    for i in range(10, 20):
        extractor.add_sample("R1", "T1", -72.0, now + i * 0.05, channel=37)

    major_features = extractor.compute_features("R1", "T1", baseline, channel=37, baseline_std=std_dev, z_threshold=3.0)
    assert major_features.attenuation_drop >= 10.0
    assert major_features.activity_score >= 10.0

