#!/usr/bin/env python
#

import pytest
import time
import numpy as np

from sniffle.radar.models import LinkSample, NodeType
from sniffle.radar.public_devices import PublicDeviceManager
from sniffle.radar.baseline import BaselineTracker
from sniffle.radar.features import FeatureExtractor
from radar_tomography import build_parser, run_radar_pipeline, generate_simulated_samples


def test_public_device_manager_discovery_and_pruning():
    mgr = PublicDeviceManager(inactivity_timeout=30.0, room_dim=(20.0, 10.0))
    now = time.time()

    # Discover two public devices over the air
    mgr.register_sample(LinkSample(now, -65.0, "R1", "AA:11:22:33:44:55", 37))
    mgr.register_sample(LinkSample(now + 1.0, -70.0, "R2", "BB:22:33:44:55:66", 38))

    active_nodes = mgr.get_active_nodes()
    assert "AA:11:22:33:44:55" in active_nodes
    assert "BB:22:33:44:55:66" in active_nodes
    assert active_nodes["AA:11:22:33:44:55"].role == NodeType.TRANSMITTER

    # Simulate 35s passing (inactivity threshold crossed for first MAC)
    mgr.register_sample(LinkSample(now + 35.0, -71.0, "R2", "BB:22:33:44:55:66", 38))
    mgr.prune_inactive(now + 35.0)

    updated_nodes = mgr.get_active_nodes()
    assert "AA:11:22:33:44:55" not in updated_nodes
    assert "BB:22:33:44:55:66" in updated_nodes


def test_per_channel_baseline_tracker():
    tracker = BaselineTracker(alpha=0.1)

    # Feed baseline samples on Channel 37 (-60 dBm) vs Channel 38 (-75 dBm due to multipath)
    for _ in range(20):
        tracker.update("R1", "PUBLIC_MAC", -60.0, channel=37)
        tracker.update("R1", "PUBLIC_MAC", -75.0, channel=38)

    base_37 = tracker.get_baseline("R1", "PUBLIC_MAC", channel=37)
    base_38 = tracker.get_baseline("R1", "PUBLIC_MAC", channel=38)

    assert pytest.approx(base_37, 0.5) == -60.0
    assert pytest.approx(base_38, 0.5) == -75.0


def test_multi_channel_feature_extraction():
    extractor = FeatureExtractor(window_size=10)
    now = time.time()

    # Add samples across channels 37, 38, 39
    for i in range(10):
        extractor.add_sample("R1", "PUBLIC_MAC", rssi=-60.0, timestamp=now + i * 0.05, channel=37)
        extractor.add_sample("R1", "PUBLIC_MAC", rssi=-75.0, timestamp=now + i * 0.05, channel=38)

    features_37 = extractor.compute_features("R1", "PUBLIC_MAC", baseline_rssi=-60.0, channel=37)
    features_38 = extractor.compute_features("R1", "PUBLIC_MAC", baseline_rssi=-75.0, channel=38)

    # Residual drop should be ~0.0 for both channels despite different raw RSSI values
    assert pytest.approx(features_37.attenuation_drop, 0.5) == 0.0
    assert pytest.approx(features_38.attenuation_drop, 0.5) == 0.0


def test_public_mode_cli_flags():
    parser = build_parser()
    args = parser.parse_args(["--public-mode", "--multi-channel", "--mac-timeout", "45.0"])

    assert args.public_mode is True
    assert args.multi_channel is True
    assert args.mac_timeout == 45.0
