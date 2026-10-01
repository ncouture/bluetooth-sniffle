"""
Unit Tests for 2D Spatial Tomography, Tracker, and Visualizer (sniffle.radar.tomography).
"""

import math
import time
import numpy as np
import pytest

from sniffle.radar.tomography import (
    TomographyResult,
    SpatialTomography2D,
    TargetTracker,
)
from sniffle.radar.visualizer import RadarVisualizer


def test_spatial_tomography_grid_and_kernel(standard_geometry):
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    assert tomo.nx == 100
    assert tomo.ny == 50
    assert tomo.P == 5000

    assert tomo.W is None
    assert tomo.Gram_inv is None

    links = standard_geometry["links"]
    K = len(links)
    tomo.update_geometry(links)

    assert tomo.W is not None
    assert tomo.W.shape == (K, 5000)
    assert tomo.Gram_inv is not None
    assert tomo.Gram_inv.shape == (K, K)

    row_sums = np.sum(tomo.W, axis=1)
    for s in row_sums:
        assert abs(s - 1.0) < 1e-4 or s == 0.0


def test_spatial_tomography_dual_tikhonov_solve(standard_geometry):
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = standard_geometry["links"]
    tomo.update_geometry(links)
    K = len(links)

    anom_vec = np.zeros(K, dtype=np.float32)
    anom_vec[0] = 8.0

    t_start = time.perf_counter()
    heatmap = tomo.solve_attenuation_field(anom_vec)
    solve_duration = (time.perf_counter() - t_start) * 1000.0

    assert heatmap.shape == (50, 100)
    assert solve_duration < 10.0
    assert np.all(heatmap >= 0.0)
    assert np.max(heatmap) > 0.0


def test_spatial_tomography_target_centroid(standard_geometry):
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = standard_geometry["links"]
    tomo.update_geometry(links)

    anom_vec = np.zeros(len(links), dtype=np.float32)
    anom_vec[4] = 10.0
    heatmap = tomo.solve_attenuation_field(anom_vec)

    pos = tomo.estimate_target_position(heatmap, percentile=95.0)
    assert pos is not None
    x, y = pos
    assert 0.0 <= x <= 20.0
    assert 0.0 <= y <= 10.0

    assert tomo.estimate_target_position(np.zeros_like(heatmap)) is None


def test_spatial_tomography_solve_contract(standard_geometry):
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    links = standard_geometry["links"]
    tomo.update_geometry(links)

    anom_vec = np.ones(len(links), dtype=np.float32) * 2.0
    link_keys = [f"L_{i}" for i in range(len(links))]
    res = tomo.solve(link_keys, anom_vec)

    assert isinstance(res, TomographyResult)
    assert res.heatmap.shape == (50, 100)
    assert res.max_intensity > 0.0


def test_spatial_tomography_empty_geometry():
    tomo = SpatialTomography2D(room_dim=(20.0, 10.0), resolution=0.2)
    tomo.update_geometry([])
    hm = tomo.solve_attenuation_field(np.array([]))
    assert hm.shape == (50, 100)
    assert np.all(hm == 0.0)
    assert tomo.estimate_target_position(hm) is None


def test_target_tracker_lifecycle_and_coasting():
    tracker = TargetTracker(alpha=0.6, beta=0.15)
    assert tracker.pos is None

    pos1 = tracker.update((5.0, 5.0), dt=0.1)
    assert pos1 == (5.0, 5.0)
    assert np.all(tracker.vel == 0.0)

    pos2 = tracker.update((5.5, 5.0), dt=0.1)
    assert pos2 is not None
    assert pos2[0] > 5.0
    assert tracker.vel[0] > 0.0

    pos_before_coast = tuple(tracker.pos)
    vel_x = tracker.vel[0]
    pos_coasted = tracker.update(None, dt=0.1)
    assert pos_coasted is not None
    assert abs(pos_coasted[0] - (pos_before_coast[0] + vel_x * 0.1)) < 1e-4

    tracker.reset()
    assert tracker.pos is None


def test_radar_visualizer_headless(standard_geometry):
    viz = RadarVisualizer(room_dim=(20.0, 10.0), headless=True)
    assert viz.headless is True

    receivers = [{"pos": (0.5, 0.5)}, {"pos": (19.5, 0.5)}]
    transmitters = [{"pos": (10.0, 5.0)}]
    links = [((0.5, 0.5), (10.0, 5.0))]

    viz.init_plot(receivers, transmitters, links)
    assert len(viz.rx_artists) >= 1

    viz.update_target((10.0, 5.0))
    assert len(viz.trail_history) == 1
    assert viz.target_marker.get_data() == ([10.0], [5.0])

    dummy_heatmap = np.zeros((50, 100), dtype=np.float32)
    viz.update_frame(
        heatmap=dummy_heatmap,
        target_coords=(10.2, 5.1),
        active_links_count=24,
        max_intensity=4.5,
        anomaly_sigma=3.8,
    )
    assert len(viz.trail_history) == 2

    viz.close()
