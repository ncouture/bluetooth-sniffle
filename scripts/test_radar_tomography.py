#!/usr/bin/env python
#

import pytest
import numpy as np

from sniffle.radar.models import Node, NodeType, RFLink
from sniffle.radar.tomography import LinkTomographyGrid
from sniffle.radar.localization import estimate_position
from sniffle.radar.tracker import AlphaBetaTracker


def test_link_tomography_grid_precomputation():
    room_dim = (6.0, 6.0)
    grid_res = 0.2
    
    nodes = {
        "R1": Node("R1", NodeType.RECEIVER, np.array([0.5, 0.5])),
        "R2": Node("R2", NodeType.RECEIVER, np.array([5.5, 0.5])),
        "T1": Node("T1", NodeType.TRANSMITTER, np.array([1.0, 5.5])),
        "T2": Node("T2", NodeType.TRANSMITTER, np.array([5.0, 5.5])),
    }
    
    links = [
        RFLink(nodes["R1"], nodes["T1"]),
        RFLink(nodes["R1"], nodes["T2"]),
        RFLink(nodes["R2"], nodes["T1"]),
        RFLink(nodes["R2"], nodes["T2"]),
    ]
    
    tomo = LinkTomographyGrid(room_dim, grid_res, nodes, links, ellipse_width=0.4)
    
    # Grid size: 6.0 / 0.2 = 30x30
    assert tomo.weights.shape == (4, 30, 30)
    
    # Reconstruct heatmap with disturbance on link (R1, T1)
    link_activations = {
        ("R1", "T1"): 10.0,
        ("R2", "T2"): 0.0
    }
    heatmap = tomo.reconstruct_heatmap(link_activations)
    assert heatmap.shape == (30, 30)
    assert heatmap.max() > 0.0


def test_position_estimation():
    room_dim = (6.0, 6.0)
    grid_res = 0.1
    
    nodes = {
        "R1": Node("R1", NodeType.RECEIVER, np.array([0.5, 0.5])),
        "R2": Node("R2", NodeType.RECEIVER, np.array([5.5, 0.5])),
        "T1": Node("T1", NodeType.TRANSMITTER, np.array([1.0, 5.5])),
        "T2": Node("T2", NodeType.TRANSMITTER, np.array([5.0, 5.5])),
    }
    
    links = [
        RFLink(nodes["R1"], nodes["T1"]),
        RFLink(nodes["R2"], nodes["T1"]),
    ]
    
    tomo = LinkTomographyGrid(room_dim, grid_res, nodes, links)
    
    # Target standing near intersection of R1-T1 and R2-T1 near (1.0, 5.5) / (2.0, 3.0)
    activations = {
        ("R1", "T1"): 8.0,
        ("R2", "T1"): 7.5,
    }
    heatmap = tomo.reconstruct_heatmap(activations)
    pos = estimate_position(heatmap, tomo.grid_x, tomo.grid_y, threshold_percentile=90)
    
    assert pos is not None
    assert len(pos) == 2
    assert 0.0 <= pos[0] <= 6.0
    assert 0.0 <= pos[1] <= 6.0


def test_alpha_beta_tracker():
    tracker = AlphaBetaTracker(alpha=0.6, beta=0.1)
    
    # Initial measurement
    pos1 = tracker.update(np.array([2.0, 3.0]), dt=0.1)
    assert pytest.approx(pos1[0], 0.1) == 2.0
    assert pytest.approx(pos1[1], 0.1) == 3.0
    
    # Moving along +X direction to (2.2, 3.0)
    pos2 = tracker.update(np.array([2.2, 3.0]), dt=0.1)
    assert 2.0 < pos2[0] < 2.3
    assert pytest.approx(pos2[1], 0.1) == 3.0
