"""
Sniffle Radar Package - Passive BLE Human Sensing & Radio Tomographic Imaging Engine
"""

from .capture import (
    LinkSample,
    SnifflePacketSource,
    HardwareSniffleSource,
    MockSniffleSource,
    DualSnifferManager,
    point_to_segment_distance,
)

from .matrix import (
    AddressType,
    classify_ble_mac,
    LinkState,
    LinkRecord,
    MxNLinkMatrixManager,
    PublicDeviceManager,
)

from .anomaly import (
    compute_wilson_hilferty,
    LinkAnomalyVector,
    RobustAnomalyEngine,
)

from .tomography import (
    TomographyResult,
    SpatialTomography2D,
    TargetTracker,
    LinkTomographyGrid,
)

from .visualizer import (
    RadarVisualizer,
    RadarFrameProcessor,
    run_single_frame,
    run_radar_pipeline,
)

from .models import Node, RFLink, NodeType, LinkFeatures
from .baseline import BaselineTracker
from .features import FeatureExtractor
from .localization import estimate_position
from .tracker import AlphaBetaTracker
from .demuxer import StreamDemuxer

__all__ = [
    # Ingestion & Capture
    "LinkSample",
    "SnifflePacketSource",
    "HardwareSniffleSource",
    "MockSniffleSource",
    "DualSnifferManager",
    "point_to_segment_distance",

    # Matrix & Lifecycle
    "NodeType",
    "AddressType",
    "classify_ble_mac",
    "LinkState",
    "LinkRecord",
    "MxNLinkMatrixManager",
    "PublicDeviceManager",

    # Anomaly Engine
    "compute_wilson_hilferty",
    "LinkAnomalyVector",
    "RobustAnomalyEngine",

    # Tomography & Tracking
    "TomographyResult",
    "SpatialTomography2D",
    "TargetTracker",
    "LinkTomographyGrid",

    # Visualization & Runner
    "RadarVisualizer",
    "RadarFrameProcessor",
    "run_single_frame",

    # Legacy models & helpers
    "Node",
    "RFLink",
    "LinkFeatures",
    "BaselineTracker",
    "FeatureExtractor",
    "estimate_position",
    "AlphaBetaTracker",
    "StreamDemuxer",
    "run_radar_pipeline",
]
