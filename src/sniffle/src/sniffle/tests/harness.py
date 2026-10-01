"""
Unified Test Harness & Reference Oracle for BLE RSSI Radar E2E Suite.
Provides standard reference models, physics simulation, protocol mocks,
and bridges to the core radar package.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum
import io
import math
import os
from pathlib import Path
import queue
import random
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

# Ensure python_cli is on sys.path
_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from sniffle.radar.capture import (
    LinkSample,
    SnifflePacketSource,
    HardwareSniffleSource,
    MockSniffleSource,
    DualSnifferManager,
    point_to_segment_distance,
)

try:
    from sniffle.sniffle_hw import make_sniffle_hw, SnifferMode, SniffleHW
    from sniffle.packet_decoder import (
        str_mac,
        PacketMessage,
        AdvIndMessage,
        AdvNonconnIndMessage,
        ScanRspMessage,
        AdvScanIndMessage,
        AdvDirectIndMessage,
        AdvExtIndMessage,
    )
    from sniffle.errors import UsageError, SniffleHWPacketError
except ImportError:
    make_sniffle_hw = None  # type: ignore
    SnifferMode = None  # type: ignore
    SniffleHW = None  # type: ignore
    PacketMessage = Any  # type: ignore
    AdvIndMessage = Any  # type: ignore
    AdvNonconnIndMessage = Any  # type: ignore
    ScanRspMessage = Any  # type: ignore
    AdvScanIndMessage = Any  # type: ignore
    AdvDirectIndMessage = Any  # type: ignore
    AdvExtIndMessage = Any  # type: ignore
    UsageError = Exception  # type: ignore
    SniffleHWPacketError = Exception  # type: ignore

    def str_mac(mac: bytes) -> str:
        return ":".join(["%02X" % b for b in reversed(mac)])


from sniffle.radar.matrix import (
    NodeType,
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


def create_synthetic_adv_packet(pdu_type: str, mac_bytes: bytes, data: bytes = b"\x02\x01\x06") -> Any:
    """
    Constructs a synthetic BLE advertising packet for testing MAC decoders.
    mac_bytes: 6 raw little-endian bytes.
    """
    pdu_map = {
        "ADV_IND": (0, AdvIndMessage),
        "ADV_DIRECT_IND": (1, AdvDirectIndMessage),
        "ADV_NONCONN_IND": (2, AdvNonconnIndMessage),
        "SCAN_RSP": (4, ScanRspMessage),
        "ADV_SCAN_IND": (6, AdvScanIndMessage),
        "ADV_EXT_IND": (7, AdvExtIndMessage),
    }
    
    pdu_id, cls_type = pdu_map.get(pdu_type, (0, AdvIndMessage))
    
    body = mac_bytes + data
    header = bytes([pdu_id, len(body)])
    raw_payload = header + body

    class MockPacketMessage:
        def __init__(self, payload: bytes):
            self.payload = payload
            self.body = payload[2:]
            self.rssi = -60
            self.channel = 37

    pkt = MockPacketMessage(raw_payload)
    if cls_type is not Any:
        try:
            return cls_type(pkt)
        except Exception:
            pass

    class MockDecodedMsg:
        def __init__(self, adva_bytes: bytes):
            self.AdvA = adva_bytes
            self.body = b"\x00\x00" + adva_bytes + data
            self.rssi = -60
            self.channel = 37

    return MockDecodedMsg(mac_bytes)


__all__ = [
    # Capture (M1)
    "LinkSample",
    "SnifflePacketSource",
    "HardwareSniffleSource",
    "MockSniffleSource",
    "DualSnifferManager",
    "point_to_segment_distance",
    "str_mac",
    # Matrix (M2)
    "NodeType",
    "AddressType",
    "classify_ble_mac",
    "LinkState",
    "LinkRecord",
    "MxNLinkMatrixManager",
    "PublicDeviceManager",
    # Anomaly (M3)
    "compute_wilson_hilferty",
    "RobustAnomalyEngine",
    "LinkAnomalyVector",
    # Tomography & Tracking (M4)
    "SpatialTomography2D",
    "TargetTracker",
    "TomographyResult",
    # Visualizer & Pipeline (M4)
    "RadarVisualizer",
    "RadarFrameProcessor",
    "run_single_frame",
    "run_radar_pipeline",
    "RadarTomographyPipeline",
    "build_cli_parser",
    "parse_radar_args",
    # Test Fixtures
    "create_synthetic_adv_packet",
]
