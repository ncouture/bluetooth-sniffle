#!/usr/bin/env python
#

import pytest
import json
import tempfile
import os
import io
import sys
import numpy as np

from sniffle.radar.demuxer import StreamDemuxer
from sniffle.radar.models import LinkSample
from radar_tomography import build_parser, run_radar_pipeline, generate_simulated_samples


def test_cli_parser_help_and_defaults():
    parser = build_parser()
    help_text = parser.format_help()
    
    assert "--simulate" in help_text
    assert "--replay" in help_text
    assert "--port1" in help_text
    assert "--channel" in help_text
    assert "Step-by-Step Command Examples" in help_text

    args = parser.parse_args(["--simulate", "--headless", "--room-width", "8.0"])
    assert args.simulate is True
    assert args.headless is True
    assert args.room_width == 8.0


def test_packaged_sample_dataset_loading():
    dataset_path = os.path.join(os.path.dirname(__file__), "radar_sample_data.json")
    assert os.path.exists(dataset_path)

    demuxer = StreamDemuxer()
    samples = demuxer.load_json_replay(dataset_path)
    assert len(samples) >= 10
    assert samples[0].channel == 37


def test_terminal_packet_logging_for_ports():
    samples = generate_simulated_samples()
    captured_output = io.StringIO()
    sys.stdout = captured_output
    
    try:
        run_radar_pipeline(samples, headless=True, mode_name="Test Mode")
    finally:
        sys.stdout = sys.__stdout__

    output = captured_output.getvalue()
    assert "Ingesting & Demultiplexing Public BLE Device Packets Across Channels 37, 38, 39:" in output
    assert "[PACKET #0001 | R1 (port1)]" in output
    assert "[PACKET #0002 | R2 (port2)]" in output
    assert "RSSI: -60.0 dBm" in output
