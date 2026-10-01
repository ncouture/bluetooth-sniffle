"""
Unit Tests for BLE RSSI Radar CLI Runner (radar_tomography.py).
"""

import sys
from pathlib import Path
import pytest

_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from radar_tomography import (
    build_cli_parser,
    parse_radar_args,
    RadarTomographyPipeline,
    main,
)


def test_cli_parser_defaults():
    parser = build_cli_parser()
    args = parser.parse_args([])
    assert args.port1 == "/dev/ttyUSB0"
    assert args.port2 == "/dev/ttyUSB1"
    assert args.chan1 == 37
    assert args.chan2 == 38
    assert args.baud == 921600
    assert args.public_mode is True
    assert args.multi_channel is False
    assert args.simulate is False
    assert args.headless is False
    assert args.room_width == 20.0
    assert args.room_length == 10.0
    assert args.grid_res == 0.2
    assert args.mac_timeout == 30.0
    assert args.alpha_reg == 0.05


def test_cli_parser_custom_options():
    args = parse_radar_args([
        "--port1", "/dev/ttyUSB2",
        "--port2", "/dev/ttyUSB3",
        "--chan1", "38",
        "--chan2", "39",
        "--baud", "115200",
        "--simulate",
        "--headless",
        "--room-width", "30.0",
        "--room-length", "15.0",
        "--grid-res", "0.5",
        "--mac-timeout", "45.0",
        "--alpha-reg", "0.1",
        "--max-frames", "10",
    ])
    assert args.port1 == "/dev/ttyUSB2"
    assert args.port2 == "/dev/ttyUSB3"
    assert args.chan1 == 38
    assert args.chan2 == 39
    assert args.baud == 115200
    assert args.simulate is True
    assert args.headless is True
    assert args.room_width == 30.0
    assert args.room_length == 15.0
    assert args.grid_res == 0.5
    assert args.mac_timeout == 45.0
    assert args.alpha_reg == 0.1
    assert args.max_frames == 10


def test_cli_parser_invalid_channels():
    with pytest.raises((ValueError, SystemExit)):
        parse_radar_args(["--chan1", "36"])

    with pytest.raises((ValueError, SystemExit)):
        parse_radar_args(["--chan2", "40"])


def test_cli_parser_public_mode_overrides_multi_channel():
    args = parse_radar_args(["--public-mode", "--multi-channel"])
    assert args.public_mode is True
    assert args.multi_channel is False


def test_pipeline_fallback_to_mock_on_absent_ports():
    args = parse_radar_args([
        "--port1", "/dev/nonexistent_dongle_1",
        "--port2", "/dev/nonexistent_dongle_2",
        "--headless",
        "--max-frames", "3",
    ])
    pipeline = RadarTomographyPipeline(args)
    pipeline.start()
    assert pipeline.sniffer.using_mock is True
    assert pipeline.running is True
    pipeline.stop()
    assert pipeline.running is False


def test_pipeline_step_execution():
    args = parse_radar_args([
        "--simulate",
        "--headless",
        "--max-frames", "5",
    ])
    pipeline = RadarTomographyPipeline(args)
    pipeline.start()

    frames_processed = 0
    import time
    time.sleep(0.1)

    for _ in range(15):
        frame = pipeline.step(timeout=0.05)
        if frame is not None:
            frames_processed += 1
            assert "frame" in frame
            assert "active_links" in frame
            assert "target_coords" in frame
            assert "max_intensity" in frame
            if frames_processed >= 3:
                break
        time.sleep(0.05)

    pipeline.stop()
    assert frames_processed >= 2


def test_cli_main_entrypoint():
    ret = main(["--simulate", "--headless", "--max-frames", "2"])
    assert ret == 0
