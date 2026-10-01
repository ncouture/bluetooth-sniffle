"""
Comprehensive Unit and Integration Tests for Hardware Ingestion & Channel Locking.
"""

import dataclasses
import queue
import sys
import time
from unittest.mock import MagicMock, patch
import pytest
import os
from pathlib import Path

_SNIFFLE_CLI = Path("/home/self/git/Sniffle/Sniffle/python_cli")
if _SNIFFLE_CLI.exists() and str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from sniffle.radar.capture import (
    LinkSample,
    SnifflePacketSource,
    HardwareSniffleSource,
    MockSniffleSource,
    DualSnifferManager,
    point_to_segment_distance,
)
from sniffle.sniffle_hw import SniffleHW, SnifferMode
from sniffle.packet_decoder import (
    str_mac,
    AdvIndMessage,
    AdvNonconnIndMessage,
    ScanRspMessage,
    AdvScanIndMessage,
    AdvExtIndMessage,
)
from sniffle.errors import UsageError


# ===========================================================================
# 1. LinkSample Tests
# ===========================================================================

def test_link_sample_properties_and_values():
    """Verify LinkSample correctly stores and exposes all sample fields."""
    sample = LinkSample(
        timestamp=1789830000.123,
        rssi=-62.5,
        rx_id="R1",
        tx_mac="AA:BB:CC:DD:EE:01",
        channel=37,
    )
    assert sample.timestamp == 1789830000.123
    assert sample.rssi == -62.5
    assert sample.rx_id == "R1"
    assert sample.tx_mac == "AA:BB:CC:DD:EE:01"
    assert sample.channel == 37


def test_link_sample_immutability_frozen():
    """Verify that LinkSample is strictly immutable (frozen dataclass)."""
    sample = LinkSample(
        timestamp=100.0,
        rssi=-70.0,
        rx_id="R1",
        tx_mac="11:22:33:44:55:66",
        channel=37,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        sample.rssi = -50.0  # type: ignore

    with pytest.raises(dataclasses.FrozenInstanceError):
        sample.timestamp = 200.0  # type: ignore

    with pytest.raises(dataclasses.FrozenInstanceError):
        sample.rx_id = "R2"  # type: ignore

    with pytest.raises(dataclasses.FrozenInstanceError):
        sample.tx_mac = "AA:BB:CC:DD:EE:FF"  # type: ignore

    with pytest.raises(dataclasses.FrozenInstanceError):
        sample.channel = 38  # type: ignore


def test_link_sample_equality_and_hashability():
    """Verify LinkSample supports value equality and hashable set/dict usage."""
    s1 = LinkSample(10.0, -60.0, "R1", "AA:BB:CC:DD:EE:FF", 37)
    s2 = LinkSample(10.0, -60.0, "R1", "AA:BB:CC:DD:EE:FF", 37)
    s3 = LinkSample(10.0, -65.0, "R1", "AA:BB:CC:DD:EE:FF", 37)

    assert s1 == s2
    assert s1 != s3
    assert hash(s1) == hash(s2)

    sample_set = {s1, s2, s3}
    assert len(sample_set) == 2
    assert s1 in sample_set
    assert s3 in sample_set


# ===========================================================================
# 2. HardwareSniffleSource Configuration & Channel Locking
# ===========================================================================

def test_hardware_sniffle_source_r1_locking_and_baud():
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make_hw:
        mock_hw = MagicMock()
        mock_make_hw.return_value = mock_hw

        source = HardwareSniffleSource(
            port="/dev/ttyUSB0",
            baudrate=921600,
            channel=37,
            rx_id="R1",
        )

        source.start()

        mock_make_hw.assert_called_once_with("/dev/ttyUSB0", baudrate=921600, logger=source._logger)
        mock_hw.setup_sniffer.assert_called_once_with(
            mode=SnifferMode.PASSIVE_SCAN,
            chan=37,
            hop3=False,
            targ_mac=None,
            targ_irk=None,
            validate_crc=True,
            rssi_min=-128,
        )

        mock_hw.mark_and_flush.assert_called_once()
        assert source.is_running()

        source.stop()
        assert not source.is_running()
        mock_hw.cancel_recv.assert_called_once()


def test_hardware_sniffle_source_r2_locking_and_baud():
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make_hw:
        mock_hw = MagicMock()
        mock_make_hw.return_value = mock_hw

        source = HardwareSniffleSource(
            port="/dev/ttyUSB1",
            baudrate=921600,
            channel=38,
            rx_id="R2",
        )

        source.start()

        mock_make_hw.assert_called_once_with("/dev/ttyUSB1", baudrate=921600, logger=source._logger)
        mock_hw.setup_sniffer.assert_called_once_with(
            mode=SnifferMode.PASSIVE_SCAN,
            chan=38,
            hop3=False,
            targ_mac=None,
            targ_irk=None,
            validate_crc=True,
            rssi_min=-128,
        )
        mock_hw.mark_and_flush.assert_called_once()
        source.stop()


def test_hardware_sniffle_source_invalid_channel():
    with pytest.raises(ValueError, match="Invalid primary advertising channel"):
        HardwareSniffleSource(channel=36)

    with pytest.raises(ValueError, match="Invalid primary advertising channel"):
        HardwareSniffleSource(channel=40)


def test_setup_sniffer_parameters_prevent_usage_error():
    with patch("sniffle.sniffle_hw.Serial") as mock_serial_cls:
        mock_ser = MagicMock()
        mock_serial_cls.return_value = mock_ser

        hw = SniffleHW(serport="/dev/ttyUSB0", baudrate=921600)

        hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=37, hop3=False)
        hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=38, hop3=False)

        with pytest.raises(UsageError, match="Must specify a target for advertising channel hop"):
            hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=37, hop3=True)


# ===========================================================================
# 3. Packet Decoder Verification Across All Advertising Types
# ===========================================================================

def _create_mock_packet(pdu_type: int, mac_bytes: bytes, rssi: int = -65):
    pkt = MagicMock()
    pkt.body = bytes([pdu_type, 6 + len(mac_bytes)]) + mac_bytes + b"\x00" * 6
    pkt.rssi = rssi
    return pkt


def test_packet_decoding_adv_ind():
    mac_bytes = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    pkt = _create_mock_packet(0x00, mac_bytes, rssi=-64)

    msg = AdvIndMessage(pkt)
    assert hasattr(msg, "AdvA") and msg.AdvA
    assert str_mac(msg.AdvA) == "06:05:04:03:02:01"
    assert msg.rssi == -64


def test_packet_decoding_adv_nonconn_ind():
    mac_bytes = bytes([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33])
    pkt = _create_mock_packet(0x02, mac_bytes, rssi=-70)

    msg = AdvNonconnIndMessage(pkt)
    assert hasattr(msg, "AdvA") and msg.AdvA
    assert str_mac(msg.AdvA) == "33:22:11:CC:BB:AA"
    assert msg.rssi == -70


def test_packet_decoding_scan_rsp():
    mac_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
    pkt = _create_mock_packet(0x04, mac_bytes, rssi=-58)

    msg = ScanRspMessage(pkt)
    assert hasattr(msg, "AdvA") and msg.AdvA
    assert str_mac(msg.AdvA) == "01:00:EF:BE:AD:DE"
    assert msg.rssi == -58


def test_packet_decoding_adv_scan_ind():
    mac_bytes = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
    pkt = _create_mock_packet(0x06, mac_bytes, rssi=-75)

    msg = AdvScanIndMessage(pkt)
    assert hasattr(msg, "AdvA") and msg.AdvA
    assert str_mac(msg.AdvA) == "BC:9A:78:56:34:12"
    assert msg.rssi == -75


def test_packet_decoding_adv_ext_ind():
    mac_bytes = bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54])
    ext_pkt = MagicMock()
    ext_pkt.body = bytes([0x07, 0x07, 0x07, 0x01]) + mac_bytes
    ext_pkt.rssi = -72

    msg = AdvExtIndMessage(ext_pkt)
    assert hasattr(msg, "AdvA") and msg.AdvA
    assert str_mac(msg.AdvA) == "54:76:98:BA:DC:FE"
    assert msg.rssi == -72


def test_hardware_sniffle_source_ingestion_end_to_end_mocked():
    with patch("sniffle.radar.capture.make_sniffle_hw") as mock_make_hw:
        mock_hw = MagicMock()
        mock_make_hw.return_value = mock_hw

        mac1 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        msg1 = AdvIndMessage(_create_mock_packet(0x00, mac1, -61))

        msg_dummy = MagicMock(spec=[])

        mac2 = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ext_pkt = MagicMock()
        ext_pkt.body = bytes([0x07, 0x07, 0x07, 0x01]) + mac2
        ext_pkt.rssi = -68
        msg2 = AdvExtIndMessage(ext_pkt)

        mock_hw.recv_and_decode.side_effect = [msg1, msg_dummy, msg2, None]

        source = HardwareSniffleSource(
            port="/dev/ttyUSB0",
            channel=37,
            rx_id="R1",
        )
        source.start()

        sample1 = source.queue.get(timeout=1.0)
        sample2 = source.queue.get(timeout=1.0)

        source.stop()

        assert sample1.rx_id == "R1"
        assert sample1.channel == 37
        assert sample1.tx_mac == "66:55:44:33:22:11"
        assert sample1.rssi == -61.0

        assert sample2.rx_id == "R1"
        assert sample2.channel == 37
        assert sample2.tx_mac == "FF:EE:DD:CC:BB:AA"
        assert sample2.rssi == -68.0

        assert source.queue.empty()


# ===========================================================================
# 4. MockSniffleSource Simulation & RF Physics Verification
# ===========================================================================

def test_mock_sniffle_source_10_plus_unique_macs_both_channels():
    mock = MockSniffleSource(rx_id="R1", channels=[37, 38], seed=42)
    samples = mock.generate_samples(count=150)

    unique_macs = {s.tx_mac for s in samples}
    channels_seen = {s.channel for s in samples}

    assert len(unique_macs) >= 10
    assert channels_seen == {37, 38}

    for s in samples:
        assert -100.0 <= s.rssi <= -10.0
        assert s.rx_id == "R1"


def test_mock_sniffle_source_log_distance_path_loss():
    custom_txs = [
        {"mac": "AA:BB:CC:11:22:01", "name": "Near_TX", "pos": (1.0, 5.0), "interval": 0.1, "tx_power": -40.0},
        {"mac": "AA:BB:CC:11:22:02", "name": "Far_TX", "pos": (18.0, 5.0), "interval": 0.1, "tx_power": -40.0},
    ]

    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=(0.0, 5.0),
        channel=37,
        transmitters=custom_txs,
        simulate_target=False,
        noise_std=0.0,
        seed=1,
    )

    samples = mock.generate_samples(count=20)
    near_samples = [s.rssi for s in samples if s.tx_mac == "AA:BB:CC:11:22:01"]
    far_samples = [s.rssi for s in samples if s.tx_mac == "AA:BB:CC:11:22:02"]

    assert len(near_samples) > 0 and len(far_samples) > 0
    assert near_samples[0] > far_samples[0] + 20.0


def test_mock_sniffle_source_target_occlusion_and_3sigma_drop():
    tx_pos = (10.0, 5.0)
    rx_pos = (0.0, 5.0)
    noise_sigma = 1.5
    three_sigma = 3.0 * noise_sigma

    tx = [{"mac": "AA:BB:CC:11:22:99", "name": "Test_TX", "pos": tx_pos, "interval": 0.1, "tx_power": -42.0}]

    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=rx_pos,
        channel=37,
        transmitters=tx,
        noise_std=noise_sigma,
        max_target_attenuation=16.0,
        pdr_drop_prob=0.0,
        seed=100,
    )

    mock.set_target_pos(None)
    mock.set_simulate_target(False)
    baseline_samples = [s.rssi for s in mock.generate_samples(count=30)]
    mean_baseline = sum(baseline_samples) / len(baseline_samples)

    mock.set_simulate_target(True)
    mock.set_target_pos((5.0, 5.0))
    occluded_samples = [s.rssi for s in mock.generate_samples(count=30)]
    mean_occluded = sum(occluded_samples) / len(occluded_samples)

    attenuation_drop = mean_baseline - mean_occluded
    assert attenuation_drop >= three_sigma


def test_mock_sniffle_source_pdr_drop_simulation():
    tx = [{"mac": "AA:BB:CC:11:22:99", "name": "Test_TX", "pos": (10.0, 5.0), "interval": 0.05, "tx_power": -42.0}]

    mock = MockSniffleSource(
        rx_id="R1",
        rx_pos=(0.0, 5.0),
        channel=37,
        transmitters=tx,
        pdr_drop_radius=0.6,
        pdr_drop_prob=0.9,
        seed=77,
    )

    mock.set_simulate_target(True)
    mock.set_target_pos((5.0, 5.0))

    samples = []
    sim_time = 0.0
    total_attempts = 50
    for _ in range(total_attempts):
        sim_time += 0.05
        s = mock._compute_sample(tx[0], 37, sim_time, target_xy=(5.0, 5.0))
        if s is not None:
            samples.append(s)

    pdr = len(samples) / total_attempts
    assert pdr < 0.5


def test_mock_sniffle_source_deterministic_seed():
    mock1 = MockSniffleSource(rx_id="R1", channels=[37, 38], seed=12345)
    mock2 = MockSniffleSource(rx_id="R1", channels=[37, 38], seed=12345)

    s1 = mock1.generate_samples(count=40)
    s2 = mock2.generate_samples(count=40)

    for a, b in zip(s1, s2):
        assert a.timestamp == b.timestamp
        assert a.rssi == b.rssi
        assert a.tx_mac == b.tx_mac
        assert a.channel == b.channel


# ===========================================================================
# 5. DualSnifferManager Lifecycle, Streaming & Fallback
# ===========================================================================

def test_dual_sniffer_manager_simulation_mode():
    manager = DualSnifferManager(simulate=True, seed=42)
    assert not manager.is_running()

    manager.start()
    assert manager.is_running()
    assert manager.using_mock

    time.sleep(0.15)
    samples = []
    for s in manager.stream_samples(timeout=0.05):
        samples.append(s)
        if len(samples) >= 15:
            break

    manager.stop()
    assert not manager.is_running()
    assert len(samples) >= 15

    receivers = {s.rx_id for s in samples}
    channels = {s.channel for s in samples}

    assert "R1" in receivers
    assert "R2" in receivers
    assert 37 in channels
    assert 38 in channels


def test_dual_sniffer_manager_context_manager():
    with DualSnifferManager(simulate=True, seed=12) as mgr:
        assert mgr.is_running()
        time.sleep(0.05)

    assert not mgr.is_running()


def test_dual_sniffer_manager_stream_samples_timeout():
    manager = DualSnifferManager(simulate=True, seed=5)
    manager.start()

    count = 0
    for s in manager.stream_samples(timeout=0.1):
        count += 1
        if count >= 5:
            break

    assert count == 5

    manager.stop()
    remaining = list(manager.stream_samples(timeout=0.05))
    assert isinstance(remaining, list)


def test_dual_sniffer_manager_fallback_on_missing_ports():
    manager = DualSnifferManager(
        port1="/dev/ttyNonExistentUSB0",
        port2="/dev/ttyNonExistentUSB1",
        simulate=False,
        fallback_to_mock=True,
        seed=99,
    )

    manager.start()
    assert manager.is_running()
    assert manager.using_mock

    time.sleep(0.1)
    samples = []
    for s in manager.stream_samples(timeout=0.05):
        samples.append(s)
        if len(samples) >= 5:
            break

    assert len(samples) >= 5
    manager.stop()
    assert not manager.is_running()


def test_dual_sniffer_manager_no_fallback_raises():
    manager = DualSnifferManager(
        port1="/dev/ttyNonExistentUSB0",
        port2="/dev/ttyNonExistentUSB1",
        simulate=False,
        fallback_to_mock=False,
    )

    with pytest.raises(Exception):
        manager.start()

    assert not manager.is_running()


def test_point_to_segment_distance():
    pt = (5.0, 6.0)
    seg_start = (0.0, 5.0)
    seg_end = (10.0, 5.0)

    dist, u = point_to_segment_distance(pt, seg_start, seg_end)
    assert pytest.approx(dist, rel=1e-3) == 1.0
    assert pytest.approx(u, rel=1e-3) == 0.5

    pt_before = (-2.0, 5.0)
    dist_b, u_b = point_to_segment_distance(pt_before, seg_start, seg_end)
    assert pytest.approx(dist_b, rel=1e-3) == 2.0
    assert u_b < 0.0

    pt_after = (13.0, 5.0)
    dist_a, u_a = point_to_segment_distance(pt_after, seg_start, seg_end)
    assert pytest.approx(dist_a, rel=1e-3) == 3.0
    assert u_a > 1.0
