#!/usr/bin/env python3.13
"""
Passive BLE Human Radar - 2D Radio Tomographic Imaging Engine
Uses Sniffle BLE5 sniffers, static beacon anchors, and ambient BLE devices
for device-free human sensing and 2D spatial tomography.

Self-Documenting CLI Options:
Execute `python3 radar_tomography.py --help` for complete command line usage.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import queue
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

# Ensure python_cli root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sniffle.radar.capture import (
    LinkSample,
    DualSnifferManager,
    HardwareSniffleSource,
    MockSniffleSource,
)
from sniffle.radar.matrix import (
    AddressType,
    LinkState,
    LinkRecord,
    MxNLinkMatrixManager,
    PublicDeviceManager,
)
from sniffle.radar.anomaly import (
    RobustAnomalyEngine,
    LinkAnomalyVector,
    compute_wilson_hilferty,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
    LinkTomographyGrid,
)
from sniffle.radar.visualizer import RadarVisualizer
from sniffle.radar.demuxer import StreamDemuxer
from sniffle.radar.baseline import BaselineTracker
from sniffle.radar.features import FeatureExtractor
from sniffle.radar.localization import estimate_position
from sniffle.radar.tracker import AlphaBetaTracker
from sniffle.radar.models import Node, NodeType, RFLink


def build_cli_parser() -> argparse.ArgumentParser:
    """Builds comprehensive argument parser for radar_tomography CLI."""
    epilog_text = """
Step-by-Step Command Examples:

  1. Multi-Channel Public BLE Sensing (Auto-Discover Ambient Devices across Ch 37, 38, 39):
     python3 radar_tomography.py --public-mode --multi-channel --room-width 20 --room-height 10 --grid-res 0.1

  2. Live Dual-Dongle Hardware Ingestion with Public Device MAC Auto-Discovery:
     python3 radar_tomography.py --port1 /dev/ttyUSB0 --port2 /dev/ttyUSB1 --public-mode --mac-timeout 30.0

  3. Headless Verification (CI / Automated Testing):
     python3 radar_tomography.py --simulate --headless
"""
    parser = argparse.ArgumentParser(
        description="Passive BLE Human Radar - Multi-Channel Public BLE Device Sensing Engine",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_argument_group("Operational Mode")
    group.add_argument("--simulate", action="store_true", default=False, help="Execute 2D indoor RF sensing simulation")
    group.add_argument("--replay", type=str, help="Path to JSON dataset replay file (e.g. radar_sample_data.json)")
    group.add_argument("--headless", action="store_true", default=False, help="Disable Matplotlib GUI rendering")
    group.add_argument("--public-mode", action="store_true", default=True, help="Auto-discover public BLE devices over the air")

    hw = parser.add_argument_group("Hardware Connection (Live Dual Sniffle Mode)")
    hw.add_argument("--port1", type=str, default="/dev/ttyUSB0", help="Serial port for Sniffle Receiver 1 (e.g. /dev/ttyUSB0)")
    hw.add_argument("--port2", type=str, default="/dev/ttyUSB1", help="Serial port for Sniffle Receiver 2 (e.g. /dev/ttyUSB1)")
    hw.add_argument("--chan1", type=int, default=37, choices=[37, 38, 39], help="Primary BLE channel for Dongle 1")
    hw.add_argument("--chan2", type=int, default=38, choices=[37, 38, 39], help="Primary BLE channel for Dongle 2")
    hw.add_argument("--baud", type=int, default=921600, help="Serial baud rate for Sniffle receivers (default: 921600)")
    hw.add_argument("--channel", type=int, default=37, choices=[37, 38, 39], help="Alias for primary channel")
    hw.add_argument("--multi-channel", action="store_true", default=False, help="Enable multi-channel scanning via receiver spatial diversity")

    grid = parser.add_argument_group("Spatial Grid & Algorithm Tuning")
    grid.add_argument("--room-width", type=float, default=20.0, help="Room width X in meters (default: 20.0)")
    grid.add_argument("--room-height", type=float, default=10.0, help="Room height Y in meters (default: 10.0)")
    grid.add_argument("--room-length", type=float, default=10.0, help="Alias for room height Y in meters")
    grid.add_argument("--grid-res", type=float, default=0.2, help="Grid cell size in meters (default: 0.2)")
    grid.add_argument("--threshold", type=float, default=92.0, help="Disturbance percentile threshold (default: 92.0)")
    grid.add_argument("--mac-timeout", type=float, default=30.0, help="Public MAC address inactivity timeout in seconds (default: 30.0)")
    grid.add_argument("--alpha-reg", type=float, default=0.05, help="Covariance shrinkage regularization factor")
    grid.add_argument("--max-frames", type=int, default=None, help="Exit after processing N frames (useful for testing)")

    return parser


# Backward compatibility alias
build_parser = build_cli_parser


def parse_radar_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses and validates CLI arguments."""
    parser = build_cli_parser()
    parsed = parser.parse_args(args)
    if parsed.chan1 not in (37, 38, 39) or parsed.chan2 not in (37, 38, 39):
        raise ValueError("Invalid primary advertising channel")
    if parsed.room_length != 10.0 and parsed.room_height == 10.0:
        parsed.room_height = parsed.room_length
    if parsed.public_mode:
        parsed.multi_channel = False
    return parsed


def capture_from_hardware(
    port: str,
    baud: int,
    channel: int,
    rx_id: str,
    port_name: str,
    multi_channel: bool = False,
    max_packets: int = 15
) -> List[LinkSample]:
    """Connects to physical Sniffle hardware to capture live over-the-air packets."""
    try:
        from sniffle.sniffle_hw import make_sniffle_hw, SnifferMode
        from sniffle.packet_decoder import str_mac

        print(f"[+] Connecting to Sniffle Hardware on {port_name} ({port} @ {baud} baud, Channel={channel})...")
        hw = make_sniffle_hw(port, baudrate=baud)
        hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, chan=channel, hop3=False)
        hw.mark_and_flush()

        samples: List[LinkSample] = []
        for _ in range(max_packets):
            try:
                msg = hw.recv_and_decode()
                tx_mac = "PUBLIC_T1"
                if hasattr(msg, "AdvA") and msg.AdvA:
                    tx_mac = str_mac(msg.AdvA)
                elif hasattr(msg, "adv_mac") and msg.adv_mac:
                    tx_mac = str_mac(msg.adv_mac)
                elif hasattr(msg, "addr") and msg.addr:
                    tx_mac = str_mac(msg.addr)

                rssi_val = float(getattr(msg, "rssi", -60.0))
                ts_val = float(getattr(msg, "timestamp", time.time()))
                ch_val = int(getattr(msg, "chan", channel))

                samples.append(LinkSample(ts_val, rssi_val, rx_id, tx_mac, ch_val))
            except Exception:
                break
        return samples
    except Exception as err:
        print(f"[!] Serial Hardware Connection Alert ({port_name} on {port}): {err}")
        return []


def generate_simulated_samples() -> List[LinkSample]:
    """Generates multi-channel simulated packet samples representing public BLE devices."""
    now = time.time()
    samples = []
    samples.append(LinkSample(now + 0.00, -60.0, "R1", "AA:11:22:33:44:55", 37))
    samples.append(LinkSample(now + 0.02, -61.0, "R2", "AA:11:22:33:44:55", 38))
    samples.append(LinkSample(now + 0.04, -59.5, "R1", "BB:22:33:44:55:66", 39))
    samples.append(LinkSample(now + 0.20, -75.0, "R1", "AA:11:22:33:44:55", 37))
    samples.append(LinkSample(now + 0.22, -78.0, "R2", "AA:11:22:33:44:55", 38))
    return samples


def run_radar_pipeline(
    samples: List[LinkSample],
    room_width: float = 20.0,
    room_height: float = 10.0,
    grid_res: float = 0.1,
    headless: bool = False,
    public_mode: bool = True,
    mac_timeout: float = 30.0,
    mode_name: str = "Public BLE Multi-Channel"
):
    """
    Legacy compatibility runner: processes packet samples, logs packets to stdout,
    and runs spatial tomography reconstruction.
    """
    print("=" * 75)
    print(f"  Passive BLE Human Radar - {mode_name} Mode")
    print("=" * 75)

    room_dim = (room_width, room_height)
    rx_nodes = {
        "R1": Node("R1", NodeType.RECEIVER, np.array([0.5, 0.5])),
        "R2": Node("R2", NodeType.RECEIVER, np.array([room_width - 0.5, 0.5])),
    }

    public_mgr = PublicDeviceManager(inactivity_timeout=mac_timeout, room_dim=room_dim)
    baseline_tracker = BaselineTracker(alpha=0.05)
    feature_extractor = FeatureExtractor(window_size=10, expected_rate_hz=20.0)
    tracker = AlphaBetaTracker(alpha=0.6, beta=0.15)
    demuxer = StreamDemuxer(verbose=True)

    print(f"\n[+] Ingesting & Demultiplexing Public BLE Device Packets Across Channels 37, 38, 39:")
    print("-" * 75)

    all_nodes: Dict[str, Node] = dict(rx_nodes)
    links: List[RFLink] = []
    link_activations: Dict[tuple, float] = {}

    for sample in samples:
        port_label = "port1" if sample.rx_id == "R1" else "port2"
        link_key, rssi, ts = demuxer.process_sample(sample, port_name=port_label)

        tx_node = public_mgr.register_sample(sample)
        all_nodes[tx_node.node_id] = tx_node

        rx_node = rx_nodes.get(sample.rx_id, rx_nodes["R1"])
        rf_link = RFLink(rx=rx_node, tx=tx_node)
        if rf_link not in links:
            links.append(rf_link)

        baseline = baseline_tracker.update(sample.rx_id, sample.tx_mac, rssi, channel=sample.channel)
        baseline_std = baseline_tracker.get_std_dev(sample.rx_id, sample.tx_mac, channel=sample.channel)
        feature_extractor.add_sample(sample.rx_id, sample.tx_mac, rssi, ts, channel=sample.channel)
        features = feature_extractor.compute_features(
            sample.rx_id, sample.tx_mac, baseline, channel=sample.channel, baseline_std=baseline_std, z_threshold=3.0
        )

        link_activations[rf_link.key] = features.activity_score

    print("-" * 75)

    if not links:
        tx_default = public_mgr.register_sample(LinkSample(time.time(), -60.0, "R1", "T1", 37))
        all_nodes["T1"] = tx_default
        links.append(RFLink(rx_nodes["R1"], tx_default))

    tomo = LinkTomographyGrid(room_dim, grid_res, all_nodes, links, ellipse_width=0.4)
    heatmap = tomo.reconstruct_heatmap(link_activations)
    raw_pos = estimate_position(heatmap, tomo.grid_x, tomo.grid_y, threshold_percentile=92)
    smoothed_pos = tracker.update(raw_pos, dt=0.1) if raw_pos is not None else None

    print(f"[+] Public BLE Devices Tracked: {len(public_mgr.get_active_nodes())}")
    print(f"[+] Total Packets Processed:    {demuxer.samples_processed}")
    print(f"[+] 2D Tomography Grid:        {tomo.nx}x{tomo.ny} cells ({grid_res}m resolution)")
    if raw_pos is not None:
        print(f"[+] Raw Estimated Position:    X={raw_pos[0]:.2f}m, Y={raw_pos[1]:.2f}m")
    else:
        print(f"[+] Anomaly Status:            No statistically significant RF disturbance detected (z < 3.0)")
    if smoothed_pos is not None:
        print(f"[+] Smoothed Target Position:  X={smoothed_pos[0]:.2f}m, Y={smoothed_pos[1]:.2f}m")

    if not headless:
        try:
            import matplotlib.pyplot as plt
            plt.figure(figsize=(8, 5))
            plt.imshow(
                heatmap,
                extent=[0, room_dim[0], 0, room_dim[1]],
                origin="lower",
                cmap="inferno"
            )
            plt.colorbar(label="Multi-Channel RF Disturbance Intensity")
            plt.title(f"Multi-Channel Public BLE Radar ({mode_name})")
            plt.tight_layout()
            plt.show()
        except ImportError:
            pass


class RadarTomographyPipeline:
    """
    Integrates the complete sensing pipeline:
    DualSnifferManager -> MxNLinkMatrixManager & PublicDeviceManager
    -> RobustAnomalyEngine -> SpatialTomography2D -> TargetTracker -> RadarVisualizer.
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.running = False

        self.rx_configs: Dict[str, Tuple[int, Tuple[float, float]]] = {
            "R1": (args.chan1, (0.5, 0.5)),
            "R2": (args.chan2, (args.room_width - 0.5, 0.5)),
        }

        self.sniffer = DualSnifferManager(
            port1=args.port1,
            port2=args.port2,
            baudrate=args.baud,
            simulate=args.simulate,
            fallback_to_mock=True,
            rx1_id="R1",
            rx2_id="R2",
            channel1=args.chan1,
            channel2=args.chan2,
            rx_pos1=self.rx_configs["R1"][1],
            rx_pos2=self.rx_configs["R2"][1],
        )

        self.matrix_mgr = MxNLinkMatrixManager(
            rx_configs=self.rx_configs,
            inactivity_timeout=args.mac_timeout,
            room_dim=(args.room_width, args.room_height),
        )
        self.device_mgr = PublicDeviceManager(
            room_dim=(args.room_width, args.room_height),
            inactivity_timeout=args.mac_timeout,
        )

        self.anomaly_engine = RobustAnomalyEngine(
            history_len=30,
            min_mad=0.5,
            alpha_reg=args.alpha_reg,
        )

        self.tomo = SpatialTomography2D(
            room_dim=(args.room_width, args.room_height),
            resolution=args.grid_res,
        )
        self.tracker = TargetTracker(alpha=0.65, beta=0.15)

        self.visualizer = RadarVisualizer(
            room_dim=(args.room_width, args.room_height),
            headless=args.headless,
        )

        self._current_link_keys: List[str] = []
        self._frame_count = 0

    def start(self) -> None:
        """Starts packet acquisition and enters processing loop."""
        self.running = True
        self.sniffer.start()
        print(
            f"[RADAR] DualSniffer started ({'Mock Simulation' if self.sniffer.using_mock else 'Hardware'})."
        )
        print(f"[RADAR] R1 locked to Channel {self.args.chan1}, R2 locked to Channel {self.args.chan2}.")
        print(f"[RADAR] Public mode: {self.args.public_mode} | Room: {self.args.room_width}m x {self.args.room_height}m.")

    def stop(self) -> None:
        """Stops sniffer and releases visualizer."""
        self.running = False
        self.sniffer.stop()
        self.visualizer.close()
        print("[RADAR] Stopped pipeline cleanly.")

    def step(self, timeout: float = 0.05) -> Optional[Dict[str, Any]]:
        """
        Drains available packets from queue, updates link matrix and anomaly engine,
        solves tomography, and updates tracker and visualizer.
        """
        now = time.time()
        packets_ingested = 0

        while True:
            try:
                sample: LinkSample = self.sniffer.queue.get_nowait()
                self.matrix_mgr.register_sample(sample)
                self.device_mgr.register_sample(sample)
                packets_ingested += 1
            except queue.Empty:
                break

        self.matrix_mgr.prune_inactive(now)
        self.device_mgr.prune_inactive(now)

        link_keys, curr_rssi, pdr_vec, base_rssi = self.matrix_mgr.get_active_matrix_snapshot()
        if len(link_keys) == 0:
            time.sleep(timeout)
            return None

        if link_keys != self._current_link_keys:
            self._current_link_keys = list(link_keys)
            active_links: List[Tuple[np.ndarray, np.ndarray]] = []
            center = (self.args.room_width / 2.0, self.args.room_height / 2.0)
            for k_str in link_keys:
                parts = k_str.split("_")
                rx_id = parts[0]
                tx_mac = "_".join(parts[1:-1]) if len(parts) > 2 else parts[1]
                rx_pos = np.array(self.rx_configs.get(rx_id, (37, (0.5, 0.5)))[1], dtype=np.float32)
                tx_pos = np.array(self.matrix_mgr.tx_nodes.get(tx_mac, center), dtype=np.float32)
                active_links.append((rx_pos, tx_pos))
            self.tomo.update_geometry(active_links)

        anom_res = self.anomaly_engine.process_matrix_snapshot(link_keys, curr_rssi, pdr_vec)

        tomo_res = self.tomo.solve(link_keys, anom_res.anomaly_scores)

        raw_target = tomo_res.target_coords
        tracked_target = self.tracker.update(raw_target, dt=0.1)

        self._frame_count += 1
        peak_z = float(anom_res.mahalanobis_score)

        self.visualizer.update_frame(
            heatmap=tomo_res.heatmap,
            target_coords=tracked_target,
            active_links_count=len(link_keys),
            max_intensity=tomo_res.max_intensity,
            anomaly_sigma=peak_z,
        )

        target_str = f"({tracked_target[0]:.2f}, {tracked_target[1]:.2f})" if tracked_target else "None"
        frame_summary = (
            f"[RADAR FRAME {self._frame_count:04d}] "
            f"Links: {len(link_keys):2d} | "
            f"Packets: {packets_ingested:2d} | "
            f"Peak Z: {peak_z:5.2f}σ | "
            f"Intensity: {tomo_res.max_intensity:5.2f} | "
            f"Target: {target_str}"
        )
        print(frame_summary)

        return {
            "frame": self._frame_count,
            "active_links": len(link_keys),
            "target_coords": tracked_target,
            "peak_z": peak_z,
            "max_intensity": tomo_res.max_intensity,
            "heatmap": tomo_res.heatmap,
        }

    def run(self) -> int:
        """Main execution loop."""
        self.start()
        try:
            while self.running:
                self.step(timeout=0.05)
                if self.args.max_frames and self._frame_count >= self.args.max_frames:
                    break
                time.sleep(0.05)
        except KeyboardInterrupt:
            print("\n[RADAR] User interrupted.")
        finally:
            self.stop()
        return 0


def main(cli_args: Optional[List[str]] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(cli_args)

    if args.replay:
        demuxer = StreamDemuxer(verbose=False)
        samples = demuxer.load_json_replay(args.replay)
        run_radar_pipeline(
            samples=samples,
            room_width=args.room_width,
            room_height=args.room_height,
            grid_res=args.grid_res,
            headless=args.headless,
            public_mode=args.public_mode,
            mac_timeout=args.mac_timeout,
            mode_name=f"Replay ({args.replay})"
        )
        return 0
    else:
        pipeline = RadarTomographyPipeline(args)

        def sig_handler(sig, frame):
            pipeline.running = False

        try:
            signal.signal(signal.SIGINT, sig_handler)
            signal.signal(signal.SIGTERM, sig_handler)
        except Exception:
            pass

        return pipeline.run()


if __name__ == "__main__":
    sys.exit(main())
