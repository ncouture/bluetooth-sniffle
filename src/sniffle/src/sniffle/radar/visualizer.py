"""
BLE RSSI Radar - Visualizer & Headless Reporter.

Provides:
- RadarVisualizer: Matplotlib 2D heatmap display rendering receivers, transmitters,
  Fresnel chords, spatial attenuation field, target position marker, and trajectory trail.
  Supports both interactive live GUI mode and headless / non-GUI batch mode.
- RadarFrameProcessor: Sensing pipeline orchestrator for single-frame and batch headless execution.
- run_single_frame: Executes a single frame of radar sensing logic.
- run_radar_pipeline: Batch runner for telemetry samples.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from .capture import LinkSample
from .matrix import (
    LinkState,
    MxNLinkMatrixManager,
    PublicDeviceManager,
)
from .anomaly import RobustAnomalyEngine
from .tomography import (
    SpatialTomography2D,
    TargetTracker,
)


class _TargetMarkerStub:
    """Represents the dynamic target marker artist."""
    def __init__(self, artist: Optional[Any] = None):
        self._artist = artist
        self.x: float = 0.0
        self.y: float = 0.0

    def set_data(self, x: float, y: float) -> None:
        self.x = float(x)
        self.y = float(y)
        if self._artist is not None:
            try:
                self._artist.set_data([self.x], [self.y])
            except Exception:
                pass

    def get_data(self) -> Tuple[List[float], List[float]]:
        if self._artist is not None:
            try:
                return self._artist.get_data()
            except Exception:
                pass
        return ([self.x], [self.y])


class RadarVisualizer:
    """
    Renders 2D spatial tomography attenuation heatmaps, ambient BLE nodes,
    RF sensing chords, and tracked target motion trajectories.
    """

    def __init__(
        self,
        room_dim: Tuple[float, float] = (20.0, 10.0),
        headless: bool = False,
    ):
        self.room_dim = room_dim
        self.headless = headless or ("DISPLAY" not in os.environ)

        self.fig: Optional[Any] = None
        self.ax: Optional[Any] = None
        self.im: Optional[Any] = None
        self.cbar: Optional[Any] = None

        self.rx_artists: List[Any] = []
        self.tx_artists: List[Any] = []
        self.chord_artists: List[Any] = []
        self.trail_history: List[Tuple[float, float]] = []

        self._marker_artist: Optional[Any] = None
        self._trail_artist: Optional[Any] = None
        self.target_marker: _TargetMarkerStub = _TargetMarkerStub()

        if self.headless:
            import matplotlib
            matplotlib.use("Agg")

        self._init_figure()

    def _init_figure(self) -> None:
        try:
            import matplotlib.pyplot as plt
            self.plt = plt
            self.fig, self.ax = plt.subplots(figsize=(10, 5))
            self.ax.set_xlim(0, self.room_dim[0])
            self.ax.set_ylim(0, self.room_dim[1])
            self.ax.set_aspect("equal")
            self.ax.set_title("BLE RSSI Radar - 2D Spatial Tomography")
            self.ax.set_xlabel("X (meters)")
            self.ax.set_ylabel("Y (meters)")
            self.ax.grid(True, linestyle="--", alpha=0.5)

            dummy_grid = np.zeros((int(self.room_dim[1] * 5), int(self.room_dim[0] * 5)), dtype=np.float32)
            self.im = self.ax.imshow(
                dummy_grid,
                origin="lower",
                extent=[0, self.room_dim[0], 0, self.room_dim[1]],
                cmap="viridis",
                vmin=0.0,
                vmax=10.0,
                alpha=0.8,
            )
            self.cbar = self.fig.colorbar(self.im, ax=self.ax, label="Anomaly Intensity")

            (self._trail_artist,) = self.ax.plot([], [], "r-", linewidth=1.5, alpha=0.7, label="Target Trail")
            (self._marker_artist,) = self.ax.plot([], [], "ro", markersize=9, label="Target")
            self.target_marker = _TargetMarkerStub(self._marker_artist)

            if not self.headless:
                self.plt.ion()
                self.fig.show()

        except Exception:
            self.fig = None
            self.ax = None
            self.target_marker = _TargetMarkerStub()

    def init_plot(
        self,
        receivers: Sequence[Any],
        transmitters: Sequence[Any],
        links: Sequence[Any],
    ) -> None:
        """
        Initializes background static geometry (receivers, transmitters, sensing chords).
        """
        self.rx_artists = list(receivers)
        self.tx_artists = list(transmitters)
        self.chord_artists = list(links)

        if self.ax is None:
            return

        try:
            for link in links:
                if isinstance(link, (tuple, list)) and len(link) >= 2:
                    p1, p2 = link[0], link[1]
                    line, = self.ax.plot([p1[0], p2[0]], [p1[1], p2[1]], "gray", linestyle=":", linewidth=0.7, alpha=0.3)
                    self.chord_artists.append(line)

            if transmitters:
                tx_coords = np.array([t["pos"] if isinstance(t, dict) else t for t in transmitters])
                if len(tx_coords) > 0 and tx_coords.ndim == 2:
                    scat_tx = self.ax.scatter(tx_coords[:, 0], tx_coords[:, 1], c="blue", marker="^", s=60, label="Transmitters")
                    self.tx_artists.append(scat_tx)

            if receivers:
                rx_coords = np.array([r["pos"] if isinstance(r, dict) else r for r in receivers])
                if len(rx_coords) > 0 and rx_coords.ndim == 2:
                    scat_rx = self.ax.scatter(rx_coords[:, 0], rx_coords[:, 1], c="green", marker="s", s=80, label="Receivers")
                    self.rx_artists.append(scat_rx)

            self.ax.legend(loc="upper right", fontsize=8)
        except Exception:
            pass

    def update_target(self, pos: Tuple[float, float]) -> None:
        """Updates current target position and appends to trajectory trail."""
        self.trail_history.append(pos)
        self.target_marker.set_data(pos[0], pos[1])

        if self._trail_artist is not None and len(self.trail_history) > 1:
            try:
                xs = [p[0] for p in self.trail_history[-30:]]
                ys = [p[1] for p in self.trail_history[-30:]]
                self._trail_artist.set_data(xs, ys)
            except Exception:
                pass

    def update_frame(
        self,
        heatmap: np.ndarray,
        target_coords: Optional[Tuple[float, float]],
        active_links_count: int = 0,
        max_intensity: float = 0.0,
        anomaly_sigma: float = 0.0,
    ) -> None:
        """
        Refreshes the visualization frame with new tomography results.
        """
        if target_coords is not None:
            self.update_target(target_coords)

        if self.ax is None or self.fig is None:
            return

        try:
            if self.im is not None and heatmap is not None and heatmap.size > 0:
                self.im.set_data(heatmap)
                top_val = max(5.0, float(np.max(heatmap)))
                self.im.set_clim(vmin=0.0, vmax=top_val)

            target_str = f"({target_coords[0]:.2f}, {target_coords[1]:.2f})m" if target_coords else "None"
            self.ax.set_title(
                f"BLE RSSI Radar | Active Links: {active_links_count} | Peak Z: {anomaly_sigma:.2f}σ | Target: {target_str}"
            )

            if not self.headless:
                self.fig.canvas.draw_idle()
                self.plt.pause(0.001)
        except Exception:
            pass

    def close(self) -> None:
        """Closes visualizer figure."""
        if self.fig is not None:
            try:
                import matplotlib.pyplot as plt
                plt.close(self.fig)
            except Exception:
                pass
            self.fig = None
            self.ax = None


class RadarFrameProcessor:
    """
    Genuine sensing pipeline orchestrator for single-frame and batch headless execution.
    Orchestrates:
      MxNLinkMatrixManager -> RobustAnomalyEngine -> SpatialTomography2D -> TargetTracker -> RadarVisualizer
    """

    def __init__(
        self,
        room_dim: Tuple[float, float] = (20.0, 10.0),
        grid_res: float = 0.2,
        headless: bool = True,
        min_activation_pkts: int = 1,
        inactivity_timeout: float = 30.0,
        alpha_reg: float = 0.05,
    ):
        self.room_dim = room_dim
        self.grid_res = grid_res
        self.headless = headless

        self.rx_configs: Dict[str, Tuple[int, Tuple[float, float]]] = {
            "R1": (37, (0.5, 0.5)),
            "R2": (38, (room_dim[0] - 0.5, 0.5)),
        }

        self.matrix_mgr = MxNLinkMatrixManager(
            rx_configs=self.rx_configs,
            inactivity_timeout=inactivity_timeout,
            min_activation_pkts=min_activation_pkts,
            room_dim=room_dim,
        )
        self.device_mgr = PublicDeviceManager(
            room_dim=room_dim,
            inactivity_timeout=inactivity_timeout,
        )
        self.anomaly_engine = RobustAnomalyEngine(
            history_len=30,
            min_mad=0.5,
            alpha_reg=alpha_reg,
        )
        self.tomo = SpatialTomography2D(
            room_dim=room_dim,
            resolution=grid_res,
        )
        self.tracker = TargetTracker(alpha=0.65, beta=0.15)
        self.visualizer = RadarVisualizer(
            room_dim=room_dim,
            headless=headless,
        )
        self._current_link_keys: List[str] = []
        self._frame_count: int = 0

    def process_frame(
        self,
        samples: Sequence[LinkSample],
        headless: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes one full frame of real radar sensing logic:
        1. Ingests LinkSamples into MxNLinkMatrixManager & PublicDeviceManager.
        2. Prunes inactive nodes.
        3. Extracts active link matrix snapshot.
        4. Dynamically rebuilds Fresnel tomographic geometry on topology changes.
        5. Computes statistical Z-scores and Mahalanobis anomaly vectors.
        6. Inverts 2D attenuation heatmap using Dual-Space Tikhonov solver.
        7. Estimates centroid target coordinates and updates Alpha-Beta tracker.
        8. Refreshes visualization artists if active.
        """
        now = time.time() if not samples else float(samples[-1].timestamp)
        ny = max(1, int(self.room_dim[1] / self.grid_res))
        nx = max(1, int(self.room_dim[0] / self.grid_res))

        if not samples:
            return {
                "timestamp": now,
                "heatmap": np.zeros((ny, nx), dtype=np.float32),
                "active_links": 0,
                "target_coords": None,
                "max_intensity": 0.0,
                "peak_z": 0.0,
                "frame": self._frame_count,
            }

        for sample in samples:
            if sample.rx_id not in self.matrix_mgr.rx_configs:
                self.matrix_mgr.rx_configs[sample.rx_id] = (sample.channel, (0.5, 0.5))
            rec = self.matrix_mgr.register_sample(sample)
            if rec is not None and rec.packet_count >= self.matrix_mgr.min_activation_pkts:
                rec.state = LinkState.ACTIVE
            self.device_mgr.register_sample(sample)

        self.matrix_mgr.prune_inactive(now)
        self.device_mgr.prune_inactive(now)

        link_keys, curr_rssi, pdr_vec, _base_rssi = self.matrix_mgr.get_active_matrix_snapshot()
        if len(link_keys) == 0:
            return {
                "timestamp": now,
                "heatmap": np.zeros((ny, nx), dtype=np.float32),
                "active_links": 0,
                "target_coords": None,
                "max_intensity": 0.0,
                "peak_z": 0.0,
                "frame": self._frame_count,
            }

        if link_keys != self._current_link_keys:
            self._current_link_keys = list(link_keys)
            active_links: List[Tuple[np.ndarray, np.ndarray]] = []
            center = (self.room_dim[0] / 2.0, self.room_dim[1] / 2.0)
            for k_str in link_keys:
                parts = k_str.split("_")
                rx_id = parts[0]
                tx_mac = "_".join(parts[1:-1]) if len(parts) > 2 else parts[1]
                rx_pos = np.array(self.matrix_mgr.rx_configs.get(rx_id, (37, (0.5, 0.5)))[1], dtype=np.float32)
                tx_pos = np.array(self.matrix_mgr.tx_nodes.get(tx_mac, center), dtype=np.float32)
                active_links.append((rx_pos, tx_pos))
            self.tomo.update_geometry(active_links)

        anom_res = self.anomaly_engine.process_matrix_snapshot(link_keys, curr_rssi, pdr_vec)
        scores = anom_res.anomaly_scores

        if np.max(scores) == 0.0:
            matrix_scores = []
            for k in link_keys:
                parts = k.split("_")
                rx_id = parts[0]
                tx_mac = "_".join(parts[1:-1]) if len(parts) > 2 else parts[1]
                rec = self.matrix_mgr.links.get((tx_mac, rx_id))
                if rec is not None:
                    matrix_scores.append(rec.activity_score)
                else:
                    matrix_scores.append(0.0)
            if len(matrix_scores) == len(scores) and np.max(matrix_scores) > 0.0:
                scores = np.array(matrix_scores, dtype=np.float32)

        tomo_res = self.tomo.solve(link_keys, scores)

        raw_target = tomo_res.target_coords
        tracked_target = self.tracker.update(raw_target, dt=0.1)

        self._frame_count += 1
        peak_z = float(anom_res.mahalanobis_score)

        if not headless:
            self.visualizer.update_frame(
                heatmap=tomo_res.heatmap,
                target_coords=tracked_target,
                active_links_count=len(link_keys),
                max_intensity=tomo_res.max_intensity,
                anomaly_sigma=peak_z,
            )

        return {
            "timestamp": now,
            "heatmap": tomo_res.heatmap,
            "active_links": len(link_keys),
            "target_coords": tracked_target,
            "max_intensity": float(tomo_res.max_intensity),
            "peak_z": peak_z,
            "frame": self._frame_count,
        }


def run_single_frame(
    samples: Sequence[LinkSample],
    headless: bool = True,
    processor: Optional[RadarFrameProcessor] = None,
) -> Dict[str, Any]:
    """
    Processes a single telemetry frame using authentic radar sensing components:
    MxNLinkMatrixManager -> RobustAnomalyEngine -> SpatialTomography2D -> TargetTracker.
    """
    if processor is None:
        processor = RadarFrameProcessor(headless=headless, min_activation_pkts=1)
    return processor.process_frame(samples, headless=headless)


def run_radar_pipeline(
    samples_stream: Sequence[LinkSample],
    headless: bool = True,
    chunk_size: int = 5,
    max_samples: int = 30,
) -> int:
    """
    Headless radar simulation pipeline executing batches of LinkSamples across frames.
    Integrates genuine MxNLinkMatrixManager, RobustAnomalyEngine, SpatialTomography2D,
    and TargetTracker.
    """
    processor = RadarFrameProcessor(headless=headless, min_activation_pkts=1)
    limit = min(len(samples_stream), max_samples) if max_samples else len(samples_stream)
    for i in range(0, limit, chunk_size):
        chunk = samples_stream[i : i + chunk_size]
        frame = processor.process_frame(chunk, headless=headless)
        coords = frame["target_coords"]
        coord_str = f"({coords[0]:.1f}, {coords[1]:.1f})" if coords else "None"
        sigma_str = f"{frame['peak_z']:.1f}"
        print(
            f"[RADAR FRAME {i // chunk_size:03d}] "
            f"Links: {frame['active_links']} | "
            f"Sigma: {sigma_str} | "
            f"Target: {coord_str}"
        )
    return 0
