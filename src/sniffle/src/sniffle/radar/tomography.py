"""
BLE RSSI Radar - 2D Spatial Tomography & Tracker.

Provides:
- TomographyResult: Output dataclass holding heatmap, target coordinates, and peak intensity.
- SpatialTomography2D: Radio Tomographic Imaging (RTI) solver on a discretized 2D grid.
  Precomputes 1st Fresnel zone elliptical sensitivity kernel W.
  Solves spatial attenuation field via Dual-Space Tikhonov Regularization:
  x = max(0, W^T (W W^T + alpha I)^-1 y). Fast real-time solve (< 3 ms).
  Extracts dynamic target coordinates (X, Y) via spatial centroid ROI.
- TargetTracker: 2D Alpha-Beta filter with velocity smoothing and blindspot coasting.
- LinkTomographyGrid: Legacy 2D room grid discretization and Fresnel ellipse precomputer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from .models import Node, RFLink


@dataclass
class TomographyResult:
    """
    Result of a tomographic reconstruction solve.
    """
    heatmap: np.ndarray
    target_coords: Optional[Tuple[float, float]]
    max_intensity: float


class SpatialTomography2D:
    """
    2D Radio Tomographic Imaging (RTI) solver for a 20m x 10m grid.
    Precomputes 1st Fresnel zone elliptical sensitivity kernels W_ij.
    Solves spatial attenuation field via Dual-Space Tikhonov Regularization:
    x = max(0, W^T (W W^T + alpha I)^-1 y).
    """

    def __init__(
        self,
        room_dim: Tuple[float, float] = (20.0, 10.0),
        resolution: float = 0.2,
        wavelength: float = 0.125,
        lambda_eff: float = 0.25,
        alpha_tikhonov: float = 0.01,
    ):
        self.room_dim = room_dim
        self.resolution = resolution
        self.wavelength = wavelength
        self.lambda_eff = lambda_eff
        self.alpha = alpha_tikhonov

        self.nx = max(1, int(room_dim[0] / resolution))
        self.ny = max(1, int(room_dim[1] / resolution))
        self.P = self.nx * self.ny

        x = np.linspace(0, room_dim[0], self.nx, dtype=np.float32)
        y = np.linspace(0, room_dim[1], self.ny, dtype=np.float32)
        self.gx, self.gy = np.meshgrid(x, y)

        self.links: List[Tuple[np.ndarray, np.ndarray]] = []
        self.W: Optional[np.ndarray] = None
        self.Gram_inv: Optional[np.ndarray] = None

    def update_geometry(self, links: Sequence[Tuple[np.ndarray, np.ndarray]]) -> None:
        """
        Precomputes W (K x P) matrix for the given link coordinates.
        W_ij = 1 / sqrt(excess + eps) inside Fresnel zone excess <= lambda_eff.
        """
        self.links = list(links)
        K = len(self.links)
        if K == 0:
            self.W = None
            self.Gram_inv = None
            return

        W = np.zeros((K, self.P), dtype=np.float32)
        gx_flat = self.gx.ravel()
        gy_flat = self.gy.ravel()

        for k, (rx_pos, tx_pos) in enumerate(self.links):
            rx_p = np.asarray(rx_pos, dtype=np.float32)
            tx_p = np.asarray(tx_pos, dtype=np.float32)
            d0 = float(np.linalg.norm(rx_p - tx_p))
            d1 = np.sqrt((gx_flat - tx_p[0]) ** 2 + (gy_flat - tx_p[1]) ** 2)
            d2 = np.sqrt((gx_flat - rx_p[0]) ** 2 + (gy_flat - rx_p[1]) ** 2)
            excess = (d1 + d2) - d0

            mask = excess <= self.lambda_eff
            w_row = np.zeros_like(excess)
            w_row[mask] = 1.0 / np.sqrt(excess[mask] + 1e-4)

            norm_val = float(np.sum(w_row))
            if norm_val > 0.0:
                w_row /= norm_val
            W[k] = w_row

        self.W = W
        Gram = W @ W.T + self.alpha * np.eye(K, dtype=np.float32)
        self.Gram_inv = np.linalg.pinv(Gram)

    def solve_attenuation_field(self, link_anomalies: np.ndarray) -> np.ndarray:
        """
        Solves spatial attenuation field image (ny, nx) using Dual Tikhonov Regularization.
        Execution time: < 2 ms.
        """
        if self.W is None or self.Gram_inv is None or len(link_anomalies) == 0:
            return np.zeros((self.ny, self.nx), dtype=np.float32)

        dual_weights = self.Gram_inv @ link_anomalies.astype(np.float32)
        x_field = self.W.T @ dual_weights
        x_field = np.maximum(0.0, x_field)
        return x_field.reshape((self.ny, self.nx))

    def estimate_target_position(
        self,
        heatmap: np.ndarray,
        percentile: float = 93.0,
    ) -> Optional[Tuple[float, float]]:
        """
        Estimates dynamic target coordinates (X, Y) via spatial centroid above percentile.
        Clamps result within room dimensions.
        """
        if heatmap is None or heatmap.size == 0 or float(np.max(heatmap)) < 1e-4:
            return None

        thresh = float(np.percentile(heatmap, percentile))
        roi = heatmap > thresh
        if not np.any(roi):
            return None

        mass = float(np.sum(heatmap[roi]))
        if mass <= 0.0:
            return None

        x_est = float(np.sum(self.gx[roi] * heatmap[roi]) / mass)
        y_est = float(np.sum(self.gy[roi] * heatmap[roi]) / mass)

        x_est = max(0.0, min(float(self.room_dim[0]), x_est))
        y_est = max(0.0, min(float(self.room_dim[1]), y_est))
        return (x_est, y_est)

    def solve(
        self,
        link_keys: Sequence[str],
        anomaly_scores: np.ndarray,
        percentile: float = 93.0,
    ) -> TomographyResult:
        """
        Solves the spatial field and estimates target position, returning a TomographyResult.
        Interface contract for downstream pipeline.
        """
        heatmap = self.solve_attenuation_field(anomaly_scores)
        target_coords = self.estimate_target_position(heatmap, percentile=percentile)
        max_int = float(np.max(heatmap)) if heatmap.size > 0 else 0.0
        return TomographyResult(
            heatmap=heatmap,
            target_coords=target_coords,
            max_intensity=max_int,
        )


class TargetTracker:
    """
    2D Alpha-Beta tracking filter for target position and velocity smoothing
    with blindspot coasting.
    """

    def __init__(self, alpha: float = 0.65, beta: float = 0.15):
        self.alpha = alpha
        self.beta = beta
        self.pos: Optional[np.ndarray] = None
        self.vel: np.ndarray = np.zeros(2, dtype=np.float64)

    def reset(self) -> None:
        """Resets tracker state."""
        self.pos = None
        self.vel = np.zeros(2, dtype=np.float64)

    def update(
        self,
        measurement: Optional[Tuple[float, float]],
        dt: float = 0.1,
    ) -> Optional[Tuple[float, float]]:
        """
        Updates the target state with a new position measurement.
        If measurement is None, coasts the state forward along estimated velocity.
        """
        if dt <= 0.0:
            if self.pos is not None:
                return (float(self.pos[0]), float(self.pos[1]))
            if measurement is not None:
                self.pos = np.array(measurement, dtype=np.float64)
                self.vel = np.zeros(2, dtype=np.float64)
                return (float(self.pos[0]), float(self.pos[1]))
            return None

        if measurement is None:
            if self.pos is not None:
                self.pos = self.pos + self.vel * dt
                return (float(self.pos[0]), float(self.pos[1]))
            return None

        z = np.array(measurement, dtype=np.float64)
        if self.pos is None:
            self.pos = z
            self.vel = np.zeros(2, dtype=np.float64)
            return (float(self.pos[0]), float(self.pos[1]))

        pred_pos = self.pos + self.vel * dt
        residual = z - pred_pos
        self.pos = pred_pos + self.alpha * residual
        self.vel = self.vel + (self.beta / max(1e-3, dt)) * residual

        return (float(self.pos[0]), float(self.pos[1]))


class LinkTomographyGrid:
    """
    Discretizes a 2D room grid and precomputes 1st Fresnel zone Gaussian spatial
    sensitivity weight tensors W_l(x, y) for each RF link (rx, tx).
    (Legacy interface support)
    """
    def __init__(
        self,
        room_dim: Tuple[float, float],
        resolution: float,
        nodes: Dict[str, Node],
        links: List[RFLink],
        ellipse_width: float = 0.4
    ):
        self.room_dim = room_dim
        self.resolution = resolution
        self.nodes = nodes
        self.links = links
        self.sigma_w = ellipse_width

        self.nx = int(room_dim[0] / resolution)
        self.ny = int(room_dim[1] / resolution)

        x = np.linspace(0, room_dim[0], self.nx)
        y = np.linspace(0, room_dim[1], self.ny)
        self.grid_x, self.grid_y = np.meshgrid(x, y)

        self.weights = self._precompute_ellipses()

    def _precompute_ellipses(self) -> np.ndarray:
        tensors = []
        for link in self.links:
            p_rx = link.rx.position
            p_tx = link.tx.position
            d_link = link.distance

            d_rx = np.sqrt((self.grid_x - p_rx[0])**2 + (self.grid_y - p_rx[1])**2)
            d_tx = np.sqrt((self.grid_x - p_tx[0])**2 + (self.grid_y - p_tx[1])**2)

            excess_path = (d_rx + d_tx) - d_link

            w = np.exp(-excess_path / (2.0 * self.sigma_w**2))
            w[excess_path > 1.2] = 0.0

            norm_factor = w.sum() + 1e-6
            w /= norm_factor
            tensors.append(w)

        return np.array(tensors)

    def reconstruct_heatmap(self, link_activations: Dict[Tuple[str, str], float]) -> np.ndarray:
        heatmap = np.zeros((self.ny, self.nx), dtype=np.float64)
        for i, link in enumerate(self.links):
            key = link.key
            intensity = link_activations.get(key, 0.0)
            if intensity > 0.0:
                heatmap += self.weights[i] * intensity

        return heatmap
