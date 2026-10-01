"""
BLE RSSI Radar - Robust Anomaly Detection Engine.

Provides:
- compute_wilson_hilferty: Normalizes Chi-Square Mahalanobis distance to standard normal Z.
- LinkAnomalyVector: Output dataclass holding per-link and multivariate anomaly scores.
- RobustAnomalyEngine: Statistical engine computing Robust Z-Score (Median/MAD)
  and Regularized Mahalanobis Distance with selective baseline freezing (>= 3.0 sigma).
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np


def compute_wilson_hilferty(d_sq: float, K: int) -> float:
    """
    Transforms Chi-Square distributed squared Mahalanobis distance D_M^2
    with K degrees of freedom into an equivalent standard normal Z-score
    via the Wilson-Hilferty cube-root transformation:

    Z_M = ((D_M^2 / K)^(1/3) - (1 - 2 / (9*K))) / sqrt(2 / (9*K))
    """
    if K <= 0 or d_sq <= 0.0:
        return 0.0
    term1 = (d_sq / K) ** (1.0 / 3.0)
    term2 = 1.0 - (2.0 / (9.0 * K))
    denom = math.sqrt(2.0 / (9.0 * K))
    return float((term1 - term2) / denom)


@dataclass
class LinkAnomalyVector:
    """
    Anomaly output vector bridging Anomaly Engine and Spatial Tomography.
    """
    link_keys: List[str]
    anomaly_scores: np.ndarray
    mahalanobis_score: float
    is_anomaly: bool


class RobustAnomalyEngine:
    """
    Computes Robust Z-scores and Regularized Multivariate Mahalanobis Distance
    across active link state vectors to detect human attenuation anomalies (>= 3.0 sigma).

    Key features:
    - Median and MAD outlier rejection with min_mad floor (0.5 dBm) and 0.6745 scale.
    - Captures both shadowing drops and constructive multipath reflection boosts.
    - Appends Packet Delivery Rate (PDR) drop penalties.
    - Regularized covariance matrix (S + gamma * I) with shrinkage for singular matrices.
    - Wilson-Hilferty transformation of D_M^2 to standard normal Z_M.
    - Selective baseline freezing: holding baseline history when Z_M >= 3.0.
    """

    def __init__(
        self,
        history_len: int = 30,
        min_mad: float = 0.5,
        alpha_reg: float = 0.05,
    ):
        self.history_len = history_len
        self.min_mad = min_mad
        self.alpha_reg = alpha_reg

        self.link_history: Dict[Any, List[float]] = {}
        self.multivariate_history: List[np.ndarray] = []
        self.tracked_link_keys: List[Any] = []
        self.last_sigma_reg: Optional[np.ndarray] = None

    def update_link_sample(
        self,
        rx_id: str,
        tx_mac: str,
        channel: int,
        rssi: float,
    ) -> None:
        """Appends a new RSSI sample to the historical buffer for the given link."""
        key = (rx_id, tx_mac, channel)
        if key not in self.link_history:
            self.link_history[key] = []
        hist = self.link_history[key]
        hist.append(float(rssi))
        if len(hist) > self.history_len:
            hist.pop(0)

    def compute_link_robust_z(
        self,
        rx_id: str,
        tx_mac: str,
        channel: int,
        current_rssi: float,
        pdr: float = 1.0,
    ) -> Tuple[float, float, float]:
        """
        Computes the robust Z-score using Median and Median Absolute Deviation (MAD):
        Z_robust = 0.6745 * |x - median| / MAD_eff
        Z_drop = 0.6745 * max(0, median - x) / MAD_eff
        Combined score incorporates PDR drop penalty up to 6.0 sigma.

        Returns:
            (z_robust, z_drop, combined_score)
        """
        key = (rx_id, tx_mac, channel)
        hist = self.link_history.get(key, [])
        if len(hist) < 3:
            return (0.0, 0.0, 0.0)

        arr = np.array(hist, dtype=np.float64)
        median_val = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median_val)))
        mad_eff = max(mad, self.min_mad)

        abs_dev = abs(current_rssi - median_val)
        z_robust = 0.6745 * (abs_dev / mad_eff)

        drop = max(0.0, median_val - current_rssi)
        z_drop = 0.6745 * (drop / mad_eff)

        pdr_penalty = max(0.0, (1.0 - pdr) * 6.0)
        combined_score = max(z_robust, z_drop) + pdr_penalty

        return (float(z_robust), float(z_drop), float(combined_score))

    def compute_mahalanobis_anomaly(
        self,
        active_keys: Sequence[Any],
        current_rssi_vec: np.ndarray,
    ) -> Tuple[float, float, np.ndarray]:
        """
        Computes multivariate Mahalanobis distance across active links:
        D_M(x) = sqrt((x - mu)^T * Sigma_reg^-1 * (x - mu))
        Uses covariance shrinkage: Sigma_reg = S + gamma * I.
        Normalizes D_M^2 to an equivalent standard normal Z-score via Wilson-Hilferty.

        Returns:
            (D_M, Z_M, residual_vector)
        """
        K = len(active_keys)
        if K == 0:
            return (0.0, 0.0, np.zeros(0, dtype=np.float64))

        active_keys_list = list(active_keys)
        if active_keys_list != self.tracked_link_keys:
            self.tracked_link_keys = active_keys_list
            self.multivariate_history.clear()

        N = len(self.multivariate_history)
        if N < 3:
            self.multivariate_history.append(current_rssi_vec.copy())
            return (0.0, 0.0, np.zeros(K, dtype=np.float64))

        X = np.array(self.multivariate_history, dtype=np.float64)
        mu = np.median(X, axis=0)
        diff = current_rssi_vec - mu

        if N > 1:
            S = np.cov(X, rowvar=False)
            if K == 1:
                S = np.array([[float(S)]], dtype=np.float64)
        else:
            S = np.zeros((K, K), dtype=np.float64)

        trace_val = float(np.trace(S)) if K > 1 else float(S[0, 0])
        gamma = max(self.alpha_reg * (trace_val / max(K, 1)), self.min_mad**2)
        Sigma_reg = S + gamma * np.eye(K, dtype=np.float64)
        self.last_sigma_reg = Sigma_reg

        try:
            inv_Sigma = np.linalg.pinv(Sigma_reg)
            d_sq = float(diff.T @ inv_Sigma @ diff)
            d_sq = max(0.0, d_sq)
            D_M = math.sqrt(d_sq)
        except Exception:
            D_M = 0.0
            d_sq = 0.0

        Z_M = compute_wilson_hilferty(d_sq, K)

        if Z_M < 3.0:
            self.multivariate_history.append(current_rssi_vec.copy())
            if len(self.multivariate_history) > self.history_len:
                self.multivariate_history.pop(0)

        return (float(D_M), float(Z_M), diff)

    def process_matrix_snapshot(
        self,
        link_keys: List[str],
        current_rssi: np.ndarray,
        pdr_vec: np.ndarray,
    ) -> LinkAnomalyVector:
        """
        End-to-end convenience method: updates buffers, calculates link Z-scores and
        multivariate Mahalanobis score, returning a LinkAnomalyVector.
        """
        K = len(link_keys)
        if K == 0:
            return LinkAnomalyVector(
                link_keys=[],
                anomaly_scores=np.zeros(0, dtype=np.float32),
                mahalanobis_score=0.0,
                is_anomaly=False,
            )

        link_scores = np.zeros(K, dtype=np.float32)
        for i, key_str in enumerate(link_keys):
            parts = key_str.split("_")
            rx_id = parts[0]
            if len(parts) > 2:
                try:
                    ch = int(parts[-1])
                    tx_mac = "_".join(parts[1:-1])
                except ValueError:
                    tx_mac = parts[1]
                    ch = 37
            elif len(parts) == 2:
                tx_mac = parts[1]
                ch = 37
            else:
                tx_mac = key_str
                ch = 37

            self.update_link_sample(rx_id, tx_mac, ch, float(current_rssi[i]))
            pdr = float(pdr_vec[i]) if i < len(pdr_vec) else 1.0
            _, _, comb = self.compute_link_robust_z(rx_id, tx_mac, ch, float(current_rssi[i]), pdr=pdr)
            link_scores[i] = comb

        d_m, z_m, _ = self.compute_mahalanobis_anomaly(link_keys, current_rssi)
        is_anom = (z_m >= 3.0) or (np.max(link_scores) >= 3.0)

        return LinkAnomalyVector(
            link_keys=link_keys,
            anomaly_scores=link_scores,
            mahalanobis_score=z_m,
            is_anomaly=is_anom,
        )
