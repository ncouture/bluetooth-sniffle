from typing import Dict, Tuple, List
import numpy as np
from .models import LinkFeatures


class FeatureExtractor:
    """
    Extracts rolling RSSI standard deviation (variance spike), mean residual
    attenuation drop, and packet delivery rate (PDR) per channel.
    """
    def __init__(self, window_size: int = 10, expected_rate_hz: float = 20.0):
        self.window_size = window_size
        self.expected_rate_hz = expected_rate_hz
        self.rssi_buffers: Dict[Tuple[str, str, int], List[float]] = {}
        self.time_buffers: Dict[Tuple[str, str, int], List[float]] = {}

    def add_sample(self, rx_id: str, tx_mac: str, rssi: float, timestamp: float, channel: int = 37):
        key = (rx_id, tx_mac, channel)
        if key not in self.rssi_buffers:
            self.rssi_buffers[key] = []
            self.time_buffers[key] = []
        
        buf_r = self.rssi_buffers[key]
        buf_t = self.time_buffers[key]

        buf_r.append(rssi)
        buf_t.append(timestamp)

        if len(buf_r) > self.window_size:
            buf_r.pop(0)
            buf_t.pop(0)

    def compute_features(
        self,
        rx_id: str,
        tx_mac: str,
        baseline_rssi: float,
        channel: int = 37,
        baseline_std: float = 1.0,
        z_threshold: float = 3.0
    ) -> LinkFeatures:
        key = (rx_id, tx_mac, channel)
        buf_r = self.rssi_buffers.get(key, [])
        buf_t = self.time_buffers.get(key, [])

        if not buf_r:
            return LinkFeatures(std_dev=0.0, attenuation_drop=0.0, pdr=0.0, activity_score=0.0)

        rssi_arr = np.array(buf_r, dtype=np.float64)
        std_dev = float(np.std(rssi_arr))
        mean_rssi = float(np.mean(rssi_arr))
        
        attenuation_drop = max(0.0, baseline_rssi - mean_rssi)
        
        # Robust Z-Score calculation against dynamic idle baseline variance
        z_score = attenuation_drop / max(0.5, baseline_std)

        if len(buf_t) >= 2:
            dt = max(0.001, buf_t[-1] - buf_t[0])
            expected_pkts = max(1.0, dt * self.expected_rate_hz)
            actual_pkts = len(buf_t)
            pdr = min(1.0, actual_pkts / expected_pkts)
        else:
            pdr = 1.0

        turb = max(0.0, std_dev - 1.0)
        
        # Gate activity score by statistically significant anomaly threshold (z >= 3.0)
        if z_score >= z_threshold or turb > 2.5:
            activity_score = attenuation_drop + (1.5 * turb)
        else:
            activity_score = 0.0

        return LinkFeatures(
            std_dev=std_dev,
            attenuation_drop=attenuation_drop if z_score >= z_threshold else 0.0,
            pdr=pdr,
            activity_score=activity_score
        )

