import numpy as np
from typing import Optional


def estimate_position(
    heatmap: np.ndarray,
    grid_x: np.ndarray,
    grid_y: np.ndarray,
    threshold_percentile: float = 90.0
) -> Optional[np.ndarray]:
    """
    Solves 2D target position by finding the Center-of-Mass of the hottest
    RF disturbance region above threshold_percentile.
    """
    if heatmap is None or heatmap.max() < 1e-4:
        return None

    thresh = float(np.percentile(heatmap, threshold_percentile))
    active_mask = heatmap > thresh

    if not np.any(active_mask):
        return None

    total_mass = float(np.sum(heatmap[active_mask]))
    if total_mass <= 0.0:
        return None

    x_est = float(np.sum(grid_x[active_mask] * heatmap[active_mask]) / total_mass)
    y_est = float(np.sum(grid_y[active_mask] * heatmap[active_mask]) / total_mass)

    return np.array([x_est, y_est], dtype=np.float64)
