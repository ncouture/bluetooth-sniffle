import numpy as np
from typing import Optional


class AlphaBetaTracker:
    """
    2D Position trajectory filter (Alpha-Beta filter) to eliminate single-frame
    position jitter and estimate velocity.
    """
    def __init__(self, alpha: float = 0.65, beta: float = 0.15):
        self.alpha = alpha
        self.beta = beta
        self.state_x: Optional[np.ndarray] = None  # Position [x, y]
        self.state_v: np.ndarray = np.array([0.0, 0.0])  # Velocity [vx, vy]

    def update(self, pos_measured: Optional[np.ndarray], dt: float = 0.1) -> Optional[np.ndarray]:
        if pos_measured is None:
            if self.state_x is not None:
                # Predict forward with velocity
                self.state_x += self.state_v * dt
            return self.state_x

        pos_measured = np.array(pos_measured, dtype=np.float64)

        if self.state_x is None:
            # Initialize tracker state
            self.state_x = pos_measured.copy()
            self.state_v = np.array([0.0, 0.0])
            return self.state_x

        # Prediction step
        x_pred = self.state_x + self.state_v * dt

        # Residual / Innovation
        residual = pos_measured - x_pred

        # Correction step
        self.state_x = x_pred + self.alpha * residual
        self.state_v = self.state_v + (self.beta / max(0.001, dt)) * residual

        return self.state_x
