from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from typing import Tuple, Optional


class NodeType(Enum):
    RECEIVER = "receiver"
    TRANSMITTER = "transmitter"


@dataclass
class Node:
    node_id: str
    role: NodeType
    position: np.ndarray  # 2D coordinates [x, y] in meters

    def __post_init__(self):
        if not isinstance(self.position, np.ndarray):
            self.position = np.array(self.position, dtype=np.float64)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            return False
        return self.node_id == other.node_id and self.role == other.role and np.array_equal(self.position, other.position)


@dataclass
class RFLink:
    rx: Node
    tx: Node

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RFLink):
            return False
        return self.rx == other.rx and self.tx == other.tx

    @property
    def rx_id(self) -> str:
        return self.rx.node_id

    @property
    def tx_id(self) -> str:
        return self.tx.node_id

    @property
    def distance(self) -> float:
        return float(np.linalg.norm(self.rx.position - self.tx.position))

    @property
    def key(self) -> Tuple[str, str]:
        return (self.rx_id, self.tx_id)


@dataclass
class LinkSample:
    timestamp: float
    rssi: float
    rx_id: str
    tx_mac: str
    channel: int = 37


@dataclass
class LinkFeatures:
    std_dev: float
    attenuation_drop: float
    pdr: float
    activity_score: float
