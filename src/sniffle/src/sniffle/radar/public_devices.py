import numpy as np
from typing import Dict, Tuple, Optional
from .models import Node, NodeType, LinkSample, RFLink


class PublicDeviceManager:
    """
    Dynamically discovers ambient public BLE advertiser MACs over the air,
    estimates anchor positions across the monitored 2D space, and prunes dormant
    MACs after an inactivity timeout.
    """
    def __init__(self, inactivity_timeout: float = 30.0, room_dim: Tuple[float, float] = (20.0, 10.0)):
        self.inactivity_timeout = inactivity_timeout
        self.room_dim = room_dim
        self.nodes: Dict[str, Node] = {}
        self.last_seen: Dict[str, float] = {}

    def register_sample(self, sample: LinkSample) -> Node:
        mac = sample.tx_mac
        self.last_seen[mac] = sample.timestamp

        if mac not in self.nodes:
            # Deterministic pseudo-random position estimate based on MAC hash across perimeter
            seed = sum(ord(c) for c in mac)
            rng = np.random.RandomState(seed)
            x_pos = float(rng.uniform(1.0, self.room_dim[0] - 1.0))
            y_pos = float(rng.uniform(1.0, self.room_dim[1] - 1.0))

            self.nodes[mac] = Node(
                node_id=mac,
                role=NodeType.TRANSMITTER,
                position=np.array([x_pos, y_pos])
            )

        return self.nodes[mac]

    def prune_inactive(self, current_time: float):
        inactive_macs = [
            mac for mac, last_t in self.last_seen.items()
            if (current_time - last_t) > self.inactivity_timeout
        ]

        for mac in inactive_macs:
            self.nodes.pop(mac, None)
            self.last_seen.pop(mac, None)

    def get_active_nodes(self) -> Dict[str, Node]:
        return self.nodes
