"""
BLE RSSI Radar - Link Lifecycle & Ambient Device Matrix Layer.

Provides:
- AddressType: BLE MAC address classification enum.
- classify_ble_mac: Classifier using TxAdd header bit and MAC MSB bits.
- LinkState: 5-state link lifecycle enum.
- LinkRecord: Detailed tracking dataclass for each (TX, RX) link.
- MxNLinkMatrixManager: M ambient transmitters across N receivers (R1 Ch 37, R2 Ch 38).
- PublicDeviceManager: Ambient public BLE device discovery and coordinate tracker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Tuple, Sequence

import numpy as np

from .capture import LinkSample


class NodeType(Enum):
    TRANSMITTER = "TRANSMITTER"
    RECEIVER = "RECEIVER"


class AddressType(Enum):
    PUBLIC = "Public"
    RANDOM_STATIC = "Random_Static"
    RANDOM_RPA = "Random_RPA"
    RANDOM_NRPA = "Random_NRPA"


def classify_ble_mac(mac_str: str, tx_add: int = 0) -> AddressType:
    """
    Classifies a BLE MAC address based on TxAdd header bit and MSB bits:
    - TxAdd == 0 -> Public
    - TxAdd == 1 -> Random:
        - 11b (MSB & 0xC0 == 0xC0): Random Static
        - 01b (MSB & 0xC0 == 0x40): Random RPA (Resolvable Private Address)
        - 00b (MSB & 0xC0 == 0x00): Random NRPA (Non-resolvable Private Address)
    """
    if tx_add == 0:
        return AddressType.PUBLIC

    octets = mac_str.split(":")
    if not octets:
        return AddressType.RANDOM_RPA
    try:
        msb = int(octets[0], 16)
    except ValueError:
        return AddressType.RANDOM_RPA

    msb_bits = (msb >> 6) & 0x03
    if msb_bits == 3:
        return AddressType.RANDOM_STATIC
    elif msb_bits == 1:
        return AddressType.RANDOM_RPA
    else:
        return AddressType.RANDOM_NRPA


class LinkState(Enum):
    DISCOVERING = "DISCOVERING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    PRUNED = "PRUNED"


@dataclass
class LinkRecord:
    """
    State and historical statistics for a single (transmitter MAC, receiver ID) link.
    """
    tx_mac: str
    rx_id: str
    channel: int
    addr_type: AddressType
    baseline_rssi: float = -60.0
    baseline_std: float = 1.0
    current_rssi: float = -60.0
    last_seen: float = 0.0
    packet_count: int = 0
    rssi_history: List[float] = field(default_factory=list)
    time_history: List[float] = field(default_factory=list)
    state: LinkState = LinkState.DISCOVERING
    expected_interval_s: float = 0.1
    pdr: float = 1.0
    activity_score: float = 0.0


class MxNLinkMatrixManager:
    """
    Tracks M ambient transmitters across N receivers (R1 Ch 37, R2 Ch 38).
    Handles dynamic discovery, link promotion, PDR drops, absolute deviations,
    and automatic inactivity pruning for rotating RPAs.
    """
    def __init__(
        self,
        rx_configs: Dict[str, Tuple[int, Tuple[float, float]]],
        inactivity_timeout: float = 30.0,
        occlusion_timeout: float = 3.0,
        min_activation_pkts: int = 3,
        window_size: int = 10,
        room_dim: Tuple[float, float] = (20.0, 10.0),
    ):
        self.rx_configs = rx_configs
        self.inactivity_timeout = inactivity_timeout
        self.occlusion_timeout = occlusion_timeout
        self.min_activation_pkts = min_activation_pkts
        self.window_size = window_size
        self.room_dim = room_dim

        self.tx_nodes: Dict[str, Tuple[float, float]] = {}
        self.tx_addr_types: Dict[str, AddressType] = {}
        self.tx_last_seen: Dict[str, float] = {}
        self.tx_packet_counts: Dict[str, int] = {}
        self.links: Dict[Tuple[str, str], LinkRecord] = {}

    def register_sample(self, sample: LinkSample, tx_add: int = 0) -> Optional[LinkRecord]:
        """Convenience method to register a LinkSample dataclass instance."""
        return self.register_packet(
            timestamp=sample.timestamp,
            rssi=sample.rssi,
            rx_id=sample.rx_id,
            tx_mac=sample.tx_mac,
            channel=sample.channel,
            tx_add=tx_add,
        )

    def register_packet(
        self,
        timestamp: float,
        rssi: float,
        rx_id: str,
        tx_mac: str,
        channel: int,
        tx_add: int = 0,
    ) -> Optional[LinkRecord]:
        """
        Ingests a raw packet observation, updates link history, advances lifecycle,
        and computes features.
        """
        if rx_id not in self.rx_configs:
            return None

        addr_type = classify_ble_mac(tx_mac, tx_add)
        self.tx_last_seen[tx_mac] = timestamp
        self.tx_packet_counts[tx_mac] = self.tx_packet_counts.get(tx_mac, 0) + 1
        self.tx_addr_types[tx_mac] = addr_type

        if tx_mac not in self.tx_nodes:
            seed = sum(ord(c) for c in tx_mac)
            rng = np.random.RandomState(seed)
            x = float(rng.uniform(1.0, max(1.5, self.room_dim[0] - 1.0)))
            y = float(rng.uniform(1.0, max(1.5, self.room_dim[1] - 1.0)))
            self.tx_nodes[tx_mac] = (x, y)

        link_key = (tx_mac, rx_id)
        if link_key not in self.links:
            expected_ch = self.rx_configs[rx_id][0]
            self.links[link_key] = LinkRecord(
                tx_mac=tx_mac,
                rx_id=rx_id,
                channel=expected_ch,
                addr_type=addr_type,
                baseline_rssi=rssi,
                current_rssi=rssi,
                last_seen=timestamp,
                packet_count=1,
                rssi_history=[rssi],
                time_history=[timestamp],
                state=LinkState.DISCOVERING,
            )
        else:
            rec = self.links[link_key]
            rec.last_seen = timestamp
            rec.packet_count += 1
            rec.current_rssi = rssi
            rec.rssi_history.append(rssi)
            rec.time_history.append(timestamp)
            if len(rec.rssi_history) > self.window_size:
                rec.rssi_history.pop(0)
                rec.time_history.pop(0)

            if len(rec.time_history) >= 2 and rec.state == LinkState.DISCOVERING:
                intervals = [rec.time_history[i] - rec.time_history[i - 1] for i in range(1, len(rec.time_history))]
                rec.expected_interval_s = max(0.01, float(np.median(intervals)))

            if rec.state in (LinkState.DISCOVERING, LinkState.DEGRADED, LinkState.STALE):
                if rec.packet_count >= self.min_activation_pkts or rec.state != LinkState.DISCOVERING:
                    rec.state = LinkState.ACTIVE
                    rec.baseline_rssi = float(np.mean(rec.rssi_history))
                    rec.baseline_std = max(0.5, float(np.std(rec.rssi_history)))
            elif rec.state == LinkState.ACTIVE:
                alpha = 0.02
                rec.baseline_rssi = alpha * rssi + (1.0 - alpha) * rec.baseline_rssi

        rec = self.links[link_key]
        dt_window = max(0.1, timestamp - rec.time_history[0]) if len(rec.time_history) >= 2 else 1.0
        expected_pkts = max(1.0, dt_window / max(0.01, rec.expected_interval_s))
        actual_pkts = len(rec.rssi_history)
        rec.pdr = min(1.0, actual_pkts / expected_pkts)
        self._update_link_features(rec, timestamp)
        return rec

    def _update_link_features(self, rec: LinkRecord, current_time: float) -> None:
        """
        Calculates attenuation drop, reflection boost, turbulence, and PDR penalty.
        """
        if not rec.rssi_history:
            return

        mean_rssi = float(np.mean(rec.rssi_history))
        std_dev = max(0.2, float(np.std(rec.rssi_history)))

        attenuation_drop = max(0.0, rec.baseline_rssi - mean_rssi)
        reflection_boost = max(0.0, mean_rssi - rec.baseline_rssi)

        time_since_last = current_time - rec.last_seen
        if time_since_last > self.inactivity_timeout:
            rec.state = LinkState.STALE
            rec.pdr = 0.0
        elif time_since_last > 15.0:
            rec.state = LinkState.STALE
            rec.pdr = 0.0
        elif time_since_last > self.occlusion_timeout and rec.state == LinkState.ACTIVE:
            rec.state = LinkState.DEGRADED
            rec.pdr = 0.0

        pdr_drop = max(0.0, 1.0 - rec.pdr)
        turb = max(0.0, std_dev - 1.0)
        pdr_penalty = pdr_drop * 15.0
        rec.activity_score = attenuation_drop + (0.6 * reflection_boost) + (1.5 * turb) + pdr_penalty

    def prune_inactive(self, current_time: float) -> List[str]:
        """
        Removes transmitters and links that have not been observed for > inactivity_timeout.
        Returns list of pruned MAC addresses.
        """
        pruned_macs = [
            mac for mac, last_t in self.tx_last_seen.items()
            if (current_time - last_t) > self.inactivity_timeout
        ]

        for mac in pruned_macs:
            self.tx_nodes.pop(mac, None)
            self.tx_last_seen.pop(mac, None)
            self.tx_packet_counts.pop(mac, None)
            self.tx_addr_types.pop(mac, None)

            for rx_id in self.rx_configs:
                key = (mac, rx_id)
                if key in self.links:
                    self.links[key].state = LinkState.PRUNED
                    del self.links[key]

        return pruned_macs

    def get_matrix(self) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Returns M x N activity score matrix, along with sorted TX MACs and RX IDs.
        """
        tx_list = sorted([
            mac for mac in self.tx_nodes if any(
                self.links.get((mac, rx_id), None) and self.links[(mac, rx_id)].state == LinkState.ACTIVE
                for rx_id in self.rx_configs
            )
        ])
        rx_list = sorted(list(self.rx_configs.keys()))

        M = len(tx_list)
        N = len(rx_list)
        mat = np.zeros((M, N), dtype=np.float64)

        for i, tx_mac in enumerate(tx_list):
            for j, rx_id in enumerate(rx_list):
                key = (tx_mac, rx_id)
                if key in self.links:
                    mat[i, j] = self.links[key].activity_score

        return mat, tx_list, rx_list

    def get_active_matrix_snapshot(self) -> Tuple[List[str], np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns active link keys, current RSSI vector, PDR vector, and baseline RSSI vector.
        Matches interface contract for downstream Anomaly Engine (M3).
        """
        link_keys: List[str] = []
        curr_rssi: List[float] = []
        pdr_list: List[float] = []
        base_rssi: List[float] = []

        for (tx_mac, rx_id), rec in sorted(self.links.items()):
            if rec.state in (LinkState.ACTIVE, LinkState.DEGRADED):
                k_str = f"{rx_id}_{tx_mac}_{rec.channel}"
                link_keys.append(k_str)
                curr_rssi.append(rec.current_rssi)
                pdr_list.append(rec.pdr)
                base_rssi.append(rec.baseline_rssi)

        return (
            link_keys,
            np.array(curr_rssi, dtype=np.float64),
            np.array(pdr_list, dtype=np.float64),
            np.array(base_rssi, dtype=np.float64),
        )


class PublicDeviceManager:
    """
    Tracks discovered ambient BLE advertiser nodes and their spatial positions.
    Guarantees deterministic coordinate mapping within room bounds and inactivity pruning.
    """
    def __init__(self, room_dim: Tuple[float, float] = (20.0, 10.0), inactivity_timeout: float = 30.0):
        self.room_dim = room_dim
        self.inactivity_timeout = inactivity_timeout
        self.nodes: Dict[str, Dict[str, Any]] = {}

    def register_sample(self, sample: LinkSample, tx_add: int = 0) -> Any:
        self.register_packet(sample.timestamp, sample.rssi, sample.rx_id, sample.tx_mac, sample.channel, tx_add)
        from .models import Node, NodeType
        pos = np.array(self.nodes[sample.tx_mac]["pos"])
        return Node(node_id=sample.tx_mac, role=NodeType.TRANSMITTER, position=pos)

    def register_packet(
        self,
        timestamp: float,
        rssi: float,
        rx_id: str,
        tx_mac: str,
        channel: int,
        tx_add: int = 0,
    ) -> None:
        if tx_mac not in self.nodes:
            seed = sum(ord(c) for c in tx_mac)
            rng = np.random.RandomState(seed)
            x = float(rng.uniform(1.0, max(1.5, self.room_dim[0] - 1.0)))
            y = float(rng.uniform(1.0, max(1.5, self.room_dim[1] - 1.0)))
            self.nodes[tx_mac] = {
                "mac": tx_mac,
                "role": NodeType.TRANSMITTER,
                "pos": (x, y),
                "addr_type": classify_ble_mac(tx_mac, tx_add),
                "last_seen": timestamp,
                "packet_count": 1,
            }
        else:
            n = self.nodes[tx_mac]
            n["last_seen"] = timestamp
            n["packet_count"] += 1

    def get_active_nodes(self) -> Dict[str, Any]:
        from .models import Node, NodeType
        result = {}
        for mac, data in self.nodes.items():
            pos = np.array(data["pos"])
            result[mac] = Node(node_id=mac, role=NodeType.TRANSMITTER, position=pos)
        return result

    def prune_inactive(self, current_time: float) -> List[str]:
        pruned = [
            mac for mac, data in self.nodes.items()
            if (current_time - data["last_seen"]) > self.inactivity_timeout
        ]
        for mac in pruned:
            del self.nodes[mac]
        return pruned
