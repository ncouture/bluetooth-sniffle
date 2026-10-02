"""Stimulus-Response Correlation Engine (PoPETs 2025-0103).

Correlates observed Bluetooth Low Energy responses (such as SCAN_REQ probes
or connection indications) against active stimulus bursts (iBeacon, AltBeacon,
Eddystone, GAEN, custom payloads) broadcast by the testbed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from bluetooth_sniffle.protocol.mac import mac_to_str, str_to_mac
from bluetooth_sniffle.sniff.dissector import DissectedBleFrame


@dataclass
class StimulusRecord:
    """Record of an active stimulus burst injected into the RF environment."""

    stimulus_id: str
    burst_id: int
    adv_a: str
    adv_a_raw: bytes
    beacon_type: str
    start_time_usec: int
    duration_usec: int
    channel: int = 37
    payload: bytes = b""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationMatch:
    """Correlated response event linked to an injected stimulus."""

    match_id: str
    stimulus_id: str
    stimulus_adv_a: str
    response_pdu_type: str
    responder_mac: str
    responder_mac_raw: bytes
    responder_type: str
    channel: int
    rssi: int
    stimulus_timestamp_usec: int
    response_timestamp_usec: int
    latency_usec: int
    latency_ms: float
    raw_frame: DissectedBleFrame | None = None


@dataclass
class CorrelationSummary:
    """Aggregate statistical summary of correlation performance."""

    total_stimuli: int = 0
    total_responses: int = 0
    correlated_stimuli_count: int = 0
    response_rate_percent: float = 0.0
    unique_responders_count: int = 0
    unique_responder_macs: list[str] = field(default_factory=list)
    responder_type_distribution: dict[str, int] = field(default_factory=dict)
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    avg_latency_ms: float | None = None
    responses_by_beacon_type: dict[str, int] = field(default_factory=dict)


class StimulusResponseCorrelator:
    """Tracks injected stimulus bursts and correlates observed Link Layer responses."""

    def __init__(
        self,
        max_latency_usec: int = 5_000_000,
        clock_tolerance_usec: int = 200_000,
        history_retention_sec: float = 300.0,
    ) -> None:
        """Initialize correlation engine.

        Args:
            max_latency_usec: Maximum elapsed microseconds post-burst to correlate
                responses (default 5.0s).
            clock_tolerance_usec: Allowed negative latency margin for timer jitter
                (default 200ms).
            history_retention_sec: Maximum age in seconds before purging old records
                (default 5 min).
        """
        self.max_latency_usec: int = max_latency_usec
        self.clock_tolerance_usec: int = clock_tolerance_usec
        self.history_retention_sec: float = history_retention_sec

        self._stimuli: list[StimulusRecord] = []
        self._stimuli_by_id: dict[str, StimulusRecord] = {}
        self._stimuli_by_mac: dict[str, list[StimulusRecord]] = {}
        self._matches: list[CorrelationMatch] = []

    def register_stimulus(
        self,
        adv_a: bytes | str,
        beacon_type: str = "Unknown",
        burst_id: int = 0,
        start_time_usec: int = 0,
        duration_usec: int = 5_000_000,
        channel: int = 37,
        payload: bytes = b"",
        stimulus_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StimulusRecord:
        """Registers an injected stimulus burst."""
        if isinstance(adv_a, str):
            mac_raw = str_to_mac(adv_a)
            mac_str = mac_to_str(mac_raw)
        else:
            if len(adv_a) != 6:
                raise ValueError(f"adv_a must be 6 bytes, got {len(adv_a)}")
            mac_raw = bytes(adv_a)
            mac_str = mac_to_str(mac_raw)

        sid = stimulus_id or f"stim_{burst_id}_{mac_str.replace(':', '')}_{start_time_usec}_{uuid.uuid4().hex[:6]}"

        record = StimulusRecord(
            stimulus_id=sid,
            burst_id=burst_id,
            adv_a=mac_str,
            adv_a_raw=mac_raw,
            beacon_type=beacon_type,
            start_time_usec=start_time_usec,
            duration_usec=duration_usec,
            channel=channel,
            payload=payload,
            metadata=dict(metadata or {}),
        )

        self._stimuli.append(record)
        self._stimuli_by_id[sid] = record
        self._stimuli_by_mac.setdefault(mac_str, []).append(record)

        return record

    def process_frame(
        self, frame: DissectedBleFrame
    ) -> CorrelationMatch | None:
        """Evaluates an observed frame against active stimulus bursts."""
        target_mac: str | None = None
        responder_mac: str | None = None
        responder_mac_raw: bytes = b""
        responder_type: str = "Unknown"

        pdu_type = frame.pdu_type
        if pdu_type == "SCAN_REQ":
            # Scanner probed our advertised address
            target_mac = frame.adv_a
            responder_mac = frame.scan_a
            responder_mac_raw = frame.scan_a_raw or b""
            responder_type = frame.scan_a_type or "Unknown"
        elif pdu_type == "CONNECT_IND":
            target_mac = frame.adv_a
            responder_mac = frame.init_a
            responder_mac_raw = frame.init_a_raw or b""
            responder_type = frame.init_a_type or "Unknown"
        elif pdu_type == "SCAN_RSP":
            target_mac = frame.adv_a
            responder_mac = frame.adv_a
            responder_mac_raw = frame.adv_a_raw or b""
            responder_type = frame.adv_a_type or "Unknown"
        else:
            # Other advertising packets are not elicitations
            return None

        if not target_mac or target_mac not in self._stimuli_by_mac:
            return None

        candidate_stimuli = self._stimuli_by_mac[target_mac]
        frame_ts = frame.timestamp_usec

        # Find the best matching stimulus within valid latency window
        # (iterate in reverse to prefer the most recent stimulus burst)
        for stim in reversed(candidate_stimuli):
            stim_ts = stim.start_time_usec

            # Modulo-32 difference handling 32-bit hardware timestamp wrap
            raw_delta = (frame_ts - stim_ts) & 0xFFFFFFFF
            if raw_delta > 0x80000000:
                signed_delta = raw_delta - 0x100000000
            else:
                signed_delta = raw_delta

            # Timing window check:
            # -clock_tolerance_usec <= delta <= stim.duration_usec + max_latency_usec
            if -self.clock_tolerance_usec <= signed_delta <= (stim.duration_usec + self.max_latency_usec):
                effective_latency_usec = max(0, signed_delta)
                effective_latency_ms = round(effective_latency_usec / 1000.0, 3)

                match_id = f"match_{stim.stimulus_id}_{uuid.uuid4().hex[:8]}"
                match = CorrelationMatch(
                    match_id=match_id,
                    stimulus_id=stim.stimulus_id,
                    stimulus_adv_a=stim.adv_a,
                    response_pdu_type=pdu_type,
                    responder_mac=responder_mac or "",
                    responder_mac_raw=responder_mac_raw,
                    responder_type=responder_type,
                    channel=frame.channel,
                    rssi=frame.rssi,
                    stimulus_timestamp_usec=stim.start_time_usec,
                    response_timestamp_usec=frame_ts,
                    latency_usec=effective_latency_usec,
                    latency_ms=effective_latency_ms,
                    raw_frame=frame,
                )
                self._matches.append(match)
                return match

        return None

    def process_frames(
        self, frames: list[DissectedBleFrame]
    ) -> list[CorrelationMatch]:
        """Processes a batch of captured frames, returning all correlated matches."""
        matches: list[CorrelationMatch] = []
        for frame in frames:
            m = self.process_frame(frame)
            if m is not None:
                matches.append(m)
        return matches

    def get_matches_for_stimulus(
        self, stimulus_id: str
    ) -> list[CorrelationMatch]:
        """Retrieves all response matches associated with a specific stimulus ID."""
        return [m for m in self._matches if m.stimulus_id == stimulus_id]

    def get_summary(self) -> CorrelationSummary:
        """Calculates comprehensive correlation metrics and response distributions."""
        total_stimuli = len(self._stimuli)
        total_responses = len(self._matches)

        correlated_stimuli_ids = {m.stimulus_id for m in self._matches}
        correlated_stimuli_count = len(correlated_stimuli_ids)

        if total_stimuli > 0:
            rate_pct = round((correlated_stimuli_count / total_stimuli) * 100.0, 2)
        else:
            rate_pct = 0.0

        unique_responders = sorted(list({m.responder_mac for m in self._matches if m.responder_mac}))
        unique_responders_count = len(unique_responders)

        type_dist: dict[str, int] = {}
        for m in self._matches:
            t = m.responder_type or "Unknown"
            type_dist[t] = type_dist.get(t, 0) + 1

        min_lat: float | None = None
        max_lat: float | None = None
        avg_lat: float | None = None

        if self._matches:
            latencies = [m.latency_ms for m in self._matches]
            min_lat = min(latencies)
            max_lat = max(latencies)
            avg_lat = round(sum(latencies) / len(latencies), 3)

        responses_by_beacon: dict[str, int] = {}
        for m in self._matches:
            stim = self._stimuli_by_id.get(m.stimulus_id)
            b_type = stim.beacon_type if stim else "Unknown"
            responses_by_beacon[b_type] = responses_by_beacon.get(b_type, 0) + 1

        return CorrelationSummary(
            total_stimuli=total_stimuli,
            total_responses=total_responses,
            correlated_stimuli_count=correlated_stimuli_count,
            response_rate_percent=rate_pct,
            unique_responders_count=unique_responders_count,
            unique_responder_macs=unique_responders,
            responder_type_distribution=type_dist,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            avg_latency_ms=avg_lat,
            responses_by_beacon_type=responses_by_beacon,
        )

    def reset(self) -> None:
        """Flushes all stimulus records and matches."""
        self._stimuli.clear()
        self._stimuli_by_id.clear()
        self._stimuli_by_mac.clear()
        self._matches.clear()

    def evict_expired(self, current_time_usec: int) -> int:
        """Evicts stimuli older than retention window."""
        retention_usec = int(self.history_retention_sec * 1_000_000)

        initial_count = len(self._stimuli)
        valid_stimuli: list[StimulusRecord] = []
        self._stimuli_by_id.clear()
        self._stimuli_by_mac.clear()

        for s in self._stimuli:
            delta = (current_time_usec - s.start_time_usec) & 0xFFFFFFFF
            if delta > 0x80000000:
                delta -= 0x100000000
            if delta <= retention_usec:
                valid_stimuli.append(s)
                self._stimuli_by_id[s.stimulus_id] = s
                self._stimuli_by_mac.setdefault(s.adv_a, []).append(s)

        self._stimuli = valid_stimuli
        return initial_count - len(valid_stimuli)

    def export_summary_dict(self) -> dict[str, Any]:
        """Exports structured dictionary ready for JSON/CSV telemetry serialization."""
        s = self.get_summary()
        return {
            "total_stimuli": s.total_stimuli,
            "total_responses": s.total_responses,
            "correlated_stimuli_count": s.correlated_stimuli_count,
            "response_rate_percent": s.response_rate_percent,
            "unique_responders_count": s.unique_responders_count,
            "unique_responder_macs": s.unique_responder_macs,
            "responder_type_distribution": s.responder_type_distribution,
            "latency_ms": {
                "min": s.min_latency_ms,
                "max": s.max_latency_ms,
                "avg": s.avg_latency_ms,
            },
            "responses_by_beacon_type": s.responses_by_beacon_type,
        }
