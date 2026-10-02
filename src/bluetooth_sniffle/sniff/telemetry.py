"""Structured session telemetry aggregation, JSON schema export, and CSV reporting.

Collects dissected BLE frames across time, tracks device statistics, logs
stimulus-response events, and produces machine-verifiable session artifacts.
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _ts_to_iso(usec: int | None, base_epoch: float) -> str:
    """Converts a microsecond timestamp to an ISO 8601 UTC string."""
    if usec is None:
        return ""
    if usec < 100_000_000_000_000:
        epoch = base_epoch + (usec / 1_000_000.0)
    else:
        epoch = usec / 1_000_000.0
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return dt.isoformat()


@dataclass
class DeviceTelemetrySummary:
    """Longitudinal metrics tracking for a distinct BLE MAC address."""

    mac_address: str
    address_type: str = "unknown"
    packet_count: int = 0
    rssi_min: int = 127
    rssi_max: int = -128
    rssi_sum: int = 0
    first_seen_usec: int | None = None
    last_seen_usec: int | None = None
    observed_names: set[str] = field(default_factory=set)
    manufacturer_profiles: list[dict[str, Any]] = field(default_factory=list)
    service_uuids: set[str] = field(default_factory=set)
    beacon_types: set[str] = field(default_factory=set)
    channels_seen: set[int] = field(default_factory=set)

    @property
    def rssi_avg(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return round(self.rssi_sum / self.packet_count, 2)

    def update(self, frame: Any, unwrapped_ts: int | None = None) -> None:
        """Update telemetry stats with an incoming dissected frame."""
        self.packet_count += 1
        rssi = getattr(frame, "rssi", -60)
        self.rssi_sum += rssi
        if rssi < self.rssi_min:
            self.rssi_min = rssi
        if rssi > self.rssi_max:
            self.rssi_max = rssi

        ts = (
            unwrapped_ts
            if unwrapped_ts is not None
            else getattr(frame, "timestamp_usec", 0)
        )
        if self.first_seen_usec is None or ts < self.first_seen_usec:
            self.first_seen_usec = ts
        if self.last_seen_usec is None or ts > self.last_seen_usec:
            self.last_seen_usec = ts

        addr_type = getattr(frame, "adv_a_type", None)
        if addr_type and self.address_type in ("unknown", None, ""):
            self.address_type = addr_type

        name = getattr(frame, "device_name", None)
        if name:
            self.observed_names.add(str(name).strip())

        chan = getattr(frame, "channel", getattr(frame, "chan", None))
        if chan is not None:
            self.channels_seen.add(chan)

        # Service UUIDs
        uuids_16 = getattr(frame, "service_uuids_16", [])
        for u in uuids_16:
            self.service_uuids.add(f"0x{u:04X}" if isinstance(u, int) else str(u))

        uuids_32 = getattr(frame, "service_uuids_32", [])
        for u in uuids_32:
            self.service_uuids.add(f"0x{u:08X}" if isinstance(u, int) else str(u))

        uuids_128 = getattr(frame, "service_uuids_128", [])
        for u in uuids_128:
            self.service_uuids.add(str(u))

        # Manufacturer data
        mfg = getattr(frame, "manufacturer_data", None)
        if mfg:
            if isinstance(mfg, list):
                for m in mfg:
                    if hasattr(m, "company_id"):
                        m_dict = {
                            "company_id": m.company_id,
                            "company_name": getattr(m, "company_name", ""),
                            "data_hex": getattr(m, "data", b"").hex(),
                        }
                        if m_dict not in self.manufacturer_profiles:
                            self.manufacturer_profiles.append(m_dict)
                    elif isinstance(m, dict) and m not in self.manufacturer_profiles:
                        self.manufacturer_profiles.append(m)
            elif isinstance(m, dict) and m not in self.manufacturer_profiles:
                self.manufacturer_profiles.append(m)

        # Beacon info
        b_type = getattr(frame, "beacon_type", None)
        if not b_type:
            b_info = getattr(frame, "beacon_info", None)
            if b_info:
                b_type = getattr(b_info, "beacon_type", None)
        if b_type:
            self.beacon_types.add(str(b_type))

    def to_dict(self, base_epoch: float = 0.0) -> dict[str, Any]:
        return {
            "mac_address": self.mac_address,
            "address_type": self.address_type,
            "packet_count": self.packet_count,
            "rssi": {
                "min": self.rssi_min if self.packet_count > 0 else 0,
                "max": self.rssi_max if self.packet_count > 0 else 0,
                "avg": self.rssi_avg,
            },
            "first_seen_usec": self.first_seen_usec,
            "last_seen_usec": self.last_seen_usec,
            "first_seen_iso": _ts_to_iso(self.first_seen_usec, base_epoch),
            "last_seen_iso": _ts_to_iso(self.last_seen_usec, base_epoch),
            "observed_names": sorted(list(self.observed_names)),
            "manufacturer_profiles": self.manufacturer_profiles,
            "service_uuids": sorted(list(self.service_uuids)),
            "beacon_types": sorted(list(self.beacon_types)),
            "channels_seen": sorted(list(self.channels_seen)),
        }

    def to_csv_row(self, base_epoch: float = 0.0) -> dict[str, Any]:
        first_iso = _ts_to_iso(self.first_seen_usec, base_epoch)
        last_iso = _ts_to_iso(self.last_seen_usec, base_epoch)
        duration_s = 0.0
        if self.first_seen_usec is not None and self.last_seen_usec is not None:
            duration_s = round(
                (self.last_seen_usec - self.first_seen_usec) / 1_000_000.0, 3
            )

        return {
            "mac_address": self.mac_address,
            "address_type": self.address_type,
            "packet_count": self.packet_count,
            "rssi_min": self.rssi_min if self.packet_count > 0 else "",
            "rssi_max": self.rssi_max if self.packet_count > 0 else "",
            "rssi_avg": self.rssi_avg,
            "first_seen_iso": first_iso,
            "last_seen_iso": last_iso,
            "duration_sec": duration_s,
            "observed_names": ";".join(sorted(list(self.observed_names))),
            "service_uuids": ";".join(sorted(list(self.service_uuids))),
            "beacon_types": ";".join(sorted(list(self.beacon_types))),
            "channels": ";".join(str(c) for c in sorted(list(self.channels_seen))),
        }


@dataclass
class StimulusResponseEvent:
    """Record of an elicited reaction to an active beacon stimulus."""

    burst_id: int | str
    stimulus_mac: str
    stimulus_type: str
    response_pdu_type: str
    responder_mac: str
    responder_mac_type: str = "unknown"
    delta_ms: float = 0.0
    chan: int = 37
    rssi: int = -60
    timestamp_usec: int = 0
    timestamp_iso: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_csv_row(self) -> dict[str, Any]:
        return asdict(self)


class TelemetrySession:
    """Coordinates longitudinal packet telemetry, device statistics, and artifact export."""

    def __init__(
        self,
        session_id: str | None = None,
        base_epoch: float | None = None,
        topology: str | None = None,
    ) -> None:
        self.session_id: str = session_id or str(uuid.uuid4())
        self.base_epoch: float = base_epoch if base_epoch is not None else time.time()
        self.topology: str | None = topology
        self._lock: threading.RLock = threading.RLock()

        self._rollover_count: int = 0
        self._last_raw_usec: int | None = None

        self.start_timestamp_usec: int | None = None
        self.end_timestamp_usec: int | None = None
        self.total_packets: int = 0
        self.channel_packet_counts: dict[int, int] = {37: 0, 38: 0, 39: 0}
        self.devices: dict[str, DeviceTelemetrySummary] = {}
        self.stimulus_response_events: list[StimulusResponseEvent] = []

    def record_packet(self, frame: Any) -> None:
        """Ingest a dissected BLE frame into the session telemetry."""
        with self._lock:
            self.total_packets += 1
            raw_ts = getattr(frame, "timestamp_usec", 0)
            if (
                self._last_raw_usec is not None
                and raw_ts < (self._last_raw_usec - (1 << 31))
            ):
                self._rollover_count += 1
            self._last_raw_usec = raw_ts
            unwrapped_usec = raw_ts + (self._rollover_count * (1 << 32))

            if self.start_timestamp_usec is None or unwrapped_usec < self.start_timestamp_usec:
                self.start_timestamp_usec = unwrapped_usec
            if self.end_timestamp_usec is None or unwrapped_usec > self.end_timestamp_usec:
                self.end_timestamp_usec = unwrapped_usec

            chan = getattr(frame, "channel", getattr(frame, "chan", 37))
            self.channel_packet_counts[chan] = (
                self.channel_packet_counts.get(chan, 0) + 1
            )

            # Ingest primary advertiser address
            adv_a = getattr(frame, "adv_a", None)
            norm_adv = str(adv_a).upper() if adv_a else None
            if norm_adv:
                if norm_adv not in self.devices:
                    self.devices[norm_adv] = DeviceTelemetrySummary(
                        mac_address=norm_adv,
                        address_type=getattr(frame, "adv_a_type", "unknown") or "unknown",
                    )
                self.devices[norm_adv].update(frame, unwrapped_ts=unwrapped_usec)

            # Ingest scanner address if SCAN_REQ
            scan_a = getattr(frame, "scan_a", None)
            norm_scan = str(scan_a).upper() if scan_a else None
            if norm_scan:
                if norm_scan not in self.devices:
                    self.devices[norm_scan] = DeviceTelemetrySummary(
                        mac_address=norm_scan,
                        address_type=getattr(frame, "scan_a_type", "unknown") or "unknown",
                    )
                dev = self.devices[norm_scan]
                scan_type = getattr(frame, "scan_a_type", None)
                if scan_type and dev.address_type in ("unknown", None, ""):
                    dev.address_type = scan_type
                if norm_scan != norm_adv:
                    dev.packet_count += 1
                    rssi = getattr(frame, "rssi", -60)
                    dev.rssi_sum += rssi
                    if rssi < dev.rssi_min:
                        dev.rssi_min = rssi
                    if rssi > dev.rssi_max:
                        dev.rssi_max = rssi
                if dev.first_seen_usec is None or unwrapped_usec < dev.first_seen_usec:
                    dev.first_seen_usec = unwrapped_usec
                if dev.last_seen_usec is None or unwrapped_usec > dev.last_seen_usec:
                    dev.last_seen_usec = unwrapped_usec
                dev.channels_seen.add(chan)

            # Ingest initiator address if CONNECT_IND
            init_a = getattr(frame, "init_a", None)
            norm_init = str(init_a).upper() if init_a else None
            if norm_init:
                if norm_init not in self.devices:
                    self.devices[norm_init] = DeviceTelemetrySummary(
                        mac_address=norm_init,
                        address_type=getattr(frame, "init_a_type", "unknown") or "unknown",
                    )
                dev = self.devices[norm_init]
                init_type = getattr(frame, "init_a_type", None)
                if init_type and dev.address_type in ("unknown", None, ""):
                    dev.address_type = init_type
                if norm_init != norm_adv:
                    dev.packet_count += 1
                    rssi = getattr(frame, "rssi", -60)
                    dev.rssi_sum += rssi
                    if rssi < dev.rssi_min:
                        dev.rssi_min = rssi
                    if rssi > dev.rssi_max:
                        dev.rssi_max = rssi
                if dev.first_seen_usec is None or unwrapped_usec < dev.first_seen_usec:
                    dev.first_seen_usec = unwrapped_usec
                if dev.last_seen_usec is None or unwrapped_usec > dev.last_seen_usec:
                    dev.last_seen_usec = unwrapped_usec
                dev.channels_seen.add(chan)

    def record_event(self, event: StimulusResponseEvent | dict[str, Any]) -> None:
        """Record an observed stimulus-response event."""
        with self._lock:
            if isinstance(event, dict):
                ts = event.get("timestamp_usec", 0)
                iso = event.get("timestamp_iso") or _ts_to_iso(ts, self.base_epoch)
                evt = StimulusResponseEvent(
                    burst_id=event.get("burst_id", 0),
                    stimulus_mac=str(event.get("stimulus_mac", "")).upper(),
                    stimulus_type=str(event.get("stimulus_type", "")),
                    response_pdu_type=str(event.get("response_pdu_type", "")),
                    responder_mac=str(event.get("responder_mac", "")).upper(),
                    responder_mac_type=str(event.get("responder_mac_type", "unknown")),
                    delta_ms=float(event.get("delta_ms", 0.0)),
                    chan=int(event.get("chan", 37)),
                    rssi=int(event.get("rssi", -60)),
                    timestamp_usec=ts,
                    timestamp_iso=iso,
                )
            else:
                evt = event
                if not evt.timestamp_iso:
                    evt.timestamp_iso = _ts_to_iso(evt.timestamp_usec, self.base_epoch)
            self.stimulus_response_events.append(evt)

    def get_summary(self) -> dict[str, Any]:
        """Compile complete structured dictionary of the session state."""
        with self._lock:
            duration_s = 0.0
            if (
                self.start_timestamp_usec is not None
                and self.end_timestamp_usec is not None
            ):
                duration_s = round(
                    (self.end_timestamp_usec - self.start_timestamp_usec)
                    / 1_000_000.0,
                    3,
                )

            meta = {
                "session_id": self.session_id,
                "topology": self.topology,
                "start_timestamp_usec": self.start_timestamp_usec,
                "end_timestamp_usec": self.end_timestamp_usec,
                "start_time_iso": _ts_to_iso(self.start_timestamp_usec, self.base_epoch),
                "end_time_iso": _ts_to_iso(self.end_timestamp_usec, self.base_epoch),
                "duration_sec": duration_s,
                "total_packets": self.total_packets,
                "unique_devices_count": len(self.devices),
                "channel_packet_counts": dict(self.channel_packet_counts),
            }

            devs = [
                dev.to_dict(self.base_epoch)
                for dev in sorted(self.devices.values(), key=lambda d: d.mac_address)
            ]
            evts = [e.to_dict() for e in self.stimulus_response_events]

            return {
                "metadata": meta,
                "devices": devs,
                "stimulus_response_events": evts,
            }

    def to_json(self, indent: int = 2) -> str:
        """Serialize session summary to JSON string."""
        summary = self.get_summary()
        return json.dumps(summary, indent=indent, default=str)

    def export_json(self, path: str | Path, indent: int = 2) -> None:
        """Atomically export session summary to a JSON file."""
        content = self.to_json(indent=indent)
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(
            f".{target.name}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        )
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def export_devices_csv(self, path: str | Path) -> None:
        """Atomically export per-device tracking table to CSV."""
        fieldnames = [
            "mac_address",
            "address_type",
            "packet_count",
            "rssi_min",
            "rssi_max",
            "rssi_avg",
            "first_seen_iso",
            "last_seen_iso",
            "duration_sec",
            "observed_names",
            "service_uuids",
            "beacon_types",
            "channels",
        ]
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(
            f".{target.name}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        )
        try:
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                with self._lock:
                    for dev in sorted(self.devices.values(), key=lambda d: d.mac_address):
                        writer.writerow(dev.to_csv_row(self.base_epoch))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def export_events_csv(self, path: str | Path) -> None:
        """Atomically export stimulus-response event log to CSV."""
        fieldnames = [
            "burst_id",
            "stimulus_mac",
            "stimulus_type",
            "response_pdu_type",
            "responder_mac",
            "responder_mac_type",
            "delta_ms",
            "chan",
            "rssi",
            "timestamp_usec",
            "timestamp_iso",
        ]
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(
            f".{target.name}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        )
        try:
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                with self._lock:
                    for evt in self.stimulus_response_events:
                        writer.writerow(evt.to_csv_row())
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def export_csv(self, path: str | Path, table_type: str = "devices") -> None:
        """Export CSV table (either 'devices' or 'events')."""
        if table_type == "events":
            self.export_events_csv(path)
        else:
            self.export_devices_csv(path)
