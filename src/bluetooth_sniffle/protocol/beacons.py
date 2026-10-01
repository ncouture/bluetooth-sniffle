"""Bluetooth Low Energy Beacon Synthesis and Encoders (PoPETs 2025-0103).

Provides bit-for-bit synthesis of legacy BLE advertising payloads (<= 31 bytes)
for beacon protocols analyzed in privacy and tracking research:
  - Apple iBeacon (Proximity UUID, Major, Minor, Measured TxPower)
  - AltBeacon (Manufacturer ID, Beacon Code 0xBEAC, Beacon ID, Reference RSSI)
  - Google Eddystone-UID (Namespace, Instance, TxPower at 0m)
  - Google Eddystone-URL (Encoded URI schemes, expansions, TxPower at 0m)
  - Google Eddystone-TLM (Battery mV, Fixed-Point Temp °C, ADV_CNT, SEC_CNT)
  - GAEN (Google/Apple Exposure Notification 0xFD6F, RPI, AEM)
  - BurstCycleHelper (Timing models for 5.0s active stimulation bursts and profile rotation)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from uuid import UUID

# Standard AD Type Constants
AD_TYPE_FLAGS = 0x01
AD_TYPE_COMPLETE_16BIT_UUIDS = 0x03
AD_TYPE_COMPLETE_128BIT_UUIDS = 0x07
AD_TYPE_SERVICE_DATA_16BIT = 0x16
AD_TYPE_MANUFACTURER_SPECIFIC = 0xFF

# Company & Service Identifiers
APPLE_COMPANY_ID = 0x004C
RADIUS_NETWORKS_ID = 0x0118
ALTBEACON_CODE = 0xBEAC
EDDYSTONE_SERVICE_UUID = 0xFEAA
GAEN_SERVICE_UUID = 0xFD6F

# Eddystone-URL Scheme Prefixes (ordered longest first for greedy matching)
EDDYSTONE_URL_SCHEMES: list[tuple[str, int]] = [
    ("https://www.", 0x01),
    ("http://www.", 0x00),
    ("https://", 0x03),
    ("http://", 0x02),
]

# Eddystone-URL Expansion Suffixes (ordered longest first for greedy matching)
EDDYSTONE_URL_EXPANSIONS: list[tuple[str, int]] = [
    (".com/", 0x00),
    (".org/", 0x01),
    (".edu/", 0x02),
    (".net/", 0x03),
    (".info/", 0x04),
    (".biz/", 0x05),
    (".gov/", 0x06),
    (".com", 0x07),
    (".org", 0x08),
    (".edu", 0x09),
    (".net", 0x0A),
    (".info", 0x0B),
    (".biz", 0x0C),
    (".gov", 0x0D),
]


def build_flags(flags: int = 0x06) -> bytes:
    """Builds a 3-byte standard BLE «Flags» AD structure.

    Args:
        flags: 8-bit flag mask. Default 0x06 (LE General Discoverable + BR/EDR Not Supported).

    Returns:
        3 bytes: [0x02, 0x01, flags].
    """
    if not (0 <= flags <= 0xFF):
        raise ValueError(f"Flags must be 0..255, got {flags}")
    return bytes([0x02, AD_TYPE_FLAGS, flags])


def build_ibeacon(
    uuid: UUID | str | bytes,
    major: int,
    minor: int,
    tx_power: int = -59,
    flags: int = 0x06,
) -> bytes:
    """Synthesizes an Apple iBeacon advertising payload (exactly 30 bytes).

    MSD Layout:
      - AD 1 (Flags): [0x02, 0x01, flags] (3 bytes)
      - AD 2 (MSD):   [0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15, UUID (16B), Major (2B BE), Minor (2B BE), tx_power (1B)] (27 bytes)

    NOTE: Major and Minor are Big-Endian (>HH) per Apple Proximity Beacon Specification.

    Args:
        uuid: 128-bit Proximity UUID as UUID object, hyphenated string, or 16 raw bytes.
        major: Sub-group identifier (0..65535).
        minor: Individual beacon identifier (0..65535).
        tx_power: Calibrated RSSI at 1 meter in dBm (-128..127). Default -59 dBm.
        flags: Discoverability flags. Default 0x06.

    Returns:
        30-byte advertising payload.

    Raises:
        ValueError: If any parameter is out of range or malformed.
    """
    if isinstance(uuid, UUID):
        uuid_bytes = uuid.bytes
    elif isinstance(uuid, str):
        uuid_bytes = UUID(uuid).bytes
    elif isinstance(uuid, (bytes, bytearray)):
        if len(uuid) != 16:
            raise ValueError(f"Proximity UUID bytes must be 16 bytes, got {len(uuid)}")
        uuid_bytes = bytes(uuid)
    else:
        raise TypeError(f"Unsupported UUID type: {type(uuid)}")

    if not (0 <= major <= 0xFFFF):
        raise ValueError(f"Major must be 0..65535, got {major}")
    if not (0 <= minor <= 0xFFFF):
        raise ValueError(f"Minor must be 0..65535, got {minor}")
    if not (-128 <= tx_power <= 127):
        raise ValueError(f"tx_power must be -128..127, got {tx_power}")

    flags_ad = build_flags(flags)

    # MSD Subtype: 0x02 (iBeacon), Sub-payload length: 0x15 (21 bytes = 16B UUID + 2B Major + 2B Minor + 1B Power)
    msd_data = (
        struct.pack("<H", APPLE_COMPANY_ID)
        + bytes([0x02, 0x15])
        + uuid_bytes
        + struct.pack(">HH", major, minor)  # Big-Endian Major/Minor per Apple spec
        + struct.pack("<b", tx_power)
    )
    msd_ad = bytes([len(msd_data) + 1, AD_TYPE_MANUFACTURER_SPECIFIC]) + msd_data

    packet = flags_ad + msd_ad
    if len(packet) != 30:
        raise ValueError(f"Unexpected iBeacon payload length: {len(packet)} (expected 30)")
    return packet


def build_altbeacon(
    mfg_id: int = RADIUS_NETWORKS_ID,
    beacon_id: bytes | str = b"\x00" * 20,
    ref_rssi: int = -59,
    mfg_reserved: int = 0x00,
    flags: int = 0x06,
) -> bytes:
    """Synthesizes an AltBeacon advertising payload (exactly 31 bytes).

    MSD Layout:
      - AD 1 (Flags): [0x02, 0x01, flags] (3 bytes)
      - AD 2 (MSD):   [0x1B, 0xFF, mfg_id (2B LE), 0xBE, 0xAC, beacon_id (20B), ref_rssi (1B), mfg_reserved (1B)] (28 bytes)

    Args:
        mfg_id: 16-bit Manufacturer Company ID (default 0x0118 for Radius Networks).
        beacon_id: 20-byte unique identifier (bytes or 40-char hex string).
        ref_rssi: Calibrated RSSI at 1 meter in dBm (-128..127). Default -59 dBm.
        mfg_reserved: 1-byte manufacturer-reserved field (0..255). Default 0x00.
        flags: Discoverability flags. Default 0x06.

    Returns:
        31-byte advertising payload.

    Raises:
        ValueError: If any parameter is out of range or malformed.
    """
    if isinstance(beacon_id, str):
        cleaned = beacon_id.replace(":", "").replace("-", "").strip()
        beacon_id_bytes = bytes.fromhex(cleaned)
    else:
        beacon_id_bytes = bytes(beacon_id)

    if len(beacon_id_bytes) != 20:
        raise ValueError(f"AltBeacon ID must be exactly 20 bytes, got {len(beacon_id_bytes)}")
    if not (0 <= mfg_id <= 0xFFFF):
        raise ValueError(f"mfg_id must be 0..65535, got {mfg_id}")
    if not (-128 <= ref_rssi <= 127):
        raise ValueError(f"ref_rssi must be -128..127, got {ref_rssi}")
    if not (0 <= mfg_reserved <= 0xFF):
        raise ValueError(f"mfg_reserved must be 0..255, got {mfg_reserved}")

    flags_ad = build_flags(flags)

    msd_data = (
        struct.pack("<H", mfg_id)
        + struct.pack(">H", ALTBEACON_CODE)
        + beacon_id_bytes
        + struct.pack("<b", ref_rssi)
        + bytes([mfg_reserved])
    )
    msd_ad = bytes([len(msd_data) + 1, AD_TYPE_MANUFACTURER_SPECIFIC]) + msd_data

    packet = flags_ad + msd_ad
    if len(packet) != 31:
        raise ValueError(f"Unexpected AltBeacon payload length: {len(packet)} (expected 31)")
    return packet


def build_eddystone_uid(
    namespace: bytes | str,
    instance: bytes | str,
    tx_power: int = -20,
    flags: int = 0x06,
) -> bytes:
    """Synthesizes a Google Eddystone-UID advertising payload (exactly 31 bytes).

    Layout:
      - AD 1 (Flags):        [0x02, 0x01, flags] (3 bytes)
      - AD 2 (Service List): [0x03, 0x03, 0xAA, 0xFE] (4 bytes)
      - AD 3 (Service Data): [0x17, 0x16, 0xAA, 0xFE, 0x00 (FrameType), tx_power, Namespace (10B), Instance (6B), 0x00, 0x00 (RFU)] (24 bytes)

    Args:
        namespace: 10-byte Namespace ID as raw bytes or 20-char hex string.
        instance: 6-byte Instance ID as raw bytes or 12-char hex string.
        tx_power: Calibrated TxPower at 0 meters in dBm (-128..127). Default -20 dBm.
        flags: Discoverability flags. Default 0x06.

    Returns:
        31-byte advertising payload.

    Raises:
        ValueError: If namespace is not 10 bytes, instance is not 6 bytes, or parameters out of range.
    """
    if isinstance(namespace, str):
        ns_bytes = bytes.fromhex(namespace.replace(":", "").replace("-", "").strip())
    else:
        ns_bytes = bytes(namespace)

    if isinstance(instance, str):
        inst_bytes = bytes.fromhex(instance.replace(":", "").replace("-", "").strip())
    else:
        inst_bytes = bytes(instance)

    if len(ns_bytes) != 10:
        raise ValueError(f"Eddystone-UID namespace must be 10 bytes, got {len(ns_bytes)}")
    if len(inst_bytes) != 6:
        raise ValueError(f"Eddystone-UID instance must be 6 bytes, got {len(inst_bytes)}")
    if not (-128 <= tx_power <= 127):
        raise ValueError(f"tx_power must be -128..127, got {tx_power}")

    flags_ad = build_flags(flags)
    svc_list_ad = bytes([0x03, AD_TYPE_COMPLETE_16BIT_UUIDS]) + struct.pack("<H", EDDYSTONE_SERVICE_UUID)

    svc_data_content = (
        struct.pack("<H", EDDYSTONE_SERVICE_UUID)
        + bytes([0x00])  # FrameType UID = 0x00
        + struct.pack("<b", tx_power)
        + ns_bytes
        + inst_bytes
        + bytes([0x00, 0x00])  # RFU = 0x0000
    )
    svc_data_ad = bytes([len(svc_data_content) + 1, AD_TYPE_SERVICE_DATA_16BIT]) + svc_data_content

    packet = flags_ad + svc_list_ad + svc_data_ad
    if len(packet) != 31:
        raise ValueError(f"Unexpected Eddystone-UID payload length: {len(packet)} (expected 31)")
    return packet


def _encode_eddystone_url_content(url: str) -> bytes:
    """Encodes a URL string into Eddystone-URL byte sequence using prefix and expansion tables."""
    matched_prefix = None
    prefix_code = None
    for prefix_str, code in EDDYSTONE_URL_SCHEMES:
        if url.startswith(prefix_str):
            matched_prefix = prefix_str
            prefix_code = code
            break

    if matched_prefix is None or prefix_code is None:
        raise ValueError(
            f"URL '{url}' does not start with a valid Eddystone-URL scheme prefix: "
            f"{[s[0] for s in EDDYSTONE_URL_SCHEMES]}"
        )

    rem_url = url[len(matched_prefix):]
    encoded_body = bytearray()
    i = 0
    rem_len = len(rem_url)

    while i < rem_len:
        match_expansion = False
        # Try matching expansion suffixes from current index
        for expansion_str, code in EDDYSTONE_URL_EXPANSIONS:
            if rem_url.startswith(expansion_str, i):
                encoded_body.append(code)
                i += len(expansion_str)
                match_expansion = True
                break

        if not match_expansion:
            c = rem_url[i]
            if ord(c) > 127:
                raise ValueError(f"Non-ASCII character '{c}' in URL '{url}' is not supported")
            encoded_body.append(ord(c))
            i += 1

    return bytes([prefix_code]) + bytes(encoded_body)


def build_eddystone_url(
    url: str,
    tx_power: int = -18,
    flags: int = 0x06,
) -> bytes:
    """Synthesizes a Google Eddystone-URL advertising payload (<= 31 bytes).

    Layout:
      - AD 1 (Flags):        [0x02, 0x01, flags] (3 bytes)
      - AD 2 (Service List): [0x03, 0x03, 0xAA, 0xFE] (4 bytes)
      - AD 3 (Service Data): [len, 0x16, 0xAA, 0xFE, 0x10 (FrameType), tx_power, scheme_prefix, encoded_url...]

    Args:
        url: URL string starting with http://, https://, http://www., or https://www.
        tx_power: Calibrated TxPower at 0 meters in dBm (-128..127). Default -18 dBm.
        flags: Discoverability flags. Default 0x06.

    Returns:
        Advertising payload of at most 31 bytes.

    Raises:
        ValueError: If URL cannot be encoded within the 31-byte legacy BLE advertising limit.
    """
    if not (-128 <= tx_power <= 127):
        raise ValueError(f"tx_power must be -128..127, got {tx_power}")

    encoded_url = _encode_eddystone_url_content(url)

    flags_ad = build_flags(flags)
    svc_list_ad = bytes([0x03, AD_TYPE_COMPLETE_16BIT_UUIDS]) + struct.pack("<H", EDDYSTONE_SERVICE_UUID)

    svc_data_content = (
        struct.pack("<H", EDDYSTONE_SERVICE_UUID)
        + bytes([0x10])  # FrameType URL = 0x10
        + struct.pack("<b", tx_power)
        + encoded_url
    )
    svc_data_ad = bytes([len(svc_data_content) + 1, AD_TYPE_SERVICE_DATA_16BIT]) + svc_data_content

    packet = flags_ad + svc_list_ad + svc_data_ad
    if len(packet) > 31:
        raise ValueError(
            f"Encoded Eddystone-URL payload length {len(packet)} exceeds maximum allowable 31 bytes"
        )
    return packet


def build_eddystone_tlm(
    vbatt_mv: int,
    temp_c: float | None,
    adv_cnt: int,
    sec_cnt: int,
    flags: int = 0x06,
) -> bytes:
    """Synthesizes a Google Eddystone-TLM (unencrypted version 0x00) payload (exactly 25 bytes).

    Layout:
      - AD 1 (Flags):        [0x02, 0x01, flags] (3 bytes)
      - AD 2 (Service List): [0x03, 0x03, 0xAA, 0xFE] (4 bytes)
      - AD 3 (Service Data): [0x11, 0x16, 0xAA, 0xFE, 0x20 (FrameType), 0x00 (Version),
                              VBATT (2B BE), TEMP (2B BE 8.8 fixed-point),
                              ADV_CNT (4B BE), SEC_CNT (4B BE)] (18 bytes)

    Args:
        vbatt_mv: Battery voltage in millivolts (0..65535).
        temp_c: Beacon temperature in degrees Celsius as float (-128.0..127.996),
                or None / -128.0 for unsupported (0x8000).
        adv_cnt: Cumulative advertisement count since boot (0..2^32-1).
        sec_cnt: Cumulative time since boot in 0.1-second / 100ms ticks (0..2^32-1).
        flags: Discoverability flags. Default 0x06.

    Returns:
        25-byte advertising payload.

    Raises:
        ValueError: If any parameter is out of range.
    """
    if not (0 <= vbatt_mv <= 0xFFFF):
        raise ValueError(f"vbatt_mv must be 0..65535, got {vbatt_mv}")
    if not (0 <= adv_cnt <= 0xFFFFFFFF):
        raise ValueError(f"adv_cnt must be 0..4294967295, got {adv_cnt}")
    if not (0 <= sec_cnt <= 0xFFFFFFFF):
        raise ValueError(f"sec_cnt must be 0..4294967295, got {sec_cnt}")

    if temp_c is None or temp_c == -128.0:
        temp_raw = -32768  # 0x8000 in two's complement 16-bit
    else:
        # Check temperature range (-128.0 to ~127.996)
        if temp_c < -128.0 or temp_c > 127.996:
            raise ValueError(f"temp_c must be within -128.0 to 127.996 °C, got {temp_c}")
        # Signed 8.8 fixed point: integer * 256 + fraction * 256
        temp_fixed = round(temp_c * 256.0)
        if temp_fixed < -32768 or temp_fixed > 32767:
            raise ValueError(f"Temperature {temp_c}°C overflows 8.8 fixed point ({temp_fixed})")
        temp_raw = temp_fixed

    flags_ad = build_flags(flags)
    svc_list_ad = bytes([0x03, AD_TYPE_COMPLETE_16BIT_UUIDS]) + struct.pack("<H", EDDYSTONE_SERVICE_UUID)

    svc_data_content = (
        struct.pack("<H", EDDYSTONE_SERVICE_UUID)
        + bytes([0x20, 0x00])  # FrameType TLM = 0x20, Version = 0x00
        + struct.pack(">H", vbatt_mv)
        + struct.pack(">h", temp_raw)  # Signed 8.8 fixed point
        + struct.pack(">II", adv_cnt, sec_cnt)
    )
    svc_data_ad = bytes([len(svc_data_content) + 1, AD_TYPE_SERVICE_DATA_16BIT]) + svc_data_content

    packet = flags_ad + svc_list_ad + svc_data_ad
    if len(packet) != 25:
        raise ValueError(f"Unexpected Eddystone-TLM payload length: {len(packet)} (expected 25)")
    return packet


def build_gaen(
    rpi: bytes | str,
    aem: bytes | str,
    flags: int = 0x1A,
) -> bytes:
    """Synthesizes a Google/Apple Exposure Notification (GAEN) payload (exactly 31 bytes).

    Uses registered 16-bit Service UUID 0xFD6F.
    Layout:
      - AD 1 (Flags):        [0x02, 0x01, 0x1A] (3 bytes, General Discoverable + Simultaneous BR/EDR)
      - AD 2 (Service List): [0x03, 0x03, 0x6F, 0xFD] (4 bytes)
      - AD 3 (Service Data): [0x17, 0x16, 0x6F, 0xFD, RPI (16B), AEM (4B)] (24 bytes)

    Args:
        rpi: 16-byte Rolling Proximity Identifier (bytes or 32-char hex string).
        aem: 4-byte Associated Encrypted Metadata (bytes or 8-char hex string).
        flags: Discoverability flags. Default 0x1A.

    Returns:
        31-byte advertising payload.

    Raises:
        ValueError: If RPI is not 16 bytes, AEM is not 4 bytes, or flags out of range.
    """
    if isinstance(rpi, str):
        rpi_bytes = bytes.fromhex(rpi.replace(":", "").replace("-", "").strip())
    else:
        rpi_bytes = bytes(rpi)

    if isinstance(aem, str):
        aem_bytes = bytes.fromhex(aem.replace(":", "").replace("-", "").strip())
    else:
        aem_bytes = bytes(aem)

    if len(rpi_bytes) != 16:
        raise ValueError(f"GAEN RPI must be exactly 16 bytes, got {len(rpi_bytes)}")
    if len(aem_bytes) != 4:
        raise ValueError(f"GAEN AEM must be exactly 4 bytes, got {len(aem_bytes)}")

    flags_ad = build_flags(flags)
    svc_list_ad = bytes([0x03, AD_TYPE_COMPLETE_16BIT_UUIDS]) + struct.pack("<H", GAEN_SERVICE_UUID)

    svc_data_content = (
        struct.pack("<H", GAEN_SERVICE_UUID)
        + rpi_bytes
        + aem_bytes
    )
    svc_data_ad = bytes([len(svc_data_content) + 1, AD_TYPE_SERVICE_DATA_16BIT]) + svc_data_content

    packet = flags_ad + svc_list_ad + svc_data_ad
    if len(packet) != 31:
        raise ValueError(f"Unexpected GAEN payload length: {len(packet)} (expected 31)")
    return packet


@dataclass
class BurstProfile:
    """Configuration profile for active beacon stimulation bursts."""

    name: str
    adv_data: bytes
    scan_rsp_data: bytes = b""
    mac_address: bytes | None = None
    mac_type: str = "static"
    interval_ms: int = 100
    burst_duration_s: float = 5.0
    idle_duration_s: float = 5.0


class BurstCycleHelper:
    """Helper managing burst schedules and profile rotation for stimulation engines.

    As documented in PoPETs 2025-0103, active injections are pulsed in short
    bursts (typically 5.0 seconds with 100ms advertising interval) followed
    by idle windows to prevent triggering Android background scan rate limiters
    (max 5 scans per 30 seconds for non-system apps).
    """

    def __init__(
        self,
        profiles: list[BurstProfile] | None = None,
        default_burst_s: float = 5.0,
        default_idle_s: float = 5.0,
        default_interval_ms: int = 100,
    ) -> None:
        self.profiles: list[BurstProfile] = list(profiles) if profiles else []
        self.default_burst_s = default_burst_s
        self.default_idle_s = default_idle_s
        self.default_interval_ms = default_interval_ms
        self._current_index = 0

    def add_profile(self, profile: BurstProfile) -> None:
        """Adds a burst profile to the rotation schedule."""
        self.profiles.append(profile)

    def next_profile(self) -> BurstProfile:
        """Rotates to and returns the next profile in the schedule."""
        if not self.profiles:
            raise ValueError("No burst profiles configured in schedule")
        profile = self.profiles[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.profiles)
        return profile

    def reset(self) -> None:
        """Resets the rotation cycle back to the first profile."""
        self._current_index = 0

    @property
    def current_profile(self) -> BurstProfile | None:
        """Returns the profile currently active without advancing rotation."""
        if not self.profiles:
            return None
        return self.profiles[self._current_index]

    @staticmethod
    def estimate_packet_count(burst_duration_s: float, interval_ms: int) -> int:
        """Calculates expected number of advertisement events in a single burst window."""
        if interval_ms <= 0:
            raise ValueError(f"interval_ms must be positive, got {interval_ms}")
        if burst_duration_s < 0:
            raise ValueError(f"burst_duration_s cannot be negative, got {burst_duration_s}")
        return int((burst_duration_s * 1000.0) // interval_ms)

    @staticmethod
    def total_cycle_duration(burst_duration_s: float, idle_duration_s: float) -> float:
        """Calculates total duration of one burst + idle cycle."""
        if burst_duration_s < 0 or idle_duration_s < 0:
            raise ValueError("Durations cannot be negative")
        return burst_duration_s + idle_duration_s
