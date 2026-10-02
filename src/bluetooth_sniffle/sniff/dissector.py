"""BLE Link Layer PDU Dissector and Identifier Extractor.

Provides Link Layer advertising channel PDU demuxing, address classification,
AD structure unpacking (LTV), local name decoding with UTF-8 fallback,
Manufacturer-Specific Data (MSD) dissection (Apple, AltBeacon, Microsoft CDP,
Google, and generic vendors), Service UUID and Service Data extraction,
and deep beacon reverse-extraction (iBeacon, AltBeacon, Eddystone-UID/URL/TLM, GAEN).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID

from bluetooth_sniffle.protocol.beacons import (
    ALTBEACON_CODE,
    APPLE_COMPANY_ID,
    EDDYSTONE_SERVICE_UUID,
    EDDYSTONE_URL_EXPANSIONS,
    GAEN_SERVICE_UUID,
    RADIUS_NETWORKS_ID,
)
from bluetooth_sniffle.protocol.mac import (
    mac_to_str,
    str_to_mac,
)

# Link Layer Advertising Channel PDU Types (Bluetooth Core Spec Vol 6 Part B §2.3)
PDU_TYPE_ADV_IND: int = 0x00
PDU_TYPE_ADV_DIRECT_IND: int = 0x01
PDU_TYPE_ADV_NONCONN_IND: int = 0x02
PDU_TYPE_SCAN_REQ: int = 0x03
PDU_TYPE_SCAN_RSP: int = 0x04
PDU_TYPE_CONNECT_IND: int = 0x05
PDU_TYPE_ADV_SCAN_IND: int = 0x06
PDU_TYPE_ADV_EXT_IND: int = 0x07

PDU_TYPE_NAMES: dict[int, str] = {
    PDU_TYPE_ADV_IND: "ADV_IND",
    PDU_TYPE_ADV_DIRECT_IND: "ADV_DIRECT_IND",
    PDU_TYPE_ADV_NONCONN_IND: "ADV_NONCONN_IND",
    PDU_TYPE_SCAN_REQ: "SCAN_REQ",
    PDU_TYPE_SCAN_RSP: "SCAN_RSP",
    PDU_TYPE_CONNECT_IND: "CONNECT_IND",
    PDU_TYPE_ADV_SCAN_IND: "ADV_SCAN_IND",
    PDU_TYPE_ADV_EXT_IND: "ADV_EXT_IND",
}

# Standard AD Types (Bluetooth Core Specification Supplement)
AD_TYPE_FLAGS: int = 0x01
AD_TYPE_INCOMPLETE_16BIT_UUIDS: int = 0x02
AD_TYPE_COMPLETE_16BIT_UUIDS: int = 0x03
AD_TYPE_INCOMPLETE_32BIT_UUIDS: int = 0x04
AD_TYPE_COMPLETE_32BIT_UUIDS: int = 0x05
AD_TYPE_INCOMPLETE_128BIT_UUIDS: int = 0x06
AD_TYPE_COMPLETE_128BIT_UUIDS: int = 0x07
AD_TYPE_SHORTENED_LOCAL_NAME: int = 0x08
AD_TYPE_COMPLETE_LOCAL_NAME: int = 0x09
AD_TYPE_TX_POWER_LEVEL: int = 0x0A
AD_TYPE_SERVICE_DATA_16BIT: int = 0x16
AD_TYPE_SERVICE_DATA_32BIT: int = 0x20
AD_TYPE_SERVICE_DATA_128BIT: int = 0x21
AD_TYPE_MANUFACTURER_SPECIFIC: int = 0xFF

# Well-known Company Identifiers
COMPANY_ID_APPLE: int = APPLE_COMPANY_ID  # 0x004C
COMPANY_ID_MICROSOFT: int = 0x0006
COMPANY_ID_GOOGLE: int = 0x00E0
COMPANY_ID_RADIUS_NETWORKS: int = RADIUS_NETWORKS_ID  # 0x0118

COMPANY_NAMES: dict[int, str] = {
    COMPANY_ID_APPLE: "Apple, Inc.",
    COMPANY_ID_MICROSOFT: "Microsoft",
    COMPANY_ID_GOOGLE: "Google",
    COMPANY_ID_RADIUS_NETWORKS: "Radius Networks, Inc.",
}


class BleAddressType(str, Enum):
    """Bluetooth Low Energy device address classification."""

    PUBLIC = "Public"
    RANDOM_STATIC = "Random Static"
    NRPA = "NRPA"
    RPA = "RPA"
    RFU = "RFU"
    UNKNOWN = "Unknown"


@dataclass
class AdStructure:
    """Parsed Advertising Data (AD) structure (Length, Type, Value)."""

    length: int
    ad_type: int
    value: bytes
    is_malformed: bool = False


@dataclass
class BeaconInfo:
    """Base class for parsed beacon identity and telemetry data."""

    beacon_type: str


@dataclass
class IBeaconInfo(BeaconInfo):
    """Apple iBeacon proximity beacon payload."""

    uuid: UUID
    major: int
    minor: int
    tx_power: int

    def __init__(self, uuid: UUID, major: int, minor: int, tx_power: int):
        super().__init__(beacon_type="iBeacon")
        self.uuid = uuid
        self.major = major
        self.minor = minor
        self.tx_power = tx_power


@dataclass
class AltBeaconInfo(BeaconInfo):
    """Radius Networks AltBeacon specification payload."""

    mfg_id: int
    beacon_code: int
    beacon_id: bytes
    ref_rssi: int
    mfg_reserved: int = 0

    def __init__(
        self,
        mfg_id: int,
        beacon_code: int,
        beacon_id: bytes,
        ref_rssi: int,
        mfg_reserved: int = 0,
    ):
        super().__init__(beacon_type="AltBeacon")
        self.mfg_id = mfg_id
        self.beacon_code = beacon_code
        self.beacon_id = beacon_id
        self.ref_rssi = ref_rssi
        self.mfg_reserved = mfg_reserved


@dataclass
class EddystoneUidInfo(BeaconInfo):
    """Google Eddystone-UID identifier beacon."""

    namespace: bytes
    instance: bytes
    tx_power: int

    def __init__(self, namespace: bytes, instance: bytes, tx_power: int):
        super().__init__(beacon_type="Eddystone-UID")
        self.namespace = namespace
        self.instance = instance
        self.tx_power = tx_power


@dataclass
class EddystoneUrlInfo(BeaconInfo):
    """Google Eddystone-URL broadcast."""

    url: str
    tx_power: int

    def __init__(self, url: str, tx_power: int):
        super().__init__(beacon_type="Eddystone-URL")
        self.url = url
        self.tx_power = tx_power


@dataclass
class EddystoneTlmInfo(BeaconInfo):
    """Google Eddystone-TLM telemetry beacon."""

    version: int
    vbatt_mv: int
    temp_c: float | None
    adv_cnt: int
    sec_cnt: int

    def __init__(
        self,
        version: int,
        vbatt_mv: int,
        temp_c: float | None,
        adv_cnt: int,
        sec_cnt: int,
    ):
        super().__init__(beacon_type="Eddystone-TLM")
        self.version = version
        self.vbatt_mv = vbatt_mv
        self.temp_c = temp_c
        self.adv_cnt = adv_cnt
        self.sec_cnt = sec_cnt


@dataclass
class GaenInfo(BeaconInfo):
    """Google/Apple Exposure Notification (0xFD6F) beacon."""

    rpi: bytes
    aem: bytes

    def __init__(self, rpi: bytes, aem: bytes):
        super().__init__(beacon_type="GAEN")
        self.rpi = rpi
        self.aem = aem


@dataclass
class AppleContinuityMessage:
    """Apple Continuity protocol message encapsulated within MSD."""

    sub_type: int
    sub_type_name: str
    data: bytes


@dataclass
class MicrosoftCdpInfo:
    """Microsoft Connected Devices Platform (MS-CDP) beacon payload."""

    scenario_type: int
    device_type: int
    device_type_name: str
    flags: int
    bt_addr_dev_id: bool
    device_status: int
    salt: int
    device_hash: bytes


@dataclass
class ManufacturerDataRecord:
    """Decoded Manufacturer-Specific Data structure."""

    company_id: int
    company_name: str
    data: bytes
    apple_messages: list[AppleContinuityMessage] = field(default_factory=list)
    microsoft_cdp: MicrosoftCdpInfo | None = None


@dataclass
class ConnectionParams:
    """Link Layer connection parameters from CONNECT_IND PDU."""

    aa_conn: int
    crc_init: int
    win_size: int
    win_offset: int
    interval: int
    latency: int
    timeout: int
    chm: bytes
    hop: int
    sca: int


@dataclass
class DissectedBleFrame:
    """Fully dissected Bluetooth Low Energy Link Layer frame."""

    # Link Layer Header Attributes
    pdu_type: str
    pdu_type_id: int
    tx_add: int
    rx_add: int
    length: int

    # Addresses & Classifications
    adv_a: str | None = None
    adv_a_raw: bytes | None = None
    adv_a_type: str | None = None

    scan_a: str | None = None
    scan_a_raw: bytes | None = None
    scan_a_type: str | None = None

    target_a: str | None = None
    target_a_raw: bytes | None = None
    target_a_type: str | None = None

    init_a: str | None = None
    init_a_raw: bytes | None = None
    init_a_type: str | None = None

    # Dissected Payload Fields
    device_name: str | None = None
    complete_local_name: str | None = None
    shortened_local_name: str | None = None
    flags: int | None = None
    tx_power_level: int | None = None

    # Manufacturer-Specific Data
    manufacturer_data: list[ManufacturerDataRecord] = field(default_factory=list)

    # Service Identifiers
    service_uuids_16: list[int] = field(default_factory=list)
    service_uuids_32: list[int] = field(default_factory=list)
    service_uuids_128: list[UUID] = field(default_factory=list)
    service_data: dict[str, bytes] = field(default_factory=dict)

    # High-level Beacon Fingerprinting
    beacon_type: str | None = None
    beacon_info: BeaconInfo | None = None

    # Connection Indication Parameters
    conn_params: ConnectionParams | None = None

    # Signal Metrics & Metadata
    channel: int = 37
    rssi: int = -60
    timestamp_usec: int = 0

    # Raw Frames & Error Diagnostics
    raw_pdu: bytes = b""
    raw_payload: bytes = b""
    ad_structures: list[AdStructure] = field(default_factory=list)
    is_malformed: bool = False
    error_details: str | None = None

    @property
    def chan(self) -> int:
        """Alias for channel."""
        return self.channel

    @chan.setter
    def chan(self, val: int) -> None:
        self.channel = val


def classify_address(
    mac: bytes | str, is_random: bool | None = None
) -> BleAddressType:
    """Classify a 6-byte MAC address into Public, Random Static, NRPA, or RPA.

    Logic:
      - If is_random is False -> BleAddressType.PUBLIC
      - If is_random is True (or inferred):
        Inspect MSB bits (mac_bytes[5] >> 6):
          11b -> BleAddressType.RANDOM_STATIC
          00b -> BleAddressType.NRPA
          01b -> BleAddressType.RPA
          10b -> BleAddressType.RFU (or Public if inferred)
    """
    if isinstance(mac, str):
        mac_bytes = str_to_mac(mac)
    else:
        if len(mac) != 6:
            raise ValueError(f"MAC address must be 6 bytes, got {len(mac)}")
        mac_bytes = bytes(mac)

    if is_random is False:
        return BleAddressType.PUBLIC

    top2 = mac_bytes[5] >> 6
    if is_random is True:
        if top2 == 0b11:
            return BleAddressType.RANDOM_STATIC
        if top2 == 0b00:
            return BleAddressType.NRPA
        if top2 == 0b01:
            return BleAddressType.RPA
        return BleAddressType.RFU

    # Inferred (is_random is None)
    if top2 == 0b11:
        return BleAddressType.RANDOM_STATIC
    if top2 == 0b00:
        return BleAddressType.NRPA
    if top2 == 0b01:
        return BleAddressType.RPA
    return BleAddressType.PUBLIC


def parse_ad_structures(
    ad_data: bytes,
) -> tuple[list[AdStructure], bool, str | None]:
    """Iteratively unpacks LTV AD structures from advertising payload.

    Halts on zero length padding. Marks malformed on buffer overflow.
    """
    records: list[AdStructure] = []
    i = 0
    is_malformed = False
    err_msg: str | None = None

    while i < len(ad_data):
        length = ad_data[i]
        if length == 0:
            # Trailing zero padding (standard BLE advertising padding)
            break
        if i + 1 + length > len(ad_data):
            is_malformed = True
            err_msg = (
                f"Truncated AD structure: claims length {length} at offset {i}, "
                f"but only {len(ad_data) - i - 1} bytes remain"
            )
            t = ad_data[i + 1] if (i + 1 < len(ad_data)) else 0
            v = ad_data[i + 2 :] if (i + 2 <= len(ad_data)) else b""
            records.append(
                AdStructure(length=length, ad_type=t, value=v, is_malformed=True)
            )
            break

        ad_type = ad_data[i + 1]
        value = ad_data[i + 2 : i + 1 + length]
        records.append(
            AdStructure(
                length=length, ad_type=ad_type, value=value, is_malformed=False
            )
        )
        i += 1 + length

    return records, is_malformed, err_msg


def decode_local_name(ad_value: bytes) -> str:
    """Decodes UTF-8 local name with safe fallback to <hex:...> on decode errors."""
    try:
        return ad_value.decode("utf-8")
    except UnicodeDecodeError:
        return f"<hex:{ad_value.hex()}>"


def decode_apple_msd(
    mfg_data: bytes,
) -> tuple[list[AppleContinuityMessage], BeaconInfo | None]:
    """Parses Apple Continuity messages and iBeacon payloads.

    Returns:
        tuple of (list of AppleContinuityMessage, optional IBeaconInfo)
    """
    messages: list[AppleContinuityMessage] = []
    beacon_info: BeaconInfo | None = None

    # Check for Apple iBeacon: sub-type 0x02, length 0x15 (21 bytes)
    if (
        len(mfg_data) >= 23
        and mfg_data[0] == 0x02
        and mfg_data[1] == 0x15
    ):
        try:
            uuid = UUID(bytes=mfg_data[2:18])
            major, minor = struct.unpack(">HH", mfg_data[18:22])  # Big-Endian per Apple spec!
            tx_power = struct.unpack("<b", mfg_data[22:23])[0]
            beacon_info = IBeaconInfo(
                uuid=uuid, major=major, minor=minor, tx_power=tx_power
            )
        except Exception:
            pass

    # Parse Continuity sub-messages (LTV within MSD)
    sub_names = {
        0x02: "iBeacon",
        0x03: "AirPrint",
        0x05: "AirDrop",
        0x06: "HomeKit",
        0x07: "Proximity Pairing",
        0x08: "Hey Siri",
        0x09: "AirPlay Target",
        0x0A: "AirPlay Source",
        0x0B: "Magic Switch",
        0x0C: "Handoff",
        0x0D: "Tethering Target",
        0x0E: "Tethering Source",
        0x10: "Nearby Info",
        0x12: "Find My",
    }

    idx = 0
    while idx < len(mfg_data):
        if idx + 2 > len(mfg_data):
            break
        sub_type = mfg_data[idx]
        sub_len = mfg_data[idx + 1]
        if idx + 2 + sub_len > len(mfg_data):
            # Truncated sub-message
            sub_data = mfg_data[idx + 2 :]
            messages.append(
                AppleContinuityMessage(
                    sub_type=sub_type,
                    sub_type_name=sub_names.get(sub_type, f"Unknown (0x{sub_type:02X})"),
                    data=sub_data,
                )
            )
            break
        sub_data = mfg_data[idx + 2 : idx + 2 + sub_len]
        messages.append(
            AppleContinuityMessage(
                sub_type=sub_type,
                sub_type_name=sub_names.get(sub_type, f"Unknown (0x{sub_type:02X})"),
                data=sub_data,
            )
        )
        idx += 2 + sub_len

    return messages, beacon_info


def decode_altbeacon_msd(
    company_id: int, mfg_data: bytes
) -> AltBeaconInfo | None:
    """Parses Radius Networks AltBeacon specification payload."""
    if len(mfg_data) >= 24:
        beacon_code = struct.unpack(">H", mfg_data[:2])[0]
        if beacon_code == ALTBEACON_CODE:  # 0xBEAC
            beacon_id = mfg_data[2:22]  # 20 bytes
            ref_rssi = struct.unpack("<b", mfg_data[22:23])[0]
            mfg_reserved = mfg_data[23] if len(mfg_data) > 23 else 0
            return AltBeaconInfo(
                mfg_id=company_id,
                beacon_code=beacon_code,
                beacon_id=beacon_id,
                ref_rssi=ref_rssi,
                mfg_reserved=mfg_reserved,
            )
    return None


def decode_microsoft_msd(mfg_data: bytes) -> MicrosoftCdpInfo | None:
    """Parses Microsoft Connected Devices Platform (MS-CDP) beacon payload."""
    if len(mfg_data) < 25:
        return None

    cdp_device_names = {
        0x01: "Xbox One",
        0x06: "Apple iPhone",
        0x07: "Apple iPad",
        0x08: "Android Device",
        0x09: "Windows 10 Desktop",
        0x0B: "Windows 10 Phone",
        0x0C: "Linx Tablet",
        0x0D: "Surface Hub",
    }

    try:
        scenario = mfg_data[0]
        dev_type = mfg_data[1] & 0x1F
        dev_name = cdp_device_names.get(dev_type, f"Device Type 0x{dev_type:02X}")
        flags = mfg_data[2] & 0x1F
        bt_dev_id = bool(mfg_data[2] & 0x20)
        status = mfg_data[3]
        salt = struct.unpack("<I", mfg_data[4:8])[0]
        dev_hash = mfg_data[8:27] if len(mfg_data) >= 27 else mfg_data[8:]

        return MicrosoftCdpInfo(
            scenario_type=scenario,
            device_type=dev_type,
            device_type_name=dev_name,
            flags=flags,
            bt_addr_dev_id=bt_dev_id,
            device_status=status,
            salt=salt,
            device_hash=dev_hash,
        )
    except Exception:
        return None


def decode_eddystone_service_data(data: bytes) -> BeaconInfo | None:
    """Parses Google Eddystone-UID (0x00), URL (0x10), and TLM (0x20) service data."""
    if not data:
        return None

    frame_type = data[0]

    # Eddystone-UID (0x00)
    if frame_type == 0x00 and len(data) >= 18:
        tx_power = struct.unpack("<b", data[1:2])[0]
        namespace = data[2:12]  # 10 bytes
        instance = data[12:18]  # 6 bytes
        return EddystoneUidInfo(
            namespace=namespace, instance=instance, tx_power=tx_power
        )

    # Eddystone-URL (0x10)
    if frame_type == 0x10 and len(data) >= 3:
        tx_power = struct.unpack("<b", data[1:2])[0]
        scheme_code = data[2]

        # Scheme prefix table
        schemes = {
            0x00: "http://www.",
            0x01: "https://www.",
            0x02: "http://",
            0x03: "https://",
        }
        url_str = schemes.get(scheme_code, f"<scheme:{scheme_code:02x}>")

        expansions = dict((code, sfx) for sfx, code in EDDYSTONE_URL_EXPANSIONS)
        # Add single byte suffix codes
        url_chars: list[str] = []
        for b in data[3:]:
            if b in expansions:
                url_chars.append(expansions[b])
            elif 32 <= b <= 126:
                url_chars.append(chr(b))
            else:
                url_chars.append(f"<0x{b:02x}>")

        url_str += "".join(url_chars)
        return EddystoneUrlInfo(url=url_str, tx_power=tx_power)

    # Eddystone-TLM (0x20)
    if frame_type == 0x20 and len(data) >= 14:
        version = data[1]
        vbatt_mv = struct.unpack(">H", data[2:4])[0]
        temp_raw = struct.unpack(">h", data[4:6])[0]
        if temp_raw == -32768:  # 0x8000 signifies uncalibrated / not supported
            temp_c = None
        else:
            temp_c = round(temp_raw / 256.0, 2)
        adv_cnt = struct.unpack(">I", data[6:10])[0]
        sec_cnt = struct.unpack(">I", data[10:14])[0]
        return EddystoneTlmInfo(
            version=version,
            vbatt_mv=vbatt_mv,
            temp_c=temp_c,
            adv_cnt=adv_cnt,
            sec_cnt=sec_cnt,
        )

    return None


def decode_gaen_service_data(data: bytes) -> GaenInfo | None:
    """Parses Google/Apple Exposure Notification (0xFD6F) service data (16B RPI + 4B AEM)."""
    if len(data) >= 20:
        rpi = data[:16]
        aem = data[16:20]
        return GaenInfo(rpi=rpi, aem=aem)
    return None


def dissect_advertising_pdu(
    raw_pdu: bytes, chan: int = 37, rssi: int = -60, ts_usec: int = 0
) -> DissectedBleFrame:
    """Top-level entrypoint parsing a raw BLE Link Layer advertising channel PDU."""
    if len(raw_pdu) < 2:
        raise ValueError(
            f"Raw PDU must be at least 2 bytes (header + length), got {len(raw_pdu)}"
        )

    hdr0 = raw_pdu[0]
    hdr1 = raw_pdu[1]

    pdu_type_id = hdr0 & 0x0F
    tx_add = (hdr0 >> 6) & 0x01
    rx_add = (hdr0 >> 7) & 0x01

    length = hdr1 & 0x3F
    pdu_type_name = PDU_TYPE_NAMES.get(pdu_type_id, f"UNKNOWN_{pdu_type_id}")

    is_malformed = False
    error_details: str | None = None

    if len(raw_pdu) < 2 + length:
        is_malformed = True
        error_details = (
            f"Truncated PDU payload: header specifies {length} bytes, "
            f"only {len(raw_pdu) - 2} bytes present"
        )
        raw_payload = raw_pdu[2:]
    else:
        raw_payload = raw_pdu[2 : 2 + length]

    adv_a: str | None = None
    adv_a_raw: bytes | None = None
    adv_a_type: str | None = None

    scan_a: str | None = None
    scan_a_raw: bytes | None = None
    scan_a_type: str | None = None

    target_a: str | None = None
    target_a_raw: bytes | None = None
    target_a_type: str | None = None

    init_a: str | None = None
    init_a_raw: bytes | None = None
    init_a_type: str | None = None

    conn_params: ConnectionParams | None = None
    ad_data = b""

    # Demux based on PDU type
    if pdu_type_id in (PDU_TYPE_ADV_IND, PDU_TYPE_ADV_NONCONN_IND, PDU_TYPE_ADV_SCAN_IND, PDU_TYPE_SCAN_RSP):
        if len(raw_payload) >= 6:
            adv_a_raw = raw_payload[:6]
            adv_a = mac_to_str(adv_a_raw)
            adv_a_type = classify_address(adv_a_raw, is_random=bool(tx_add)).value
            ad_data = raw_payload[6:]
        else:
            is_malformed = True
            error_details = (
                (error_details + "; ") if error_details else ""
            ) + f"Payload too short for AdvA in {pdu_type_name} ({len(raw_payload)} bytes)"

    elif pdu_type_id == PDU_TYPE_SCAN_REQ:
        if len(raw_payload) >= 12:
            scan_a_raw = raw_payload[:6]
            scan_a = mac_to_str(scan_a_raw)
            scan_a_type = classify_address(scan_a_raw, is_random=bool(tx_add)).value

            adv_a_raw = raw_payload[6:12]
            adv_a = mac_to_str(adv_a_raw)
            adv_a_type = classify_address(adv_a_raw, is_random=bool(rx_add)).value
        else:
            is_malformed = True
            error_details = (
                (error_details + "; ") if error_details else ""
            ) + f"Payload too short for SCAN_REQ ({len(raw_payload)} bytes)"

    elif pdu_type_id == PDU_TYPE_ADV_DIRECT_IND:
        if len(raw_payload) >= 12:
            adv_a_raw = raw_payload[:6]
            adv_a = mac_to_str(adv_a_raw)
            adv_a_type = classify_address(adv_a_raw, is_random=bool(tx_add)).value

            target_a_raw = raw_payload[6:12]
            target_a = mac_to_str(target_a_raw)
            target_a_type = classify_address(target_a_raw, is_random=bool(rx_add)).value
        else:
            is_malformed = True
            error_details = (
                (error_details + "; ") if error_details else ""
            ) + f"Payload too short for ADV_DIRECT_IND ({len(raw_payload)} bytes)"

    elif pdu_type_id == PDU_TYPE_CONNECT_IND:
        if len(raw_payload) >= 12:
            init_a_raw = raw_payload[:6]
            init_a = mac_to_str(init_a_raw)
            init_a_type = classify_address(init_a_raw, is_random=bool(tx_add)).value

            adv_a_raw = raw_payload[6:12]
            adv_a = mac_to_str(adv_a_raw)
            adv_a_type = classify_address(adv_a_raw, is_random=bool(rx_add)).value

            if len(raw_payload) >= 34:
                lldata = raw_payload[12:34]
                try:
                    aa_conn = struct.unpack("<I", lldata[0:4])[0]
                    crc_init = lldata[4] | (lldata[5] << 8) | (lldata[6] << 16)
                    win_size = lldata[7]
                    win_offset, interval, latency, timeout = struct.unpack(
                        "<HHHH", lldata[8:16]
                    )
                    chm = lldata[16:21]
                    hop = lldata[21] & 0x1F
                    sca = (lldata[21] >> 5) & 0x07
                    conn_params = ConnectionParams(
                        aa_conn=aa_conn,
                        crc_init=crc_init,
                        win_size=win_size,
                        win_offset=win_offset,
                        interval=interval,
                        latency=latency,
                        timeout=timeout,
                        chm=chm,
                        hop=hop,
                        sca=sca,
                    )
                except Exception as ex:
                    is_malformed = True
                    error_details = (
                        (error_details + "; ") if error_details else ""
                    ) + f"Failed to unpack LLData in CONNECT_IND: {ex}"
            else:
                is_malformed = True
                error_details = (
                    (error_details + "; ") if error_details else ""
                ) + f"LLData truncated in CONNECT_IND ({len(raw_payload)} bytes)"
        else:
            is_malformed = True
            error_details = (
                (error_details + "; ") if error_details else ""
            ) + f"Payload too short for CONNECT_IND ({len(raw_payload)} bytes)"

    elif pdu_type_id == PDU_TYPE_ADV_EXT_IND:
        if len(raw_payload) >= 6:
            adv_a_raw = raw_payload[:6]
            adv_a = mac_to_str(adv_a_raw)
            adv_a_type = classify_address(adv_a_raw, is_random=bool(tx_add)).value
            ad_data = raw_payload[6:]
        else:
            ad_data = raw_payload
    else:
        ad_data = raw_payload

    # Parse AD structures
    ad_structures: list[AdStructure] = []
    flags: int | None = None
    tx_power_level: int | None = None
    complete_local_name: str | None = None
    shortened_local_name: str | None = None
    manufacturer_data: list[ManufacturerDataRecord] = []
    service_uuids_16: list[int] = []
    service_uuids_32: list[int] = []
    service_uuids_128: list[UUID] = []
    service_data: dict[str, bytes] = {}
    beacon_type: str | None = None
    beacon_info: BeaconInfo | None = None

    if ad_data:
        parsed_ads, ad_malformed, ad_err = parse_ad_structures(ad_data)
        ad_structures = parsed_ads
        if ad_malformed:
            is_malformed = True
            error_details = (
                (error_details + "; " + ad_err) if error_details else ad_err
            )

        for ad in ad_structures:
            t = ad.ad_type
            v = ad.value

            # 0x01: Flags
            if t == AD_TYPE_FLAGS and len(v) >= 1:
                flags = v[0]

            # 0x02, 0x03: 16-bit Service UUIDs
            elif t in (AD_TYPE_INCOMPLETE_16BIT_UUIDS, AD_TYPE_COMPLETE_16BIT_UUIDS):
                for off in range(0, len(v) - (len(v) % 2), 2):
                    u16 = struct.unpack("<H", v[off : off + 2])[0]
                    service_uuids_16.append(u16)
                if len(v) % 2 != 0:
                    is_malformed = True

            # 0x04, 0x05: 32-bit Service UUIDs
            elif t in (AD_TYPE_INCOMPLETE_32BIT_UUIDS, AD_TYPE_COMPLETE_32BIT_UUIDS):
                for off in range(0, len(v) - (len(v) % 4), 4):
                    u32 = struct.unpack("<I", v[off : off + 4])[0]
                    service_uuids_32.append(u32)
                if len(v) % 4 != 0:
                    is_malformed = True

            # 0x06, 0x07: 128-bit Service UUIDs
            elif t in (AD_TYPE_INCOMPLETE_128BIT_UUIDS, AD_TYPE_COMPLETE_128BIT_UUIDS):
                for off in range(0, len(v) - (len(v) % 16), 16):
                    try:
                        u128 = UUID(bytes=v[off : off + 16])
                        service_uuids_128.append(u128)
                    except Exception:
                        is_malformed = True
                if len(v) % 16 != 0:
                    is_malformed = True

            # 0x08: Shortened Local Name
            elif t == AD_TYPE_SHORTENED_LOCAL_NAME:
                shortened_local_name = decode_local_name(v)

            # 0x09: Complete Local Name
            elif t == AD_TYPE_COMPLETE_LOCAL_NAME:
                complete_local_name = decode_local_name(v)

            # 0x0A: Tx Power Level
            elif t == AD_TYPE_TX_POWER_LEVEL and len(v) >= 1:
                tx_power_level = struct.unpack("<b", v[:1])[0]

            # 0x16: Service Data 16-bit
            elif t == AD_TYPE_SERVICE_DATA_16BIT:
                if len(v) >= 2:
                    s_uuid16 = struct.unpack("<H", v[:2])[0]
                    s_payload = v[2:]
                    service_data[f"0x{s_uuid16:04X}"] = s_payload

                    # Check for Eddystone
                    if s_uuid16 == EDDYSTONE_SERVICE_UUID:
                        eddy = decode_eddystone_service_data(s_payload)
                        if eddy is not None:
                            beacon_info = eddy
                            beacon_type = eddy.beacon_type

                    # Check for GAEN
                    elif s_uuid16 == GAEN_SERVICE_UUID:
                        gaen = decode_gaen_service_data(s_payload)
                        if gaen is not None:
                            beacon_info = gaen
                            beacon_type = gaen.beacon_type
                else:
                    is_malformed = True

            # 0x20: Service Data 32-bit
            elif t == AD_TYPE_SERVICE_DATA_32BIT:
                if len(v) >= 4:
                    s_uuid32 = struct.unpack("<I", v[:4])[0]
                    service_data[f"0x{s_uuid32:08X}"] = v[4:]
                else:
                    is_malformed = True

            # 0x21: Service Data 128-bit
            elif t == AD_TYPE_SERVICE_DATA_128BIT:
                if len(v) >= 16:
                    try:
                        s_uuid128 = UUID(bytes=v[:16])
                        service_data[str(s_uuid128)] = v[16:]
                    except Exception:
                        is_malformed = True
                else:
                    is_malformed = True

            # 0xFF: Manufacturer-Specific Data
            elif t == AD_TYPE_MANUFACTURER_SPECIFIC:
                if len(v) >= 2:
                    company_id = struct.unpack("<H", v[:2])[0]
                    m_data = v[2:]
                    c_name = COMPANY_NAMES.get(company_id, f"Vendor 0x{company_id:04X}")

                    apple_msgs: list[AppleContinuityMessage] = []
                    ms_cdp: MicrosoftCdpInfo | None = None

                    if company_id == COMPANY_ID_APPLE:
                        apple_msgs, ibeacon = decode_apple_msd(m_data)
                        if ibeacon is not None:
                            beacon_info = ibeacon
                            beacon_type = ibeacon.beacon_type

                    elif company_id == COMPANY_ID_RADIUS_NETWORKS:
                        alt = decode_altbeacon_msd(company_id, m_data)
                        if alt is not None:
                            beacon_info = alt
                            beacon_type = alt.beacon_type

                    elif company_id == COMPANY_ID_MICROSOFT:
                        ms_cdp = decode_microsoft_msd(m_data)

                    mfg_record = ManufacturerDataRecord(
                        company_id=company_id,
                        company_name=c_name,
                        data=m_data,
                        apple_messages=apple_msgs,
                        microsoft_cdp=ms_cdp,
                    )
                    manufacturer_data.append(mfg_record)
                else:
                    is_malformed = True

    # Device name selection: complete local name takes precedence
    device_name = complete_local_name if complete_local_name is not None else shortened_local_name

    return DissectedBleFrame(
        pdu_type=pdu_type_name,
        pdu_type_id=pdu_type_id,
        tx_add=tx_add,
        rx_add=rx_add,
        length=length,
        adv_a=adv_a,
        adv_a_raw=adv_a_raw,
        adv_a_type=adv_a_type,
        scan_a=scan_a,
        scan_a_raw=scan_a_raw,
        scan_a_type=scan_a_type,
        target_a=target_a,
        target_a_raw=target_a_raw,
        target_a_type=target_a_type,
        init_a=init_a,
        init_a_raw=init_a_raw,
        init_a_type=init_a_type,
        device_name=device_name,
        complete_local_name=complete_local_name,
        shortened_local_name=shortened_local_name,
        flags=flags,
        tx_power_level=tx_power_level,
        manufacturer_data=manufacturer_data,
        service_uuids_16=service_uuids_16,
        service_uuids_32=service_uuids_32,
        service_uuids_128=service_uuids_128,
        service_data=service_data,
        beacon_type=beacon_type,
        beacon_info=beacon_info,
        conn_params=conn_params,
        channel=chan,
        rssi=rssi,
        timestamp_usec=ts_usec,
        raw_pdu=raw_pdu,
        raw_payload=raw_payload,
        ad_structures=ad_structures,
        is_malformed=is_malformed,
        error_details=error_details,
    )


def dissect_packet(pkt: Any) -> DissectedBleFrame:
    """Convenience entrypoint unpacking from Sniffle PacketMessage or compatible object."""
    body = getattr(pkt, "body", b"")
    chan = getattr(pkt, "chan", 37)
    rssi = getattr(pkt, "rssi", -60)
    ts = getattr(pkt, "ts", 0)
    if len(body) < 2:
        return DissectedBleFrame(
            pdu_type="MALFORMED",
            pdu_type_id=0xFF,
            tx_add=0,
            rx_add=0,
            length=len(body),
            channel=chan,
            rssi=rssi,
            timestamp_usec=ts,
            raw_pdu=body,
            is_malformed=True,
            error_details="Truncated Link Layer frame (< 2 bytes)",
        )
    return dissect_advertising_pdu(raw_pdu=body, chan=chan, rssi=rssi, ts_usec=ts)
