"""Bluetooth Low Energy Active Probing Frame Encoders (PoPETs 2025-0103).

Provides synthesis of Link Layer active scan request (SCAN_REQ) and scan response (SCAN_RSP)
PDUs to elicit device names and secondary service UUIDs from nearby peripherals and
tracking SDK targets.
"""

from __future__ import annotations

import struct
from uuid import UUID

from bluetooth_sniffle.protocol.mac import str_to_mac

# BLE Link Layer PDU Types
PDU_TYPE_SCAN_REQ = 0x03
PDU_TYPE_SCAN_RSP = 0x04

# AD Structure Types
AD_TYPE_COMPLETE_16BIT_UUIDS = 0x03
AD_TYPE_COMPLETE_128BIT_UUIDS = 0x07
AD_TYPE_COMPLETE_LOCAL_NAME = 0x09
AD_TYPE_SHORTENED_LOCAL_NAME = 0x08


def build_scan_req(
    scan_a: bytes | str,
    adv_a: bytes | str,
    scan_a_random: bool = True,
    adv_a_random: bool = True,
) -> bytes:
    """Constructs a 14-byte BLE Link Layer SCAN_REQ PDU.

    Frame Format:
      - Header Byte 0: [PDU Type (4b = 0x03), RFU (1b = 0), ChSel (1b = 0), TxAdd (1b), RxAdd (1b)]
      - Header Byte 1: Payload Length (8b = 12 bytes: 6B ScanA + 6B AdvA)
      - Payload:       ScanA (6 bytes LE) + AdvA (6 bytes LE)

    Args:
        scan_a: Scanner MAC address as 6 raw bytes or hex string.
        adv_a: Target advertiser MAC address as 6 raw bytes or hex string.
        scan_a_random: True if ScanA is a random address (TxAdd = 1), False if public (TxAdd = 0).
        adv_a_random: True if AdvA is a random address (RxAdd = 1), False if public (RxAdd = 0).

    Returns:
        14-byte raw SCAN_REQ PDU.

    Raises:
        ValueError: If MAC addresses are invalid or not 6 bytes.
    """
    if isinstance(scan_a, str):
        scan_a_bytes = str_to_mac(scan_a)
    else:
        if len(scan_a) != 6:
            raise ValueError(f"ScanA must be 6 bytes, got {len(scan_a)}")
        scan_a_bytes = bytes(scan_a)

    if isinstance(adv_a, str):
        adv_a_bytes = str_to_mac(adv_a)
    else:
        if len(adv_a) != 6:
            raise ValueError(f"AdvA must be 6 bytes, got {len(adv_a)}")
        adv_a_bytes = bytes(adv_a)

    # Header byte 0: Type (bits 0..3), TxAdd (bit 6), RxAdd (bit 7)
    tx_add = 0x40 if scan_a_random else 0x00
    rx_add = 0x80 if adv_a_random else 0x00
    hdr0 = PDU_TYPE_SCAN_REQ | tx_add | rx_add

    # Header byte 1: Payload Length = 12 bytes
    hdr1 = 12

    pdu = bytes([hdr0, hdr1]) + scan_a_bytes + adv_a_bytes
    if len(pdu) != 14:
        raise ValueError(f"Unexpected SCAN_REQ PDU length: {len(pdu)} (expected 14)")
    return pdu


def build_scan_rsp(
    adv_a: bytes | str,
    local_name: str | None = None,
    service_uuids_16: list[int | str | bytes] | None = None,
    service_uuids_128: list[UUID | str | bytes] | None = None,
    adv_a_random: bool = True,
    raw_ad_data: bytes = b"",
) -> bytes:
    """Constructs a BLE Link Layer SCAN_RSP PDU.

    Frame Format:
      - Header Byte 0: [PDU Type (4b = 0x04), RFU (1b = 0), ChSel (1b = 0), TxAdd (1b), RxAdd (1b = 0)]
      - Header Byte 1: Payload Length (8b = 6 bytes AdvA + len(ScanRspData))
      - Payload:       AdvA (6 bytes LE) + ScanRspData (0..31 bytes AD structures)

    Args:
        adv_a: Advertiser MAC address as 6 raw bytes or hex string.
        local_name: Optional Complete Local Name string (AD type 0x09).
        service_uuids_16: Optional list of 16-bit Service UUIDs (integers or hex strings).
        service_uuids_128: Optional list of 128-bit Service UUIDs (UUID objects, strings, or bytes).
        adv_a_random: True if AdvA is a random address (TxAdd = 1), False if public (TxAdd = 0).
        raw_ad_data: Optional additional raw AD data to append.

    Returns:
        Raw SCAN_RSP PDU (8 to 39 bytes).

    Raises:
        ValueError: If MAC address is invalid or ScanRspData exceeds 31 bytes.
    """
    if isinstance(adv_a, str):
        adv_a_bytes = str_to_mac(adv_a)
    else:
        if len(adv_a) != 6:
            raise ValueError(f"AdvA must be 6 bytes, got {len(adv_a)}")
        adv_a_bytes = bytes(adv_a)

    ad_payload = bytearray()

    if local_name is not None:
        name_bytes = local_name.encode("utf-8")
        ad_payload += bytes([len(name_bytes) + 1, AD_TYPE_COMPLETE_LOCAL_NAME]) + name_bytes

    if service_uuids_16:
        uuid16_bytes = bytearray()
        for u in service_uuids_16:
            if isinstance(u, int):
                uuid16_bytes += struct.pack("<H", u)
            elif isinstance(u, str):
                val = int(u.replace("0x", "").replace(":", ""), 16)
                uuid16_bytes += struct.pack("<H", val)
            elif isinstance(u, (bytes, bytearray)):
                if len(u) != 2:
                    raise ValueError(f"16-bit UUID must be 2 bytes, got {len(u)}")
                uuid16_bytes += u
            else:
                raise TypeError(f"Unsupported 16-bit UUID type: {type(u)}")
        ad_payload += bytes([len(uuid16_bytes) + 1, AD_TYPE_COMPLETE_16BIT_UUIDS]) + uuid16_bytes

    if service_uuids_128:
        uuid128_bytes = bytearray()
        for u in service_uuids_128:
            if isinstance(u, UUID):
                uuid128_bytes += u.bytes
            elif isinstance(u, str):
                uuid128_bytes += UUID(u).bytes
            elif isinstance(u, (bytes, bytearray)):
                if len(u) != 16:
                    raise ValueError(f"128-bit UUID must be 16 bytes, got {len(u)}")
                uuid128_bytes += u
            else:
                raise TypeError(f"Unsupported 128-bit UUID type: {type(u)}")
        ad_payload += bytes([len(uuid128_bytes) + 1, AD_TYPE_COMPLETE_128BIT_UUIDS]) + uuid128_bytes

    if raw_ad_data:
        ad_payload += raw_ad_data

    if len(ad_payload) > 31:
        raise ValueError(
            f"Scan response advertising data length ({len(ad_payload)} bytes) exceeds standard 31-byte limit"
        )

    tx_add = 0x40 if adv_a_random else 0x00
    hdr0 = PDU_TYPE_SCAN_RSP | tx_add
    payload_len = 6 + len(ad_payload)
    hdr1 = payload_len

    return bytes([hdr0, hdr1]) + adv_a_bytes + bytes(ad_payload)
