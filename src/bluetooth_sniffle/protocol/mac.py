"""Palindromic MAC Address Generator and Utilities (PoPETs 2025-0103).

Provides endianness-invariant palindromic MAC address synthesis and classification
for BLE tracking leakage detection. Palindromic MAC addresses (B0:B1:B2:B2:B1:B0)
ensure that both radio byte order (Little-Endian) and network byte order (Big-Endian)
produce identical hexadecimal serializations, eliminating false positives in
exfiltration stream tracing.
"""

from __future__ import annotations

import secrets


def str_to_mac(s: str) -> bytes:
    """Converts a hexadecimal MAC address string into 6 raw bytes.

    Accepts formats such as 'C0:11:22:22:11:C0', 'c0-11-22-22-11-c0',
    or 'c011222211c0'.

    Args:
        s: Hexadecimal string representing a 6-byte MAC address.

    Returns:
        6 raw bytes representing the MAC address.

    Raises:
        ValueError: If the string does not represent exactly 6 hexadecimal bytes.
    """
    cleaned = s.replace(":", "").replace("-", "").strip()
    if len(cleaned) != 12:
        raise ValueError(
            f"Invalid MAC address string '{s}': expected 12 hexadecimal characters, got {len(cleaned)}"
        )
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal in MAC address string '{s}': {e}") from e
    return raw


def mac_to_str(mac: bytes) -> str:
    """Converts 6 raw MAC bytes into standard uppercase colon-delimited string.

    Args:
        mac: 6 raw bytes.

    Returns:
        Formatted string, e.g. 'C0:11:22:22:11:C0'.

    Raises:
        ValueError: If mac does not contain exactly 6 bytes.
    """
    if len(mac) != 6:
        raise ValueError(f"MAC address must be exactly 6 bytes, got {len(mac)}")
    return ":".join(f"{b:02X}" for b in mac)


def is_palindromic_mac(mac: bytes | str) -> bool:
    """Checks whether a MAC address is palindromic (endianness-invariant).

    A MAC address [B0, B1, B2, B3, B4, B5] is palindromic if:
    B0 == B5, B1 == B4, and B2 == B3.

    Args:
        mac: 6-byte MAC address as bytes or formatted string.

    Returns:
        True if the address is palindromic, False otherwise.
    """
    if isinstance(mac, str):
        try:
            mac_bytes = str_to_mac(mac)
        except ValueError:
            return False
    elif isinstance(mac, (bytes, bytearray)):
        if len(mac) != 6:
            return False
        mac_bytes = bytes(mac)
    else:
        return False

    return (
        mac_bytes[0] == mac_bytes[5]
        and mac_bytes[1] == mac_bytes[4]
        and mac_bytes[2] == mac_bytes[3]
    )


def generate_palindromic_mac(
    address_type: str = "static", seed: bytes | str | None = None
) -> bytes:
    """Generates a 6-byte palindromic MAC address compliant with Bluetooth Core Spec.

    Mathematical symmetry: B0 == B5, B1 == B4, B2 == B3.
    Configures the address classification bits on B0 and B5:
      - 'static': Random Static Address (top 2 bits: 11b)
      - 'nrpa': Non-Resolvable Private Address (top 2 bits: 00b)
      - 'rpa': Resolvable Private Address (top 2 bits: 01b)
      - 'public': Public Address (bit 0 = 0 for IEEE 802 unicast, top 2 bits 10b)

    Args:
        address_type: One of 'static', 'nrpa', 'rpa', or 'public' (case-insensitive).
        seed: Optional minimum 3-byte seed for deterministic address generation.

    Returns:
        6-byte palindromic MAC address.

    Raises:
        ValueError: If address_type is unrecognized or seed is shorter than 3 bytes.
    """
    addr_type = address_type.strip().lower()
    valid_types = ("static", "nrpa", "rpa", "public")
    if addr_type not in valid_types:
        raise ValueError(
            f"Invalid address_type '{address_type}'. Must be one of {valid_types}"
        )

    if seed is not None:
        if isinstance(seed, str):
            seed_bytes = bytes.fromhex(seed.replace(":", "").replace("-", ""))
        else:
            seed_bytes = bytes(seed)
        if len(seed_bytes) < 3:
            raise ValueError(
                f"Seed must contain at least 3 bytes, got {len(seed_bytes)}"
            )
        b0, b1, b2 = seed_bytes[0], seed_bytes[1], seed_bytes[2]
    else:
        b0 = secrets.randbelow(256)
        b1 = secrets.randbelow(256)
        b2 = secrets.randbelow(256)

    if addr_type == "static":
        b0 = (b0 & 0x3F) | 0xC0  # Top two bits: 11b
    elif addr_type == "nrpa":
        b0 = b0 & 0x3F  # Top two bits: 00b
        # NRPA address cannot have all 0 bits
        if b0 == 0 and b1 == 0 and b2 == 0:
            b2 = 0x01
    elif addr_type == "rpa":
        b0 = (b0 & 0x3F) | 0x40  # Top two bits: 01b
    elif addr_type == "public":
        # IEEE 802 unicast requires bit 0 = 0; top 2 bits set to 10b for disambiguation
        b0 = (b0 & 0x3E) | 0x80

    return bytes([b0, b1, b2, b2, b1, b0])


def classify_mac_address(mac: bytes | str, is_random: bool | None = None) -> str:
    """Classifies a Bluetooth MAC address per Bluetooth Core Spec (Vol 6, Part B, 1.3.2).

    Determines whether the address is 'Static', 'NRPA', 'RPA', or 'Public'.

    In Bluetooth Low Energy, addresses are transmitted Little-Endian (B0 over the air
    first, B5 last). For random addresses, the address type is determined by the
    most significant 2 bits of B5 (mac[5] >> 6):
      - 11b: Random Static
      - 00b: Non-Resolvable Private Address (NRPA)
      - 01b: Resolvable Private Address (RPA)
      - 10b: Reserved for Future Use (RFU) / Public

    Args:
        mac: 6-byte MAC address as bytes or formatted string.
        is_random: Optional boolean indicating whether the PDU TxAdd/RxAdd bit was set.
                   If False, always classifies as 'Public'.

    Returns:
        One of 'Static', 'NRPA', 'RPA', or 'Public'.

    Raises:
        ValueError: If mac is not 6 bytes.
    """
    if isinstance(mac, str):
        mac_bytes = str_to_mac(mac)
    else:
        if len(mac) != 6:
            raise ValueError(f"MAC address must be 6 bytes, got {len(mac)}")
        mac_bytes = bytes(mac)

    if is_random is False:
        return "Public"

    top2 = mac_bytes[5] >> 6

    if is_random is True:
        if top2 == 0b11:
            return "Static"
        if top2 == 0b00:
            return "NRPA"
        if top2 == 0b01:
            return "RPA"
        return "RFU"

    # When is_random is None, infer from bit patterns:
    if top2 == 0b11:
        return "Static"
    if top2 == 0b00:
        return "NRPA"
    if top2 == 0b01:
        return "RPA"
    return "Public"
