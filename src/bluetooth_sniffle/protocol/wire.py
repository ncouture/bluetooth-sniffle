"""Sniffle wire protocol serialization, Base64 line framing, and message decoding.

Implements the UART framing, command opcodes, and message structures used by
Sniffle firmware running on TI CC2652 / CC1352 radios.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from struct import pack, unpack
from typing import Any

# -----------------------------------------------------------------------------
# Host-to-Dongle Command Opcodes (from fw/CommandTask.h)
# -----------------------------------------------------------------------------
COMMAND_SETCHANAAPHY: int = 0x10  # Set channel, access address, phy, crci
COMMAND_PAUSEDONE: int = 0x11     # Pause sniffer when followed connection terminates
COMMAND_RSSIFILT: int = 0x12      # Minimum RSSI filter
COMMAND_MACFILT: int = 0x13       # Target MAC address filter
COMMAND_ADVHOP: int = 0x14        # Hop across primary advertising channels (37, 38, 39)
COMMAND_FOLLOW: int = 0x15        # Follow connections upon observing CONNECT_IND
COMMAND_AUXADV: int = 0x16        # Follow auxiliary pointers in BT5 extended advertising
COMMAND_RESET: int = 0x17         # MCU soft reset
COMMAND_MARKER: int = 0x18        # Sync marker request (dongle returns MarkerMessage)
COMMAND_TRANSMIT: int = 0x19      # Transmit LL PDU during connection
COMMAND_CONNECT: int = 0x1A       # Initiate connection with CONNECT_IND
COMMAND_SETADDR: int = 0x1B       # Set local MAC address and random flag
COMMAND_ADVERTISE: int = 0x1C     # Broadcast legacy BLE advertising frames
COMMAND_ADVINTRVL: int = 0x1D     # Set advertising interval (milliseconds)
COMMAND_SETIRK: int = 0x1E        # Set Identity Resolving Key (IRK)
COMMAND_INSTAHOP: int = 0x1F      # Instant hop at connection event close
COMMAND_SETMAP: int = 0x20        # Override channel map
COMMAND_INTVL_PRELOAD: int = 0x21 # Preload connection interval updates
COMMAND_SCAN: int = 0x22          # Enter active scanning mode (sends SCAN_REQ)
COMMAND_PHY_PRELOAD: int = 0x23   # Preload PHY mode updates
COMMAND_VERSION: int = 0x24       # Request firmware version report
COMMAND_ADV_EXT: int = 0x25       # Broadcast BT5 extended advertising frames
COMMAND_CRC_VALID: int = 0x26     # Validate CRC (discard or capture CRC-failed frames)
COMMAND_TX_POWER: int = 0x27      # Set radio transmission output power (dBm)

# -----------------------------------------------------------------------------
# Dongle-to-Host Response Message Types (from fw/messenger.h)
# -----------------------------------------------------------------------------
MESSAGE_BLEFRAME: int = 0x10  # Captured radio packet
MESSAGE_DEBUG: int = 0x11     # Firmware debug string
MESSAGE_MARKER: int = 0x12    # Marker echo with microsecond timestamp
MESSAGE_STATE: int = 0x13     # Sniffer operational state change
MESSAGE_MEASURE: int = 0x14   # Measurement telemetry / version report

# -----------------------------------------------------------------------------
# Sniffer Operational States (from fw/messenger.h)
# -----------------------------------------------------------------------------
STATE_STATIC: int = 0
STATE_ADVERT_SEEK: int = 1
STATE_ADVERT_HOP: int = 2
STATE_DATA: int = 3
STATE_PAUSED: int = 4
STATE_INITIATING: int = 5
STATE_CENTRAL: int = 6
STATE_PERIPHERAL: int = 7
STATE_ADVERTISING: int = 8
STATE_SCANNING: int = 9
STATE_ADVERTISING_EXT: int = 10

# -----------------------------------------------------------------------------
# Measurement Telemetry Subtypes (from fw/messenger.h)
# -----------------------------------------------------------------------------
MEASUREMENT_INTERVAL: int = 0
MEASUREMENT_CHANMAP: int = 1
MEASUREMENT_ADVHOP: int = 2
MEASUREMENT_WINOFFSET: int = 3
MEASUREMENT_DELTAINSTANT: int = 4
MEASUREMENT_VERSION: int = 5

# -----------------------------------------------------------------------------
# PHY Modes
# -----------------------------------------------------------------------------
PHY_1M: int = 0
PHY_2M: int = 1
PHY_CODED_S8: int = 2
PHY_CODED_S2: int = 3

# Standard BLE Advertising Access Address and CRC Init
BLE_ADV_AA: int = 0x8E89BED6
BLE_ADV_CRC_INIT: int = 0x555555


# -----------------------------------------------------------------------------
# Wire Framing Functions
# -----------------------------------------------------------------------------
def encode_cmd(cmd_bytes: Sequence[int] | bytes) -> bytes:
    """Encode a command byte sequence into a Sniffle Base64+CRLF line.

    The first byte (b0) represents the word count (number of 4-byte Base64 chunks).
    Calculated as: b0 = (len(cmd_bytes) + 3) // 3.

    Args:
        cmd_bytes: Byte sequence containing opcode and arguments.

    Returns:
        Base64 ASCII encoded wire bytes terminated with b'\\r\\n'.
    """
    raw_bytes = bytes(cmd_bytes)
    b0 = (len(raw_bytes) + 3) // 3
    payload = bytes([b0, *raw_bytes])
    return base64.b64encode(payload) + b"\r\n"


def decode_cmd(raw_line: bytes) -> tuple[int, int, bytes]:
    """Decode a Sniffle host-to-dongle Base64+CRLF line into (b0, opcode, args).

    Args:
        raw_line: Raw ASCII line sent to the dongle.

    Returns:
        tuple (b0: int, opcode: int, args: bytes)

    Raises:
        ValueError: If line is too short, malformed Base64, or missing headers.
    """
    stripped = raw_line.strip()
    if not stripped:
        raise ValueError("Cannot decode empty command line")

    try:
        data = base64.b64decode(stripped)
    except Exception as exc:
        raise ValueError(f"Malformed Base64 line: {raw_line!r}") from exc

    if len(data) < 2:
        raise ValueError(f"Decoded command line too short ({len(data)} bytes, expected >= 2)")

    b0 = data[0]
    opcode = data[1]
    args = data[2:]
    return b0, opcode, args


def decode_msg(raw_line: bytes) -> tuple[int, int, bytes]:
    """Decode a Sniffle Base64+CRLF line into (word_cnt, msg_type, msg_body).

    Args:
        raw_line: Raw ASCII line received from the dongle.

    Returns:
        tuple (word_cnt: int, msg_type: int, msg_body: bytes)

    Raises:
        ValueError: If line is too short, malformed Base64, or missing headers.
    """
    stripped = raw_line.strip()
    if not stripped:
        raise ValueError("Cannot decode empty wire line")

    try:
        data = base64.b64decode(stripped)
    except Exception as exc:
        raise ValueError(f"Malformed Base64 line: {raw_line!r}") from exc

    if len(data) < 2:
        raise ValueError(f"Decoded wire line too short ({len(data)} bytes, expected >= 2)")

    word_cnt = data[0]
    msg_type = data[1]
    msg_body = data[2:]
    return word_cnt, msg_type, msg_body


def encode_msg(msg_type: int, msg_body: bytes = b"") -> bytes:
    """Encode a dongle-to-host message into a Sniffle Base64+CRLF line.

    Used by mock hardware and simulation fixtures to emit valid wire frames.
    Calculates word count including b0 and msg_type prefix:
    word_cnt = (len(msg_body) + 4) // 3.

    Args:
        msg_type: Message type identifier (e.g. MESSAGE_BLEFRAME).
        msg_body: Binary message body.

    Returns:
        Base64 ASCII encoded wire bytes terminated with b'\\r\\n'.
    """
    total_len = 2 + len(msg_body)
    word_cnt = (total_len + 2) // 3
    payload = bytes([word_cnt, msg_type]) + msg_body
    return base64.b64encode(payload) + b"\r\n"


# -----------------------------------------------------------------------------
# Typed Message Classes
# -----------------------------------------------------------------------------
@dataclass
class PacketMessage:
    """Decoded BLE radio packet received from Sniffle hardware (MESSAGE_BLEFRAME).

    Unpacks the 10-byte hardware header:
    - ts: 32-bit unsigned microsecond timestamp (LE)
    - l: 16-bit uint16 (LE): bit 15 = dir, bit 14 = crc_err, bits 13..0 = body length
    - event: 16-bit uint16 (LE) connection event counter
    - rssi: 8-bit signed int8 dBm
    - chan: RF channel (bits 5..0) and PHY mode (bits 7..6)
    - body: Link Layer PDU bytes
    """

    ts: int
    pkt_dir: int
    crc_err: bool
    event: int
    rssi: int
    chan: int
    phy: int
    body: bytes
    raw: bytes

    def __init__(self, raw_msg: bytes) -> None:
        """Parse raw PacketMessage body bytes (excluding msg_type)."""
        if len(raw_msg) < 10:
            raise ValueError(
                f"PacketMessage body too short ({len(raw_msg)} bytes, expected >= 10)"
            )
        self.raw = raw_msg
        ts, l_field, event, rssi, chan_phy = unpack("<LHHbB", raw_msg[:10])
        self.ts = ts
        self.pkt_dir = (l_field >> 15) & 1
        self.crc_err = bool(l_field & 0x4000)
        self.event = event
        self.rssi = rssi
        self.chan = chan_phy & 0x3F
        self.phy = (chan_phy >> 6) & 0x03
        self.body = raw_msg[10:]

    @property
    def direction(self) -> int:
        """Alias for pkt_dir: 0 for Central->Peripheral, 1 for Peripheral->Central."""
        return self.pkt_dir

    @classmethod
    def pack(
        cls,
        body: bytes,
        ts: int = 0,
        chan: int = 37,
        rssi: int = -60,
        phy: int = PHY_1M,
        event: int = 0,
        crc_err: bool = False,
        direction: int = 0,
    ) -> bytes:
        """Pack fields into raw 10-byte header + body bytes for MESSAGE_BLEFRAME."""
        l_field = len(body) & 0x3FFF
        if crc_err:
            l_field |= 0x4000
        if direction:
            l_field |= 0x8000
        chan_phy = (chan & 0x3F) | ((phy & 0x03) << 6)
        hdr = pack("<LHHbB", ts & 0xFFFFFFFF, l_field, event & 0xFFFF, rssi, chan_phy)
        return hdr + body


@dataclass
class MarkerMessage:
    """Echoed sync marker message from Sniffle hardware (MESSAGE_MARKER)."""

    ts: int
    marker_data: bytes

    def __init__(self, raw_msg: bytes) -> None:
        if len(raw_msg) < 4:
            raise ValueError(
                f"MarkerMessage body too short ({len(raw_msg)} bytes, expected >= 4)"
            )
        self.ts = unpack("<L", raw_msg[:4])[0]
        self.marker_data = raw_msg[4:]

    @classmethod
    def pack(cls, marker_data: bytes, ts: int = 0) -> bytes:
        """Pack marker message body."""
        return pack("<L", ts & 0xFFFFFFFF) + marker_data


@dataclass
class StateMessage:
    """Sniffer state transition notification from Sniffle hardware (MESSAGE_STATE)."""

    state: int

    def __init__(self, raw_msg: bytes) -> None:
        if len(raw_msg) < 1:
            raise ValueError("StateMessage body too short (expected >= 1 byte)")
        self.state = raw_msg[0]

    @classmethod
    def pack(cls, state: int) -> bytes:
        """Pack state message body."""
        return bytes([state & 0xFF])


@dataclass
class MeasurementMessage:
    """Measurement telemetry or version report from Sniffle hardware (MESSAGE_MEASURE)."""

    length: int
    measure_type: int
    data: bytes
    version: tuple[int, int, int, int] | None = None

    def __init__(self, raw_msg: bytes) -> None:
        if len(raw_msg) < 2:
            raise ValueError(
                f"MeasurementMessage body too short ({len(raw_msg)} bytes, expected >= 2)"
            )
        self.length = raw_msg[0]
        self.measure_type = raw_msg[1]
        self.data = raw_msg[2 : 2 + self.length]
        if self.measure_type == MEASUREMENT_VERSION and len(self.data) >= 4:
            self.version = unpack("<BBBB", self.data[:4])
        else:
            self.version = None

    @classmethod
    def pack(cls, measure_type: int, data: bytes) -> bytes:
        """Pack measurement message body."""
        return bytes([len(data) & 0xFF, measure_type & 0xFF]) + data

    @classmethod
    def pack_version(cls, major: int = 1, minor: int = 8, revision: int = 0, api_level: int = 1) -> bytes:
        """Pack standard version measurement payload."""
        ver_bytes = pack("<BBBB", major, minor, revision, api_level)
        return cls.pack(MEASUREMENT_VERSION, ver_bytes)


@dataclass
class DebugMessage:
    """Debug text output from firmware (MESSAGE_DEBUG)."""

    text: str

    def __init__(self, raw_msg: bytes) -> None:
        self.text = raw_msg.decode("latin-1", errors="replace")

    @classmethod
    def pack(cls, text: str) -> bytes:
        """Pack debug message body."""
        return text.encode("latin-1", errors="replace")


def parse_sniffle_message(raw_line: bytes) -> tuple[int, Any]:
    """Parse a single Base64+CRLF wire line into (msg_type, typed_message).

    Args:
        raw_line: Raw ASCII line.

    Returns:
        tuple (msg_type: int, message: PacketMessage | MarkerMessage | StateMessage
               | MeasurementMessage | DebugMessage | bytes)
    """
    _, msg_type, msg_body = decode_msg(raw_line)

    if msg_type == MESSAGE_BLEFRAME:
        return msg_type, PacketMessage(msg_body)
    if msg_type == MESSAGE_MARKER:
        return msg_type, MarkerMessage(msg_body)
    if msg_type == MESSAGE_STATE:
        return msg_type, StateMessage(msg_body)
    if msg_type == MESSAGE_MEASURE:
        return msg_type, MeasurementMessage(msg_body)
    if msg_type == MESSAGE_DEBUG:
        return msg_type, DebugMessage(msg_body)
    return msg_type, msg_body
