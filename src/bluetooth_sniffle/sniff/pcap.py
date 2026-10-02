"""Libpcap writer and reader for Bluetooth Low Energy Link Layer with Pseudo-Header (DLT 256).

Format specification: DLT_BLUETOOTH_LE_LL_WITH_PHDR (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256).
Bit-for-bit compatible with Wireshark, tshark, crackle, and Sniffle PcapBleReader.
"""

from __future__ import annotations

import io
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator

# PCAP Constants
PCAP_MAGIC_USEC: int = 0xA1B2C3D4  # Standard microsecond PCAP magic
PCAP_VERSION_MAJOR: int = 2
PCAP_VERSION_MINOR: int = 4
PCAP_SNAPLEN: int = 65535
DLT_BLUETOOTH_LE_LL_WITH_PHDR: int = 256  # 0x0100

GLOBAL_HEADER_FORMAT: str = "<IHHIIII"  # 24 bytes
PACKET_HEADER_FORMAT: str = "<IIII"    # 16 bytes
PSEUDO_HEADER_FORMAT: str = "<BbbBIH"  # 10 bytes

BLE_ADV_AA: int = 0x8E89BED6
BLE_ADV_CRC_INIT_REV: int = 0xAAAAAA   # rbit24(0x555555)

# 256-entry BLE CRC lookup table (from Sniffle / Dominic Spill)
BLE_CRC_LUT: tuple[int, ...] = (
    0x000000, 0x01b4c0, 0x036980, 0x02dd40, 0x06d300, 0x0767c0, 0x05ba80, 0x040e40,
    0x0da600, 0x0c12c0, 0x0ecf80, 0x0f7b40, 0x0b7500, 0x0ac1c0, 0x081c80, 0x09a840,
    0x1b4c00, 0x1af8c0, 0x182580, 0x199140, 0x1d9f00, 0x1c2bc0, 0x1ef680, 0x1f4240,
    0x16ea00, 0x175ec0, 0x158380, 0x143740, 0x103900, 0x118dc0, 0x135080, 0x12e440,
    0x369800, 0x372cc0, 0x35f180, 0x344540, 0x304b00, 0x31ffc0, 0x332280, 0x329640,
    0x3b3e00, 0x3a8ac0, 0x385780, 0x39e340, 0x3ded00, 0x3c59c0, 0x3e8480, 0x3f3040,
    0x2dd400, 0x2c60c0, 0x2ebd80, 0x2f0940, 0x2b0700, 0x2ab3c0, 0x286e80, 0x29da40,
    0x207200, 0x21c6c0, 0x231b80, 0x22af40, 0x26a100, 0x2715c0, 0x25c880, 0x247c40,
    0x6d3000, 0x6c84c0, 0x6e5980, 0x6fed40, 0x6be300, 0x6a57c0, 0x688a80, 0x693e40,
    0x609600, 0x6122c0, 0x63ff80, 0x624b40, 0x664500, 0x67f1c0, 0x652c80, 0x649840,
    0x767c00, 0x77c8c0, 0x751580, 0x74a140, 0x70af00, 0x711bc0, 0x73c680, 0x727240,
    0x7bda00, 0x7a6ec0, 0x78b380, 0x790740, 0x7d0900, 0x7cbdc0, 0x7e6080, 0x7fd440,
    0x5ba800, 0x5a1cc0, 0x58c180, 0x597540, 0x5d7b00, 0x5ccfc0, 0x5e1280, 0x5fa640,
    0x560e00, 0x57bac0, 0x556780, 0x54d340, 0x50dd00, 0x5169c0, 0x53b480, 0x520040,
    0x40e400, 0x4150c0, 0x438d80, 0x423940, 0x463700, 0x4783c0, 0x455e80, 0x44ea40,
    0x4d4200, 0x4cf6c0, 0x4e2b80, 0x4f9f40, 0x4b9100, 0x4a25c0, 0x48f880, 0x494c40,
    0xda6000, 0xdbd4c0, 0xd90980, 0xd8bd40, 0xdcb300, 0xdd07c0, 0xdfda80, 0xde6e40,
    0xd7c600, 0xd672c0, 0xd4af80, 0xd51b40, 0xd11500, 0xd0a1c0, 0xd27c80, 0xd3c840,
    0xc12c00, 0xc098c0, 0xc24580, 0xc3f140, 0xc7ff00, 0xc64bc0, 0xc49680, 0xc52240,
    0xcc8a00, 0xcd3ec0, 0xcfe380, 0xce5740, 0xca5900, 0xcbedc0, 0xc93080, 0xc88440,
    0xecf800, 0xed4cc0, 0xef9180, 0xee2540, 0xea2b00, 0xeb9fc0, 0xe94280, 0xe8f640,
    0xe15e00, 0xe0eac0, 0xe23780, 0xe38340, 0xe78d00, 0xe639c0, 0xe4e480, 0xe55040,
    0xf7b400, 0xf600c0, 0xf4dd80, 0xf56940, 0xf16700, 0xf0d3c0, 0xf20e80, 0xf3ba40,
    0xfa1200, 0xfba6c0, 0xf97b80, 0xf8cf40, 0xfcc100, 0xfd75c0, 0xffa880, 0xfe1c40,
    0xb75000, 0xb6e4c0, 0xb43980, 0xb58d40, 0xb18300, 0xb037c0, 0xb2ea80, 0xb35e40,
    0xbaf600, 0xbb42c0, 0xb99f80, 0xb82b40, 0xbc2500, 0xbd91c0, 0xbf4c80, 0xbef840,
    0xac1c00, 0xada8c0, 0xaf7580, 0xaec140, 0xaacf00, 0xab7bc0, 0xa9a680, 0xa81240,
    0xa1ba00, 0xa00ec0, 0xa2d380, 0xa36740, 0xa76900, 0xa6ddc0, 0xa40080, 0xa5b440,
    0x81c800, 0x807cc0, 0x82a180, 0x831540, 0x871b00, 0x86afc0, 0x847280, 0x85c640,
    0x8c6e00, 0x8ddac0, 0x8f0780, 0x8eb340, 0x8abd00, 0x8b09c0, 0x89d480, 0x886040,
    0x9a8400, 0x9b30c0, 0x99ed80, 0x985940, 0x9c5700, 0x9de3c0, 0x9f3e80, 0x9e8a40,
    0x972200, 0x9696c0, 0x944b80, 0x95ff40, 0x91f100, 0x9045c0, 0x929880, 0x932c40,
)


def crc_ble_reverse(crc_init_reverse: int, data: bytes) -> int:
    """Compute 24-bit reversed BLE CRC over data bytes."""
    state = crc_init_reverse & 0xFFFFFF
    for b in data:
        key = b ^ (state & 0xFF)
        state = (state >> 8) ^ BLE_CRC_LUT[key]
    return state


def ble_to_rf_chan(chan: int) -> int:
    """Convert BLE logical channel (0-39) to 2.4 GHz RF physical channel index (0-39)."""
    if chan == 37:
        return 0
    if chan == 38:
        return 12
    if chan == 39:
        return 39
    if 0 <= chan <= 10:
        return chan + 1
    if 11 <= chan <= 36:
        return chan + 2
    return chan & 0x3F


def rf_to_ble_chan(rf_chan: int) -> int:
    """Convert 2.4 GHz RF physical channel index (0-39) to BLE logical channel (0-39)."""
    if rf_chan == 0:
        return 37
    if rf_chan == 12:
        return 38
    if rf_chan == 39:
        return 39
    if 1 <= rf_chan <= 11:
        return rf_chan - 1
    if 13 <= rf_chan <= 38:
        return rf_chan - 2
    return rf_chan & 0x3F


def normalize_rssi(rssi: int | float) -> int:
    """Normalize and clamp RSSI to signed 8-bit integer [-128, 127]."""
    try:
        val = int(round(float(rssi)))
    except (ValueError, TypeError):
        return -128
    if 128 <= val <= 255:
        val -= 256
    return max(-128, min(127, val))


def build_pseudo_header_flags(
    crc_err: bool = False,
    phy: int = 0,
    pdu_type: int = 0,
    aux_type: int = 0,
    dewhitened: bool = True,
    sigpower_valid: bool = True,
    ref_aa_valid: bool = True,
) -> int:
    """Build 16-bit pseudo-header flags field for LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR."""
    flags = 0
    if dewhitened:
        flags |= 0x0001
    if sigpower_valid:
        flags |= 0x0002
    if ref_aa_valid:
        flags |= 0x0010

    flags |= (pdu_type & 0x07) << 7
    flags |= 0x0400  # Bit 10: CRC Checked

    if not crc_err:
        flags |= 0x0800  # Bit 11: CRC Valid

    if pdu_type == 1:
        flags |= (aux_type & 0x03) << 12

    if phy == 3:
        flags |= 2 << 14
    else:
        flags |= (phy & 0x03) << 14

    return flags


class PcapBleWriter:
    """Thread-safe streaming libpcap writer for BLE Link Layer with PHDR (DLT 256)."""

    DLT: int = DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(
        self,
        output: str | Path | BinaryIO | None = None,
        base_epoch: float | None = None,
        auto_flush: bool = True,
    ) -> None:
        self.base_epoch: float = base_epoch if base_epoch is not None else time.time()
        self.auto_flush: bool = auto_flush
        self._lock: threading.RLock = threading.RLock()
        self._closed: bool = False
        self._owns_stream: bool = False
        self._last_raw_ts: int | None = None
        self._rollover_count: int = 0
        self.packet_count: int = 0
        self.bytes_written: int = 0

        if output is None:
            self.output: BinaryIO = io.BytesIO()
            self._owns_stream = True
        elif isinstance(output, (str, Path)):
            out_path = Path(output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            self.output = open(out_path, "wb")
            self._owns_stream = True
        elif hasattr(output, "write"):
            self.output = output
        else:
            raise TypeError(f"Unsupported output type for PcapBleWriter: {type(output)}")

        self.write_header()

    def __enter__(self) -> PcapBleWriter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def write_header(self) -> None:
        """Write 24-byte Global PCAP header."""
        with self._lock:
            hdr = struct.pack(
                GLOBAL_HEADER_FORMAT,
                PCAP_MAGIC_USEC,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,  # thiszone
                0,  # sigfigs
                PCAP_SNAPLEN,
                self.DLT,
            )
            self.output.write(hdr)
            self.bytes_written += len(hdr)
            if self.auto_flush:
                self.output.flush()

    def write_packet(
        self,
        ts_usec: int,
        aa: int = BLE_ADV_AA,
        chan: int = 37,
        rssi: int = -60,
        packet: bytes = b"",
        crc_err: bool = False,
        phy: int = 0,
        pdu_type: int = 0,
        aux_type: int = 0,
        crc_rev: int | None = None,
    ) -> None:
        """Write a single BLE Link Layer packet record to PCAP."""
        with self._lock:
            if self._closed:
                raise ValueError("Cannot write to closed PcapBleWriter")

            # 1. Monotonic microsecond unwrapping
            if self._last_raw_ts is not None and ts_usec < (self._last_raw_ts - 0x80000000):
                self._rollover_count += 1
            self._last_raw_ts = ts_usec
            unwrapped_usec = (self._rollover_count << 32) + ts_usec

            # Translate relative microsecond counter if ts_usec is relative (< 10^14)
            if unwrapped_usec < 100_000_000_000_000:
                epoch_usec = int(self.base_epoch * 1_000_000) + unwrapped_usec
            else:
                epoch_usec = unwrapped_usec

            ts_sec = epoch_usec // 1_000_000
            ts_sub = epoch_usec % 1_000_000

            # 2. Build 10-byte pseudo-header
            rf_chan = ble_to_rf_chan(chan)
            norm_rssi = normalize_rssi(rssi)
            flags = build_pseudo_header_flags(
                crc_err=crc_err,
                phy=phy,
                pdu_type=pdu_type,
                aux_type=aux_type,
            )
            pseudo_hdr = struct.pack(
                PSEUDO_HEADER_FORMAT, rf_chan, norm_rssi, -128, 0, aa, flags
            )

            # 3. Coding indicator byte (for Coded PHY)
            if phy == 2:
                ci_b = bytes([0])
            elif phy == 3:
                ci_b = bytes([1])
            else:
                ci_b = b""

            # 4. CRC resolution and payload assembly
            if len(packet) >= 2 and len(packet) == (packet[1] + 5):
                pdu_bytes = packet[:-3]
                crc_bytes = packet[-3:]
            elif len(packet) >= 2 and len(packet) == (packet[1] + 2):
                pdu_bytes = packet
                if crc_rev is None:
                    c_val = crc_ble_reverse(BLE_ADV_CRC_INIT_REV, pdu_bytes)
                else:
                    c_val = crc_rev
                crc_bytes = bytes([c_val & 0xFF, (c_val >> 8) & 0xFF, (c_val >> 16) & 0xFF])
            else:
                pdu_bytes = packet
                if crc_rev is None:
                    c_val = crc_ble_reverse(BLE_ADV_CRC_INIT_REV, pdu_bytes)
                else:
                    c_val = crc_rev
                crc_bytes = bytes([c_val & 0xFF, (c_val >> 8) & 0xFF, (c_val >> 16) & 0xFF])

            payload = pseudo_hdr + struct.pack("<I", aa) + ci_b + pdu_bytes + crc_bytes
            pkt_hdr = struct.pack(
                PACKET_HEADER_FORMAT, ts_sec, ts_sub, len(payload), len(payload)
            )

            self.output.write(pkt_hdr)
            self.output.write(payload)
            self.packet_count += 1
            self.bytes_written += len(pkt_hdr) + len(payload)

            if self.auto_flush:
                self.output.flush()

    def write_packet_message(self, pkt: Any, aa: int = BLE_ADV_AA) -> None:
        """Write a PacketMessage object received from wire protocol."""
        chan = getattr(pkt, "chan", 37)
        pdu_type = 0
        if chan < 37:
            # Data channel: direction flag determines master/slave
            pdu_type = 3 if getattr(pkt, "pkt_dir", 0) else 2

        self.write_packet(
            ts_usec=getattr(pkt, "ts", 0),
            aa=aa,
            chan=chan,
            rssi=getattr(pkt, "rssi", -60),
            packet=getattr(pkt, "body", b""),
            crc_err=getattr(pkt, "crc_err", False),
            phy=getattr(pkt, "phy", 0),
            pdu_type=pdu_type,
        )

    def write_dissected_frame(self, frame: Any, aa: int = BLE_ADV_AA) -> None:
        """Write a DissectedBleFrame object to PCAP."""
        raw_pdu = getattr(frame, "raw_pdu", b"")
        chan = getattr(frame, "channel", getattr(frame, "chan", 37))
        rssi = getattr(frame, "rssi", -60)
        ts = getattr(frame, "timestamp_usec", 0)
        self.write_packet(
            ts_usec=ts,
            aa=aa,
            chan=chan,
            rssi=rssi,
            packet=raw_pdu,
            crc_err=False,
        )

    def flush(self) -> None:
        """Flush output stream buffers."""
        with self._lock:
            if not self._closed and hasattr(self.output, "flush"):
                self.output.flush()

    def close(self) -> None:
        """Flush and safely close the PCAP stream."""
        with self._lock:
            if not self._closed:
                self.flush()
                if self._owns_stream and hasattr(self.output, "close"):
                    self.output.close()
                self._closed = True


@dataclass
class CapturedBlePacket:
    """Parsed Bluetooth LE packet record from DLT 256 PCAP."""

    ts_sec: int
    ts_usec: int
    ts_epoch: float
    rf_chan: int
    ble_chan: int
    rssi: int
    noise: int
    aa: int
    flags: int
    crc_err: bool
    phy: int
    pdu_type: int
    body: bytes
    crc: int
    raw_packet: bytes


class PcapBleReader:
    """Reader iterator for PCAP files with DLT_BLUETOOTH_LE_LL_WITH_PHDR."""

    def __init__(self, input_source: str | Path | BinaryIO) -> None:
        if isinstance(input_source, (str, Path)):
            self.input: BinaryIO = open(input_source, "rb")
            self._owns_stream: bool = True
        else:
            self.input = input_source
            self._owns_stream = False

        self._read_global_header()

    def __enter__(self) -> PcapBleReader:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _read_global_header(self) -> None:
        hdr = self.input.read(24)
        if len(hdr) < 24:
            raise ValueError("File too short for PCAP global header")
        magic, major, minor, _, _, _, dlt = struct.unpack(GLOBAL_HEADER_FORMAT, hdr)
        if magic != PCAP_MAGIC_USEC:
            raise ValueError(f"Invalid PCAP magic: 0x{magic:08X}")
        if dlt != DLT_BLUETOOTH_LE_LL_WITH_PHDR:
            raise ValueError(
                f"Unsupported LinkType: {dlt}, expected {DLT_BLUETOOTH_LE_LL_WITH_PHDR}"
            )

    def read_packet(self) -> CapturedBlePacket | None:
        """Read and parse the next packet from the PCAP stream."""
        pkt_hdr = self.input.read(16)
        if len(pkt_hdr) < 16:
            return None

        ts_sec, ts_usec, incl_len, _ = struct.unpack(PACKET_HEADER_FORMAT, pkt_hdr)
        data = self.input.read(incl_len)
        if len(data) < incl_len:
            raise EOFError("Truncated packet payload in PCAP")

        if len(data) < 17:  # 10B pseudo + 4B AA + 3B CRC
            raise ValueError(f"Payload too short for BLE PHDR ({len(data)} bytes)")

        rf_chan, rssi, noise, _, aa, flags = struct.unpack(
            PSEUDO_HEADER_FORMAT, data[:10]
        )
        wire_aa = struct.unpack("<I", data[10:14])[0]
        crc_err = not bool(flags & 0x0800)
        phy = (flags >> 14) & 0x03
        pdu_type = (flags >> 7) & 0x07

        body_idx = 14
        if phy == 2 or phy == 3:
            body_idx += 1  # Skip coding indicator byte

        body = data[body_idx:-3]
        crc_val = data[-3] | (data[-2] << 8) | (data[-1] << 16)

        return CapturedBlePacket(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            ts_epoch=ts_sec + (ts_usec / 1_000_000.0),
            rf_chan=rf_chan,
            ble_chan=rf_to_ble_chan(rf_chan),
            rssi=rssi,
            noise=noise,
            aa=wire_aa,
            flags=flags,
            crc_err=crc_err,
            phy=phy,
            pdu_type=pdu_type,
            body=body,
            crc=crc_val,
            raw_packet=data,
        )

    def __iter__(self) -> Iterator[CapturedBlePacket]:
        while True:
            pkt = self.read_packet()
            if pkt is None:
                break
            yield pkt

    def close(self) -> None:
        if self._owns_stream and hasattr(self.input, "close"):
            self.input.close()
