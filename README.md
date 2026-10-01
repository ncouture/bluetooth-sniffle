# Bluetooth-Sniffle Testbed Framework

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)]()

A modular Python testbed framework coordinating two Sniffle-enabled USB devices (simultaneously executing active beacon injection/replay and passive sniffing/fingerprinting) to exercise and evaluate the Bluetooth Low Energy (BLE) tracking and identification methods documented in **PoPETs 2025-0103**: *"Your Signal, Their Data: An Empirical Privacy Analysis of Wireless-scanning SDKs in Android"*.

---

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Operational Topologies](#operational-topologies)
  - [Topology A: Stimulator + Observer](#topology-a-stimulator--observer)
  - [Topology B: Dual-Channel Passive Observer](#topology-b-dual-channel-passive-observer)
- [Hardware Requirements](#hardware-requirements)
  - [Supported Dongles & Bridge Limits](#supported-dongles--bridge-limits)
  - [Port Auto-Discovery](#port-auto-discovery)
- [Mock Simulation & Offline Harness](#mock-simulation--offline-harness)
- [Wire Protocol & Line Framing](#wire-protocol--line-framing)
- [Installation & Quick Start](#installation--quick-start)
- [Running Tests](#running-tests)
- [Project Layout](#project-layout)

---

## Architecture Overview

The testbed coordinates two Sniffle radio dongles over UART or an in-memory virtual radio bus:

```
                          ┌───────────────────────────┐
                          │   Testbed Orchestration   │
                          │   (Topology A / B / CLI)  │
                          └──────┬─────────────┬──────┘
                                 │             │
                    ┌────────────┴───┐     ┌───┴────────────┐
                    │ Device 1 Ctrl  │     │ Device 2 Ctrl  │
                    └────────┬───────┘     └───┬────────────┘
                             │                 │
               ┌─────────────┴─────┐     ┌─────┴─────────────┐
               │  SerialPort /     │     │  SerialPort /     │
               │  MockSerial (Dev1)│     │  MockSerial (Dev2)│
               └─────────────┬─────┘     └─────┬─────────────┘
                             │                 │
                     ▲       ▼                 ▲       ▼
                ╔════════════════════════════════════════════╗
                ║   Physical BLE Air / VirtualRadioBus       ║
                ║   (Channels 37, 38, 39, 1 µs Timestamps)   ║
                ╚════════════════════════════════════════════╝
```

Key subsystems include:
1. **`protocol`**:
   - `wire`: Base64+CRLF line framing with word-count prefix, command opcodes, and binary message parsing (`PacketMessage`, `MarkerMessage`, `StateMessage`, `MeasurementMessage`).
   - `mac`: Synthetic palindromic MAC address generator ensuring endianness invariance ($B_0..B_5 = B_5..B_0$) across LE radio bytes and network logs, with full support for Static Random, NRPA, RPA, and Public address types.
   - `beacons`: Standardized bit-for-bit AD encoders for Apple iBeacon, AltBeacon, Google Eddystone (UID, URL, TLM), and Google/Apple Exposure Notification (GAEN `0xFD6F`).
   - `probing`: Active probe constructors (`SCAN_REQ`) and response frames (`SCAN_RSP`) eliciting Complete Local Names and service UUIDs.
2. **`device`**:
   - `serial_port`: Hardware autodetection (Sonoff Zigbee Dongle Plus, TI XDS110, CatSniffer), non-conflicting dual port allocation, CP2102 baud rate capping (921,600 baud), and serial synchronization (`mark_and_flush`).
   - `mock`: In-memory `MockSerialInterface` and `VirtualRadioBus` for deterministic, offline testing without hardware dongles.
   - `controller`: High-level controller (`SniffleDeviceController`) managing advertising injection, active scanning, passive sniffing, and queued packet retrieval.
3. **`topology`**:
   - `topology_a`: Stimulator (Device 1) broadcasts synthesized beacons or burst sequences while Observer (Device 2) captures over-the-air packets.
   - `topology_b`: Dual-Channel Passive Observer locking Device 1 to Ch 37 and Device 2 to Ch 38, merging captures into a single timestamp-ordered stream to eliminate channel-hop blindness.
   - `lifecycle`: Graceful shutdown coordinator handling `SIGINT`/`SIGTERM`, safely terminating reader threads, and releasing serial ports.

---

## Operational Topologies

### Topology A: Stimulator + Observer
- **Device 1 (Stimulator)**: Configured as an active transmitter broadcasting parameterized beacon profiles (e.g. iBeacon, AltBeacon, Eddystone, GAEN) or replaying recorded advertisement sequences with custom transmission intervals (e.g., 20 ms to 1000 ms) and palindromic MAC addresses.
- **Device 2 (Observer)**: Concurrently sniffs primary advertising channels (37, 38, 39) to capture peripheral advertisements, mobile device scan requests (`SCAN_REQ`), and connection attempts elicited by the stimulator.

### Topology B: Dual-Channel Passive Observer
Standard single-dongle sniffers periodically hop across channels 37, 38, and 39, causing blind spots during channel transitions. Topology B coordinates two devices simultaneously locked to fixed primary advertising channels:
- **Device 1**: Locked to Channel 37 (`hop3=False`).
- **Device 2**: Locked to Channel 38 (`hop3=False`) or Channel 39.
- Captured packets from both dongles are merged in real time into a strictly timestamp-ordered queue, providing continuous multi-channel visibility.

---

## Hardware Requirements

### Supported Dongles & Bridge Limits
- **Sonoff Zigbee 3.0 USB Dongle Plus** (TI CC2652P, USB VID: `0x10C4`, PID: `0xEA60`).
  - *Note*: Older Sonoff dongles use Silicon Labs CP2102 (non-N) bridge chips limited to **921,600 baud**. The framework automatically caps the baud rate to 921,600 baud when CP2102 bridges are detected. Newer CP2102N revisions operate at **2,000,000 baud**.
- **Texas Instruments CC26x2 LaunchPad** (CC2652R / CC2652RB / CC1352P with XDS110 Debug Probe, VID: `0x0451`, PID: `0xBEF3`). Default: **2,000,000 baud**.
- **Electronic Cats CatSniffer V3** (VID: `0x2E8A` / 11914, PID: `0x00C0` / 192).

### Port Auto-Discovery
The `discover_sniffle_ports()` and `allocate_dual_ports()` utilities automatically scan available serial interfaces, match hardware descriptors, and assign two distinct ports (`port1 != port2`) to Device 1 and Device 2 without manual configuration.

---

## Mock Simulation & Offline Harness

The testbed includes a full in-memory simulation subsystem:
- **`MockSerialInterface`**: Emulates PySerial `Serial` operations (`read`, `readline`, `write`, `cancel_read`, `close`, `in_waiting`) in pure Python with thread-safe non-blocking buffers.
- **`VirtualRadioBus`**: Routes link-layer packets between simulated dongles. When Device 1 transmits an advertisement (`COMMAND_ADVERTISE`), the bus wraps the payload into a standard `PacketMessage` with microsecond timestamps, RF channel, RSSI (-60 dBm), and valid CRC, delivering it to any listening device locked to that channel.
- Enables 100% automated test coverage in CI/CD environments without physical hardware dongles.

---

## Wire Protocol & Line Framing

Sniffle communicates over UART using **Base64 ASCII records** terminated by `\r\n`:

```
Host to Dongle:
  b0 = (len(cmd_bytes) + 3) // 3
  wire_line = base64_encode(bytes([b0, *cmd_bytes])) + "\r\n"

Dongle to Host:
  data = base64_decode(raw_line)
  word_cnt = data[0]
  msg_type = data[1]
  msg_body = data[2:]
```

### PacketMessage Header Format (Message Type `0x10`)
Packets received by the radio unpack a 10-byte header:
- `ts` (4 bytes, uint32 LE): Microsecond timestamp (1 µs resolution).
- `l` (2 bytes, uint16 LE): Flags bitfield:
  - Bit 15: Direction (`0` = Central -> Peripheral, `1` = Peripheral -> Central).
  - Bit 14: CRC Error flag (`1` = CRC error, `0` = Valid CRC).
  - Bits 13..0: Link Layer PDU length in bytes.
- `event` (2 bytes, uint16 LE): Connection event counter.
- `rssi` (1 byte, signed int8): Signal strength in dBm (-128 to 0 dBm).
- `chan` (1 byte, uint8): Bits 5..0 = RF channel (0–39); Bits 7..6 = PHY mode (0=1M, 1=2M, 2=Coded S8, 3=Coded S2).
- Followed by the raw Link Layer PDU body.

---

## Installation & Quick Start

```bash
# Clone the repository
git clone https://github.com/example/bluetooth-sniffle.git
cd bluetooth-sniffle

# Install in editable mode with development dependencies
pip install -e .[test]
```

---

## Running Tests

Execute the automated test suite with strict warning trapping:

```bash
# Run all unit tests
pytest -v -W error tests/

# Run with coverage report
pytest --cov=bluetooth_sniffle --cov-report=term-missing tests/

# Run linter
ruff check src tests
```

---

## Project Layout

```
bluetooth-sniffle/
├── README.md
├── pyproject.toml
├── src/
│   └── bluetooth_sniffle/
│       ├── __init__.py
│       ├── protocol/
│       │   ├── __init__.py
│       │   ├── wire.py          # Sniffle Base64 line framing & opcodes
│       │   ├── mac.py           # Palindromic MAC address generator
│       │   ├── beacons.py       # iBeacon, AltBeacon, Eddystone, GAEN
│       │   └── probing.py       # SCAN_REQ / SCAN_RSP builders
│       ├── device/
│       │   ├── __init__.py
│       │   ├── serial_port.py   # Port discovery, auto-baud, lifecycle
│       │   ├── mock.py          # MockSerialInterface & VirtualRadioBus
│       │   └── controller.py    # SniffleDeviceController
│       └── topology/
│           ├── __init__.py
│           ├── base.py          # BaseTopology ABC
│           ├── topology_a.py    # Stimulator + Observer
│           ├── topology_b.py    # Dual-Channel Passive Observer
│           └── lifecycle.py     # Graceful shutdown coordinator
└── tests/
    ├── conftest.py
    ├── test_beacons.py
    ├── test_palindromic_mac.py
    ├── test_probing.py
    ├── test_wire_protocol.py
    ├── test_mock_device.py
    └── test_topologies.py
```
