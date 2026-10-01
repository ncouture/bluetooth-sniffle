# Sniffle CLI operations guide

This guide documents the command line utilities included with Sniffle in `python_cli/`. It covers hardware verification, active scanning, packet sniffing, connection tracking, link-layer transmission, relay attacks, and offline packet analysis.

## Overview of Sniffle CLI tools

Sniffle pairs host-side Python utilities with firmware running on supported Texas Instruments hardware (CC1352, CC2652, CC2651, CC1354) and compatible boards such as the Sonoff Zigbee 3.0 USB Dongle Plus and CatSniffer v3.

The Python scripts in `python_cli/` communicate with the hardware over a serial interface using a base64-encoded binary command protocol.

The primary CLI utilities include:

* `version_check.py`: Probes the connected hardware and reports the firmware version and API level.
* `uart_test.py`: Runs a round-trip echo test to measure serial communication latency and packet integrity.
* `reset.py`: Sends reset commands to the firmware to recover from lockups or clear state.
* `scanner.py`: Performs active BLE scanning, collects advertisements and scan responses, and prints an aggregated summary sorted by signal strength.
* `sniff_receiver.py`: Captures advertisements and connection traffic, supports 3-channel primary advertising hopping, extended advertising, coded PHY, and PCAP export.
* `sniffle_extcap.py`: Extcap plugin enabling live capture directly in Wireshark.
* `pcap_decoder.py`: Decodes captured PCAP files offline and parses Bluetooth advertising data structures.
* `advertiser.py`: Transmits connectable legacy advertisements with a configurable device name and accepts incoming connections.
* `initiator.py`: Connects to a target peripheral and acts as a central device, sending link-layer test PDUs.
* `relay_master.py`: Acts as the central component of a link-layer relay, capturing peripheral advertising data and forwarding traffic over TCP.
* `relay_slave.py`: Acts as the peripheral component of a link-layer relay, impersonating the target peripheral and tunnelling link-layer frames to the master.
* `radar_tomography.py`: Passive radio tomographic imaging engine that processes multi-channel RSSI streams to detect and track indoor movement.

### Hardware serial port detection

Sniffle automatically searches for supported hardware in the following order:

1. TI XDS110 debug probe (USB VID `0451`, PID `BEF3`). On Linux, XDS110 presents two CDC-ACM ports (typically `/dev/ttyACM0` and `/dev/ttyACM1`). Sniffle selects the first port in alphabetical order (`/dev/ttyACM0`).
2. Sonoff Zigbee 3.0 USB Dongle Plus (USB VID `10C4`, PID `EA60`). On Linux, this appears as `/dev/ttyUSB0`.
3. CatSniffer v3 (USB VID `2E8A`, PID `00C0`). On Linux, this appears as `/dev/ttyACM0`.

If multiple devices are connected, or if a different USB-to-serial adapter is used, specify the port explicitly with `-s <port>` (for example, `-s /dev/ttyUSB1`).

### Baud rate selection

The default baud rate for Sniffle is 2,000,000 baud (2M).

Certain older Sonoff dongles manufactured with the Silicon Labs CP2102 (non-N) bridge chip have a hardware limit of 921,600 baud. For these devices, flash the `CC2652P1F_1M` firmware variant and pass `-b 921600` to all CLI commands.

---

## Hardware verification and diagnostics

Before capturing packets, verify that the hardware is responsive, that the firmware API version matches the host scripts, and that serial transfer latency is within acceptable limits.

### Checking firmware version

Run `version_check.py` to confirm communication with the hardware:

```bash
cd python_cli
./version_check.py
```

To specify an explicit port and baud rate:

```bash
./version_check.py -s /dev/ttyACM0 -b 2000000
```

Expected output:

```text
VersionMeasurement(major=1, minor=10, patch=0, api_level=0)
```

If the tool reports `API level mismatch`, update either the firmware on the hardware or the Python host scripts so their API versions match. If the tool reports `Timeout probing firmware version`, check USB permissions or run `reset.py`.

### Testing UART latency and stability

`uart_test.py` sends random byte sequences (`cmd_marker`) of varying lengths to the hardware and measures round-trip time:

```bash
./uart_test.py -s /dev/ttyACM0
```

Expected output:

```text
success, len 142, latency 2.1 ms
success, len 89, latency 1.8 ms
success, len 210, latency 2.4 ms
```

If round-trip latency exceeds 15 to 30 ms consistently on TI Launchpad boards, the XDS110 debugger firmware is buffering serial transfers. Consult the README section on XDS110 UART latency for the patch to enable interrupt-driven transfers.

### Resetting the sniffer firmware

If the sniffer firmware stops reporting packets or enters an unexpected state, use `reset.py` to issue software resets and flush UART buffers:

```bash
./reset.py -s /dev/ttyACM0
```

Expected output:

```text
Sending reset commands...
Trying a mark and flush to get things flowing...
Reset success.
```

If software reset fails, press the physical reset button located next to the micro-USB connector on the Launchpad board.

---

## Active device discovery and scanning

The `scanner.py` utility discovers nearby advertising devices without flooding the terminal with continuous packet streams. It issues active scan requests, records unique MAC addresses, calculates RSSI statistics, and prints a formatted summary when stopped.

### Basic active scan

Run `scanner.py` on default advertising channel 37:

```bash
./scanner.py
```

Press `Ctrl-C` to stop scanning and view the aggregated results.

Output format:

```text
Starting scanner. Press CTRL-C to stop scanning and show results.
Found 12:34:56:78:9A:BC (random)...
Found AA:BB:CC:DD:EE:FF (public)...
^C

Scan Results:
================================================================================
AdvA: 12:34:56:78:9A:BC (random) Avg/Min/Max RSSI: -42.3/-48/-38 Hits: 15

Advertisement:
Timestamp: 1.203450  Length: 28  RSSI: -41  Channel: 37  PHY: 1M  CRC: 0x91AB23
Ad Type: ADV_IND
AdvA: 12:34:56:78:9A:BC (random)
AdvData: 0201061107...
Flags: LE General Discoverable Mode, BR/EDR Not Supported

Scan Response:
Timestamp: 1.205120  Length: 16  RSSI: -40  Channel: 37  PHY: 1M  CRC: 0x12EF45
Ad Type: SCAN_RSP
AdvA: 12:34:56:78:9A:BC (random)
Complete Local Name: Smart Sensor
================================================================================
```

### Filtering scan results by RSSI and channel

To ignore background devices and focus on hardware placed directly next to the sniffer, set an RSSI cutoff and listen on channel 38 or 39:

```bash
./scanner.py -c 38 -r -50
```

* `-c 38`: Listens on advertising channel 38 (valid channels are 37, 38, 39).
* `-r -50`: Drops packets with RSSI lower than -50 dBm.

### Scanning Bluetooth 5 coded PHY (long range)

To scan for devices advertising on the Bluetooth 5 coded PHY:

```bash
./scanner.py -l -c 37
```

* `-l`, `--longrange`: Configures the primary advertising channel receiver for coded PHY.

### Decoding advertisement structures and saving to PCAP

```bash
./scanner.py -d -o discovery.pcap
```

* `-d`, `--decode`: Parses Bluetooth SIG advertising data types (device names, UUIDs, manufacturer data, TX power).
* `-o discovery.pcap`: Writes all received advertisement frames to a PCAP file.

---

## Packet sniffing and connection following

The `sniff_receiver.py` utility is the main sniffer CLI. It operates in three distinct modes:

1. Connection following mode (default): Listens for advertisements, detects connection establishment (`CONNECT_IND` or `AUX_CONNECT_REQ`), and automatically follows the connection onto the 37 BLE data channels.
2. Passive scan mode (`-a` / `--advonly`): Captures advertising packets without following connections.
3. Active scan mode (`-A` / `--scan`): Sends scan requests to capture scan response packets without following connections.

### Passive sniffing on a fixed advertising channel

To monitor all advertisements on channel 38 without following connections:

```bash
./sniff_receiver.py -c 38 -a
```

To filter out distant devices and export the stream to a PCAP file:

```bash
./sniff_receiver.py -c 38 -a -r -55 -o adv_capture.pcap
```

### Target filtering and three-channel advertising hopping

Standard single-channel sniffers listen on only one primary channel (for example, channel 37). Because peripherals cycle advertisements across channels 37, 38, and 39, a central device may send `CONNECT_IND` on channel 38 or 39, causing a single-channel sniffer to miss the connection entirely.

When a target filter (`-m`, `-i`, or `-S`) is specified without explicitly fixing the channel via `-c`, Sniffle hops between channels 37, 38, and 39 following the target advertiser. This provides reliable connection capture.

#### Filtering by target MAC address

Specify the 6-byte hexadecimal MAC address of the peripheral device:

```bash
./sniff_receiver.py -m 12:34:56:78:9A:BC -o conn_follow.pcap
```

Do not specify `-c` if you want automatic three-channel hopping.

#### Filtering by Identity Resolving Key (IRK)

Modern BLE devices (smartphones, wearables, trackers) use Resolvable Private Addresses (RPAs) that change periodically. If you know the peripheral device's 128-bit Identity Resolving Key (IRK), Sniffle resolves RPAs in real time and hops across channels with the target:

```bash
./sniff_receiver.py -i 4E0BEA5355866BE38EF0AC2E3F0EBC22 -o rpa_capture.pcap
```

* `-i`: Hexadecimal string representing the 16-byte key in big-endian byte order (MSB first).

Reversing key endianness:

Android stores IRK keys in little-endian format in `/data/misc/bluedroid/bt_config.conf`. Reverse the byte order before passing the key to `-i`:

```bash
# Little-endian key from bt_config.conf:
# 22BC0E3F2EACF08EE36B865553EA0B4E
#
# Reversed big-endian key for Sniffle:
./sniff_receiver.py -i 4E0BEA5355866BE38EF0AC2E3F0EBC22
```

#### Filtering by advertisement search string

If the target uses an RPA but the IRK is unknown, identify the target by matching unique byte sequences in its advertising data or scan response:

Matching ASCII text:

```bash
./sniff_receiver.py -S "MySensor" -o target.pcap
```

Matching raw byte sequences:

```bash
./sniff_receiver.py -S "\xDE\xAD\xBE\xEF" -o target.pcap
```

When `-S` is used, Sniffle accepts packets from all devices until an advertisement containing the specified sequence is seen. Once found, Sniffle locks its MAC filter to that target address, disables any RSSI filter, and hops across primary channels with that device.

### Additional capture options

* Pause after disconnection (`-p`): Halts capture when the connection terminates instead of returning to advertising capture.
* Suppress empty data packets (`-q`): Hides empty link-layer keepalive frames (`data_length == 0`) from the terminal display. Packets are still written to the PCAP file.
* Capture CRC errors (`-C`): Disables hardware CRC filtering to capture damaged frames for physical layer analysis.
* Decode advertising structures (`-d`): Expands AD elements inline in the terminal output.

---

## Bluetooth 5 extended and coded PHY sniffing

Bluetooth 5 introduces extended advertising, which allows advertising packets up to 254 bytes by offloading payloads to secondary data channels (channels 0 through 36). It also introduces coded PHY for extended range.

### Sniffing extended advertisements

To follow auxiliary pointers from primary channels to secondary channels:

```bash
./sniff_receiver.py -e -r -60 -o ext_adv.pcap
```

* `-e`, `--extadv`: Instructs the firmware to read auxiliary pointers (`AUX_ADV_IND`, `AUX_CHAIN_IND`) and switch to secondary channels to capture large payloads.

### Combining extended advertising with primary channel hopping

By default, `-e` stays on a single primary channel because auxiliary pointers on all primary channels generally point to the same secondary channel auxiliary packet. If you are unsure whether a device connects via legacy or extended advertising, enable primary hopping alongside extended advertising:

```bash
./sniff_receiver.py -e -H -m 12:34:56:78:9A:BC -o mixed_capture.pcap
```

* `-H`, `--hop`: Forces primary channel hopping while extended advertising mode is active.

### Sniffing long-range coded PHY

To capture primary advertisements transmitted using coded PHY (S=8 or S=2):

```bash
./sniff_receiver.py -l -e -c 37 -o coded_phy.pcap
```

* `-l`, `--longrange`: Enables coded PHY reception on primary advertising channels. Coded PHY primary advertising always uses the extended advertising format, so `-e` is required.

---

## Tracking encrypted connections

When a connection is encrypted, link-layer control PDUs (`LL_CONNECTION_PARAM_REQ`, `LL_CONNECTION_UPDATE_IND`, and `LL_PHY_REQ`) are also encrypted. If the central updates connection intervals or changes the PHY under encryption, a sniffer cannot read the updated timing parameters directly from the packet payload.

Sniffle includes hardware-assisted connection parameter measurement to track changes automatically. You can also supply known parameters in advance to maintain synchronization.

### Preloading connection interval updates

If the peripheral or central is known to negotiate specific connection intervals upon encryption, supply them with `-Q` (`--preload`).

Format: `Interval:DeltaInstant`

* `Interval`: Integer representing multiples of 1.25 ms (as defined in `LL_CONNECTION_UPDATE_IND`). An Interval of 6 represents 7.5 ms. An Interval of 39 represents 48.75 ms.
* `DeltaInstant`: Number of connection events between packet transmission and when parameters take effect (minimum 6).

Example with two preloaded updates:

```bash
./sniff_receiver.py -m 12:34:56:78:9A:BC -Q 6:6,39:6 -o encrypted_conn.pcap
```

### Disabling PHY change tracking

Some devices transmit encrypted link-layer control PDUs (such as LE Power Control requests) that do not alter the PHY, or issue PHY updates without changing the modulation rate. If Sniffle desynchronizes during encrypted traffic, pass `-n`:

```bash
./sniff_receiver.py -m 12:34:56:78:9A:BC -n -o session.pcap
```

* `-n`, `--nophychange`: Ignores ambiguous encrypted control PDUs that might otherwise trigger unnecessary PHY reconfigurations.

---

## Offline PCAP decoding and analysis

Sniffle saves captures in standard PCAP format with link-layer header type `DLT_BLUETOOTH_LE_LL_WITH_PHDR` (compatible with Ubertooth and Wireshark).

### Inspecting PCAP files with `pcap_decoder.py`

`pcap_decoder.py` inspects captured PCAP files from the command line without opening Wireshark.

Basic decoding:

```bash
./pcap_decoder.py capture.pcap
```

Decoding advertising structures and suppressing empty keepalives:

```bash
./pcap_decoder.py -d -q capture.pcap
```

* `-d`: Decodes advertising data structures (local names, UUIDs, service data).
* `-q`: Omits empty link-layer data packets to focus on meaningful payload data.

### Analyzing encrypted handshakes with Crackle

Captured PCAP files can be analyzed with `crackle` to identify encryption handshakes, crack legacy pairing PINs, or decrypt traffic using a known Long Term Key (LTK).

Analyzing a capture file:

```bash
crackle -i capture.pcap -v
```

Decrypting with a known LTK:

```bash
crackle -i capture.pcap -o decrypted.pcap -l 0123456789ABCDEF0123456789ABCDEF
```

---

## Live capture in Wireshark via Extcap

`sniffle_extcap.py` integrates Sniffle with Wireshark. When installed, Wireshark lists "Sniffle" as an available capture interface, allowing configuration through a graphical options menu.

### Installing the plugin

#### Linux and macOS

Create the personal extcap directory and create a symlink to `sniffle_extcap.py`:

```bash
mkdir -p ~/.local/lib/wireshark/extcap
ln -s /home/self/git/Sniffle/Sniffle/python_cli/sniffle_extcap.py ~/.local/lib/wireshark/extcap/
chmod +x ~/.local/lib/wireshark/extcap/sniffle_extcap.py
```

On macOS, if Wireshark uses the system Python rather than your active shell environment, edit the first line of `sniffle_extcap.py` to point directly to your Python 3 binary with PySerial installed (for example, `#!/usr/local/bin/python3`).

#### Windows

Copy `sniffle_extcap.py`, `sniffle_extcap.bat`, and the `sniffle/` library folder into the Wireshark personal extcap folder:

```text
%USERPROFILE%\AppData\Roaming\Wireshark\extcap
```

Ensure `sniffle_extcap.bat` points to your Python installation directory.

### Running extcap from the command line

To verify that the extcap script responds correctly:

```bash
./sniffle_extcap.py --extcap-interfaces
```

Output:

```text
interface {value=sniffle}{display=Sniffle BLE sniffer}
```

To list available configuration controls:

```bash
./sniffle_extcap.py --extcap-interface sniffle --extcap-config
```

In the Wireshark GUI, click the gear icon next to the Sniffle interface to configure the serial port, capture mode, target MAC or IRK filter, RSSI threshold, and extended advertising options before starting capture.

---

## Link-layer transmission and emulation

Sniffle supports active link-layer transmission. The firmware provides low-level control of transmitted link-layer PDUs without going through a host HCI stack.

### Peripheral emulation with `advertiser.py`

`advertiser.py` configures Sniffle to act as a connectable peripheral device. It generates a random static address, sets TX power to +5 dBm, advertises on channel 37 every 200 ms, and accepts connection requests:

```bash
./advertiser.py -n "Test Peripheral"
```

* `-n`, `--name`: Local name broadcast in the scan response data (defaults to "NCC Goat").
* `-s`: Serial port for the transmitting board.

When a central device connects, `advertiser.py` prints incoming packets and maintains connection state.

### Central connection testing with `initiator.py`

`initiator.py` scans for a specified target peripheral, transmits a `CONNECT_IND` packet to establish a connection, and acts as the central device:

Connecting by target MAC address:

```bash
./initiator.py -m 12:34:56:78:9A:BC
```

Connecting to a public address (non-random):

```bash
./initiator.py -m 12:34:56:78:9A:BC -P
```

Connecting by target name string:

```bash
./initiator.py -S "Test Peripheral"
```

Once connected, `initiator.py` exercises the connection by periodically sending `LL_PING_REQ` packets (every fourth message) and issuing an `LL_CONNECTION_UPDATE_IND` update packet at packet counter 64.

---

## Link-layer relay attacks

Sniffle can perform link-layer relay attacks against Bluetooth LE connections. The relay consists of two Sniffle devices communicating over a network:

1. Relay master (`relay_master.py`): Placed near the legitimate peripheral device. It captures advertising and scan response data, listens on TCP port 7352, and connects to the genuine peripheral when instructed.
2. Relay slave (`relay_slave.py`): Placed near the legitimate central device. It connects to the master over TCP, clones the genuine peripheral's address and advertising payload, accepts connections from the central, and tunnels all link-layer traffic.

```text
[Central (C)]  <---BLE--->  [Relay Slave (P_r)]  <---TCP (7352)--->  [Relay Master (C_r)]  <---BLE--->  [Peripheral (P)]
```

### Step 1: Start the relay master

Run `relay_master.py` on the computer connected to the first Sniffle board (positioned near the peripheral):

```bash
./relay_master.py -s /dev/ttyACM0 -m 12:34:56:78:9A:BC -f -F -o relay_capture.pcap
```

* `-s /dev/ttyACM0`: Serial port of the master Sniffle board.
* `-m 12:34:56:78:9A:BC`: MAC address of the target peripheral.
* `-f`, `--fastslave`: Requests a fast connection interval on the slave side to reduce latency.
* `-F`, `--fastmaster`: Instructs the master to request a fast connection interval on the real target.
* `-o relay_capture.pcap`: Saves all forwarded link-layer frames to PCAP.
* `-p`, `--pause`: Prompts for a key press on the master before starting the relay session.

The master script binds TCP port 7352 on `0.0.0.0` and waits for the slave to connect.

### Step 2: Start the relay slave

Run `relay_slave.py` on the computer connected to the second Sniffle board (positioned near the central):

```bash
./relay_slave.py -s /dev/ttyACM1 -M 192.168.1.50
```

* `-s /dev/ttyACM1`: Serial port of the slave Sniffle board.
* `-M 192.168.1.50`: IP address of the relay master machine.

### Step 3: Execution sequence

1. The relay slave connects to the relay master over TCP and completes a latency check.
2. The relay master sniffs the target peripheral's `ADV_IND` and `SCAN_RSP` frames.
3. The master forwards the exact advertising and scan response data to the slave.
4. The slave begins advertising using the genuine peripheral's MAC address and payload.
5. When the legitimate central issues a `CONNECT_IND` to the slave, the slave notifies the master over TCP.
6. The master transmits a `CONNECT_IND` to the genuine peripheral.
7. Once both sides are connected, packets received from the central by the slave are transmitted to the peripheral by the master, and vice versa.

---

## Radio tomographic imaging and passive human sensing

`radar_tomography.py` is a 2D radio tomographic imaging engine. It uses RSSI perturbations across RF links between ambient BLE transmitters and Sniffle receivers to detect and locate moving physical objects or people without requiring them to carry a device.

### Simulating indoor human sensing

To verify the tomographic reconstruction pipeline without physical hardware:

```bash
python3.13 radar_tomography.py --simulate --headless --max-frames 20
```

* `--simulate`: Generates simulated RF link samples with moving target disturbances.
* `--headless`: Disables graphical display windows (suited for automated runs and headless servers).
* `--max-frames 20`: Stops execution after processing 20 frames.

Expected output:

```text
[RADAR] DualSniffer started (Mock Simulation).
[RADAR] R1 locked to Channel 37, R2 locked to Channel 38.
[RADAR] Public mode: True | Room: 20.0m x 10.0m.
[RADAR FRAME 0001] Links:  8 | Packets: 15 | Peak Z:  0.00σ | Intensity:  0.00 | Target: None
[RADAR FRAME 0002] Links: 10 | Packets: 13 | Peak Z:  0.00σ | Intensity:  0.00 | Target: None
[RADAR FRAME 0003] Links: 13 | Packets:  8 | Peak Z:  0.00σ | Intensity:  4.19 | Target: (12.23, 3.68)
[RADAR FRAME 0004] Links: 15 | Packets:  9 | Peak Z:  0.00σ | Intensity: 11.28 | Target: (12.80, 4.30)
```

### Replaying a recorded RF dataset

To replay pre-recorded RSSI samples from a JSON file:

```bash
python3.13 radar_tomography.py --replay radar_sample_data.json --headless
```

### Live dual-dongle multi-channel operation

To run live spatial tomography using two physical Sniffle boards acting as distributed receivers:

```bash
python3.13 radar_tomography.py \
  --port1 /dev/ttyUSB0 \
  --port2 /dev/ttyUSB1 \
  --chan1 37 \
  --chan2 38 \
  --public-mode \
  --room-width 15.0 \
  --room-height 10.0 \
  --grid-res 0.2
```

* `--port1`, `--port2`: Serial ports for Sniffle Receiver 1 (`R1`) and Receiver 2 (`R2`).
* `--chan1`, `--chan2`: Primary advertising channels assigned to each receiver.
* `--public-mode`: Automatically discovers ambient public BLE transmitters in the room.
* `--room-width`, `--room-height`: Room dimensions in meters.
* `--grid-res`: Resolution of spatial reconstruction cells in meters.

---

## Step-by-step multi-CLI workflows

### Workflow 1: Discovery, targeted capture, and offline analysis

This workflow demonstrates finding a target device, capturing its connection handshake, and analyzing the resulting traffic.

1. Discover target devices and identify the MAC address:

   ```bash
   ./scanner.py -r -50 -d
   ```

   Locate the device of interest in the summary (for example, `AA:BB:CC:DD:EE:FF`).

2. Start targeted sniffing with three-channel hopping:

   ```bash
   ./sniff_receiver.py -m AA:BB:CC:DD:EE:FF -o target_session.pcap
   ```

3. Trigger a connection from the mobile application or central device. Observe Sniffle detect the connection request and follow it onto the data channels.

4. Press `Ctrl-C` after the session completes.

5. Inspect the recorded packets offline:

   ```bash
   ./pcap_decoder.py -q -d target_session.pcap
   ```

### Workflow 2: End-to-end hardware loopback and transmission test

This workflow validates link-layer transmission using two Sniffle boards connected to the same computer.

1. Identify serial ports for both boards:

   ```bash
   ls /dev/ttyACM* /dev/ttyUSB*
   ```

   Assume Board A is on `/dev/ttyACM0` and Board B is on `/dev/ttyACM2`.

2. Reset both boards to ensure a clean state:

   ```bash
   ./reset.py -s /dev/ttyACM0
   ./reset.py -s /dev/ttyACM2
   ```

3. Start the peripheral emulator on Board A:

   ```bash
   ./advertiser.py -s /dev/ttyACM0 -n "SniffleLab"
   ```

4. Connect to the peripheral using the initiator on Board B:

   ```bash
   ./initiator.py -s /dev/ttyACM2 -S "SniffleLab"
   ```

5. Observe the initiator detect the advertisement, transmit `CONNECT_IND`, send periodic `LL_PING_REQ` packets, and issue connection parameter updates.

### Workflow 3: Capturing and decrypting legacy pairing traffic

1. Put the target peripheral into pairing mode.

2. Launch `sniff_receiver.py` with parameter preloading enabled:

   ```bash
   ./sniff_receiver.py -m AA:BB:CC:DD:EE:FF -Q 6:6,39:6 -o pairing.pcap
   ```

3. Initiate pairing from the central device (for example, enter PIN `123456`).

4. Stop capture with `Ctrl-C` after pairing completes.

5. Process the capture with `crackle`:

   ```bash
   crackle -i pairing.pcap -o decrypted_pairing.pcap
   ```

6. Inspect the decrypted link-layer data:

   ```bash
   ./pcap_decoder.py -q decrypted_pairing.pcap
   ```

---

## CLI reference summary

| Script | Primary function | Key arguments | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| `version_check.py` | Verify firmware version and API level | `-s`, `-b` | Hardware UART | Terminal version report |
| `uart_test.py` | Test serial link latency and stability | `-s`, `-b` | Hardware UART | Latency measurements |
| `reset.py` | Reset firmware and flush buffers | `-s`, `-b` | Hardware UART | Reset status |
| `scanner.py` | Active BLE discovery and RSSI summary | `-s`, `-b`, `-c`, `-r`, `-l`, `-d`, `-o` | Live RF | Terminal summary, PCAP |
| `sniff_receiver.py` | Sniff BLE5 advertisements and connections | `-s`, `-b`, `-c`, `-m`, `-i`, `-S`, `-r`, `-a`, `-A`, `-e`, `-H`, `-l`, `-q`, `-Q`, `-n`, `-C`, `-d`, `-o` | Live RF | Terminal packets, PCAP |
| `sniffle_extcap.py` | Wireshark extcap capture interface | `--capture`, `--fifo`, `--extcap-config`, `--serport`, `--mac`, `--irk`, `--mode` | Hardware UART | Wireshark FIFO stream |
| `pcap_decoder.py` | Offline PCAP packet and AD structure parser | `pcap`, `-q`, `-d` | PCAP file | Terminal decode and hexdump |
| `advertiser.py` | Peripheral advertiser and connectable emulator | `-s`, `-b`, `-n` | CLI arguments | Transmitted BLE frames |
| `initiator.py` | Central connection initiator and tester | `-s`, `-b`, `-c`, `-m`, `-i`, `-S`, `-l`, `-P` | Live RF | Transmitted BLE frames |
| `relay_master.py` | Central relay forwarder (peripheral-facing) | `-s`, `-c`, `-m`, `-i`, `-S`, `-P`, `-q`, `-Q`, `-f`, `-p`, `-F`, `-o` | Live RF, TCP | TCP stream, PCAP |
| `relay_slave.py` | Peripheral relay emulator (central-facing) | `-s`, `-M`, `-q` | TCP stream | Live RF, forwarded frames |
| `radar_tomography.py`| Radio tomographic imaging engine | `--simulate`, `--replay`, `--headless`, `--port1`, `--port2`, `--chan1`, `--chan2`, `--public-mode` | Live RF, JSON, or mock | Terminal metrics, 2D plots |

---

## Troubleshooting and operational notes

### Serial port permissions

On Linux, accessing USB serial devices (`/dev/ttyACM*` or `/dev/ttyUSB*`) requires membership in the `dialout` or `uucp` group:

```bash
sudo usermod -aG dialout $USER
```

Log out and log back in for group changes to take effect.

### Handling firmware lockups

If the sniffer stops receiving packets while advertising traffic is known to be present:

1. Run `./reset.py -s <port>` to issue software synchronization markers and resets.
2. If the board does not recover, press the physical hardware reset button on the board.
3. Verify that the device is running the expected baud rate (2,000,000 baud default, or 921,600 baud for older CP2102 dongles).

### Minimizing packet loss

* Distance: When filtering by RSSI (`-r`), place the sniffer within 10 to 30 cm of the target.
* Hopping: Always omit `-c` when using `-m`, `-i`, or `-S` for connection tracking so Sniffle hops across channels 37, 38, and 39.
* RF environment: Busy 2.4 GHz environments with high Wi-Fi traffic can cause dropped packets during the connection establishment window. Position the sniffer antenna close to the transmitter to maximize signal-to-noise ratio.
