# Using TShark with Sniffle and Reading PCAP Files

## Key Concept: Extcap Plugins vs. PCAP Readers

In Wireshark and `tshark`, **extcap plugins** (such as `sniffle_extcap.py`) serve as **live capture interfaces** designed to capture streaming packets from external hardware dongles over a serial port (`/dev/ttyUSB*`). They are **not** file dissectors and cannot be used to open or read saved `.pcap` files.

You **do not need `sniffle_extcap.py` to read `/tmp/ads_cap.pcap`**. Wireshark and `tshark` have native built-in support for the standard BLE link-layer format (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`, DLT 256) recorded by Sniffle.

---

## Part 1: Reading `/tmp/ads_cap.pcap` with TShark

`tshark` reads existing capture files natively using the `-r` (`--read-file`) option.

### 1. Basic Packet Summary
```bash
tshark -r /tmp/ads_cap.pcap
```

### 2. Detailed Packet Dissection (Tree View)
To view full protocol fields and dissection trees:
```bash
# Decode and display the full packet tree (limit to first 5 packets with -c)
tshark -r /tmp/ads_cap.pcap -V -c 5
```

### 3. Display Filters
Apply Wireshark display filters with `-Y`:
```bash
# Filter for packets from a specific advertising address
tshark -r /tmp/ads_cap.pcap -Y "btle.advertising_address == c1:d3:1b:06:42:a4"

# Filter for advertising indications (ADV_IND) only
tshark -r /tmp/ads_cap.pcap -Y "btle.advertising_header.pdu_type == 0"

# Filter by minimum RSSI signal strength
tshark -r /tmp/ads_cap.pcap -Y "btle_rf.signal_dbm >= -60"
```

### 4. Extracting Specific Fields
Extract comma/tab-delimited fields for analysis or scripting:
```bash
tshark -r /tmp/ads_cap.pcap -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e btle.advertising_address \
  -e btle_rf.signal_dbm \
  -e btle_rf.rf_channel
```

### 5. Sniffle CLI Decoder (`pcap_decoder.py`)
If you need deep inspection of proprietary Bluetooth advertising payloads (such as Apple Find My, Nearby Info, or manufacturer data), Sniffle includes its own decoder tool:
```bash
python3 pcap_decoder.py -d /tmp/ads_cap.pcap
```

---

### 6. Resolving MAC OUI names, and showing the devices RAW MAC ADDRESSES at the same time
```bash
tshark -r /tmp/ads_cap-39.pcap
	-o "extcap.sniffle.serport:/dev/ttyUSB0" \
	-o "extcap.sniffle.mode:passive_scan" \
	-o "extcap.sniffle.advchan:37" \
	-T json
    -N m
	-Y "btle.advertising_address"
```

## Part 2: Using `sniffle_extcap.py` with TShark (Live Capture)

The extcap plugin streams packets from a physical Sniffle BLE dongle into `tshark`.

### 1. Installation & Verification
Ensure `sniffle_extcap.py` is executable and linked into your personal Wireshark extcap directory:
```bash
chmod +x sniffle_extcap.py
mkdir -p ~/.local/lib/wireshark/extcap
ln -s $(pwd)/sniffle_extcap.py ~/.local/lib/wireshark/extcap/
```

Verify that `tshark` detects the interface:
```bash
tshark -D
```
You should see:
```text
sniffle (Sniffle BLE sniffer)
```

### 2. Passing Extcap Parameters in TShark
`tshark` passes extcap options using preference strings via `-o "extcap.sniffle.<option>:<value>"`. The `--serport` parameter is mandatory.

#### Live Terminal Stream
```bash
tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0"
```

#### Live Capture to a PCAP File
```bash
tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0" -w /tmp/ads_cap.pcap
```

### 3. Available Extcap Configuration Options

| Option                     | Example Values                               | Description                                        |
|:---------------------------|:---------------------------------------------|:---------------------------------------------------|
| `extcap.sniffle.serport`   | `/dev/ttyUSB0`                               | **(Required)** Serial device path                  |
| `extcap.sniffle.mode`      | `passive_scan`, `active_scan`, `conn_follow` | Sniffer operating mode (default: `conn_follow`)    |
| `extcap.sniffle.advchan`   | `auto`, `all`, `37`, `38`, `39`              | Advertising channel to listen on (default: `auto`) |
| `extcap.sniffle.mac`       | `AA:BB:CC:DD:EE:FF`                          | Filter/follow by advertiser MAC address            |
| `extcap.sniffle.rssi`      | `-80`                                        | Minimum RSSI filter threshold (-128 to 0)          |
| `extcap.sniffle.extadv`    | `true`, `false`                              | Capture BT5 extended advertisements                |
| `extcap.sniffle.longrange` | `true`, `false`                              | Use long range (coded) PHY for primary advertising |
| `extcap.sniffle.crcerr`    | `true`, `false`                              | Capture packets with CRC errors                    |

### 4. Advanced Live Capture Examples

#### Passive Advertisement Scanning on Channels 37 (USB0) & 39 (USB1) 
```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -w /tmp/ads_cap-37.pcap

tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB1" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:39" \
  -w /tmp/ads_cap-39.pcap
```

#### Follow Connection for a Target MAC Address
```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mac:C1:D3:1B:06:42:A4" \
  -w /tmp/target_device.pcap
```

#### Live Capture with Real-Time Display Filter
```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -Y "btle.advertising_address"
```

### 5. JSON formatted packets (OUI Resolution + RAW MAC ADDRs)
```bash
tshark -i sniffle \
	-o "extcap.sniffle.serport:/dev/ttyUSB1" \
	-o "extcap.sniffle.mode:passive_scan" \
	-o "extcap.sniffle.advchan:37" \
	-T json \
    -N m \
	-Y "btle.advertising_address" | tee -a /tmp/cap-37.json
```
	
