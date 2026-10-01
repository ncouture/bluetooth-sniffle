  To capture Bluetooth Low Energy (BLE) advertisements indicating "AirDrop receive enabled", it helps to understand how Apple encodes this
	status in the advertising payload, followed by the exact commands for TShark and Sniffle Python CLI utilities.
──────
### Understanding the Packet Structure
In your example packet:
0x0000:  60 17 fa 1a 67 aa 45 51  02 01 1a 02 0a 09 0a ff  `...g.EQ........
0x0010:  4c 00 10 05 06 18 be 7b  76                       L......{v

1. Company ID: 0a ff 4c 00 ...
• 0xFF: Manufacturer Specific Data (MSD)
• 0x004C (4C 00): Apple, Inc.
2. Apple Continuity Sub-Type: 10
• 0x10: Nearby Info message (apple_message_types[0x10])
3. Length: 05 (5 bytes of Nearby Info data follow)
4. Status & Action Byte: 06 (defined in NearbyInfoMessage)
• Action Code (high 4 bits, 0x06 >> 4 = 0x0): Activity level is not known
• Status Flags (low 4 bits, 0x06 & 0x0F = 0x6):
• Bit 0x01: Primary iCloud device
• Bit 0x04 (0b0100): AirDrop receive enabled
(Any status byte where (byte & 0x04) != 0 indicates AirDrop receiving is enabled).


──────
### Method 1: Using TShark with sniffle_extcap.py

As documented in TSHARK.md, Wireshark dissects BLE advertising data under btcommon.eir_ad. In Wireshark's display filter:
• Apple Company ID: btcommon.eir_ad.entry.company_id == 0x004c
• Nearby Info Sub-Type: btcommon.eir_ad.entry.data[0] == 0x10
• AirDrop Receive Enabled bit: btcommon.eir_ad.entry.data[2] & 0x04 == 0x04
#### 1. Live Terminal Stream (Filtered)
To capture live packets on advertising channel 37 and only display matching AirDrop packets:
```bash
tshark -i sniffle \
	-o "extcap.sniffle.serport:/dev/ttyUSB0" \
	-o "extcap.sniffle.mode:passive_scan" \
	-o "extcap.sniffle.advchan:37" \
	-Y "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04"
```
#### 2. Live Capture with Verbose Dissection & Hex Dump

To view the full dissection tree and hex dump (matching your example):
```bash
tshark -i sniffle \
	-o "extcap.sniffle.serport:/dev/ttyUSB0" \
	-o "extcap.sniffle.mode:passive_scan" \
	-o "extcap.sniffle.advchan:37" \
	-Y "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04" \
	-V -x
```

#### 3. Filtering an Existing PCAP Capture to a New File

Because TShark write mode (-w) records all packets coming from an extcap interface, capture live to a file first and then extract the matching
AirDrop packets using a two-pass read filter (-2 -R):

# 1. Capture live
```bash
tshark -i sniffle \
	-o "extcap.sniffle.serport:/dev/ttyUSB0" \
	-o "extcap.sniffle.mode:passive_scan" \
	-o "extcap.sniffle.advchan:37" \
	-w /tmp/all_ads.pcap
```
# 2. Extract only AirDrop receive enabled packets into a clean PCAP
```bash
tshark -r /tmp/all_ads.pcap \
	-2 \
	-R "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04" \
	-w /tmp/airdrop_only.pcap
```
