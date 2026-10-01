# Filtering Wireshark BLE JSON with JQ

This guide explains how to parse and extract Bluetooth Low Energy (BLE) packet data from Wireshark/TShark JSON exports (`tshark -T json`) using `jq`.

---

## 1. Showing the Entire Packet When `device_name` is Present

### A. Match Packets Where `device_name` is Present Anywhere
This matches packets where the device name appears either in the primary advertisement (`ADV_IND`) or in the scan response (`SCAN_RSP`):

```bash
jq '.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/json
```

### B. Match Packets Where `device_name` is in `scan_response_data_tree` Only
If you only want packets where the device name came specifically from the scan response payload:

```bash
jq '.[] | select(._source.layers.btle["btle.scan_response_data_tree"]? | .. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/json
```

---

## 2. Output Formatting Options

### Keep Output as a Valid JSON Array
By default, `jq .[] | select(...)` streams standalone JSON objects. Wrap the expression in brackets `[...]` to output a single valid JSON array:

```bash
jq '[.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)]' /tmp/json
```

### Strip Elasticsearch/Metadata Wrappers (Show Only `layers`)
Wireshark JSON wraps each packet in `_index`, `_type`, `_score`, and `_source`. To output only the dissected packet layers:

```bash
jq '.[]._source.layers | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/json
```

### Interactive Colored Paging
To browse matching full packets with syntax highlighting in your terminal:

```bash
jq -C '.[] | select(.. | ."btcommon.eir_ad.entry.device_name"? != null)' /tmp/json | less -R
```

---

## 3. Extracting Device Names

### From Scan Responses Only
```bash
# Using recursive search within the scan response tree
jq -r '.[]._source.layers.btle["btle.scan_response_data_tree"]? | .. | ."btcommon.eir_ad.entry.device_name"? // empty' /tmp/json

# Or using the explicit hierarchical path
jq -r '.[]._source.layers.btle["btle.scan_response_data_tree"]["btcommon.eir_ad.advertising_data"]["btcommon.eir_ad.entry"]["btcommon.eir_ad.entry.device_name"] // empty' /tmp/json
```

### Unique Device Names Across All Packets
```bash
jq -r '.. | ."btcommon.eir_ad.entry.device_name"? // empty' /tmp/json | sort -u
```

### Pair Advertising Address with Device Name
```bash
jq -r '.[]._source.layers.btle | select(.. | ."btcommon.eir_ad.entry.device_name"? != null) | "\(.["btle.advertising_address"]): \(.. | ."btcommon.eir_ad.entry.device_name"? // empty)"' /tmp/json | sort -u
```

---

## 4. Key Lessons & Common Pitfalls

1. **Dots in JSON Key Names**: Wireshark fields contain literal periods (e.g. `btcommon.eir_ad.entry.device_name`). In `jq`, accessing these require quotes/bracket indexing:
   - `."btcommon.eir_ad.entry.device_name"` or `["btcommon.eir_ad.entry.device_name"]`
   - Escaping with backslashes like `btle\.scan_response_data_tree` will result in a `jq: error: syntax error`.
2. **Null Traversal**: Packets that do not contain the target field evaluate to `null`. Always use `?` (optional indexing) or `// empty` to prevent runtime indexing errors on null objects.
3. **Hierarchy**: In BLE captures, advertising entries reside inside `btcommon.eir_ad.advertising_data` -> `btcommon.eir_ad.entry`. Using recursive descent (`..`) makes searches resilient against structural variations.
