import json
import sys
from typing import List, Tuple, Dict, Any, Optional
from .models import LinkSample


class StreamDemuxer:
    """
    Ingests raw packet streams (live serial or offline replay log) and demultiplexes
    samples into discrete RF links (rx_id, tx_mac).
    """
    def __init__(self, verbose: bool = True):
        self.samples_processed = 0
        self.verbose = verbose

    def process_sample(self, sample: LinkSample, port_name: Optional[str] = None) -> Tuple[Tuple[str, str], float, float]:
        self.samples_processed += 1
        link_key = (sample.rx_id, sample.tx_mac)
        
        if self.verbose:
            port_info = f" ({port_name})" if port_name else ""
            print(f"[PACKET #{self.samples_processed:04d} | {sample.rx_id}{port_info}] "
                  f"Timestamp: {sample.timestamp:.3f}s | Tx MAC: {sample.tx_mac} | "
                  f"RSSI: {sample.rssi:.1f} dBm | Ch: {sample.channel}")
            sys.stdout.flush()

        return link_key, sample.rssi, sample.timestamp

    def load_json_replay(self, filepath: str) -> List[LinkSample]:
        """
        Loads pre-recorded packet log JSON file containing a list of sample dicts:
        [{"timestamp": float, "rssi": float, "rx_id": str, "tx_mac": str, "channel": int}]
        """
        with open(filepath, "r") as f:
            raw_data = json.load(f)

        samples: List[LinkSample] = []
        for item in raw_data:
            samples.append(
                LinkSample(
                    timestamp=float(item["timestamp"]),
                    rssi=float(item["rssi"]),
                    rx_id=str(item["rx_id"]),
                    tx_mac=str(item["tx_mac"]),
                    channel=int(item.get("channel", 37))
                )
            )
        return samples
