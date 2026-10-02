"""Unit tests for Stimulus-Response Correlation Engine (PoPETs 2025-0103)."""

import pytest

from bluetooth_sniffle.sniff.correlation import (
    StimulusResponseCorrelator,
)
from bluetooth_sniffle.sniff.dissector import DissectedBleFrame


class TestStimulusRegistration:
    """Tests registration and indexing of active stimuli bursts."""

    def test_register_single_stimulus(self):
        correlator = StimulusResponseCorrelator()
        stim = correlator.register_stimulus(
            adv_a="c0:11:22:22:11:c0",
            beacon_type="iBeacon",
            burst_id=1,
            start_time_usec=1_000_000,
            duration_usec=5_000_000,
            channel=37,
        )

        assert stim.burst_id == 1
        assert stim.adv_a == "C0:11:22:22:11:C0"
        assert stim.adv_a_raw == bytes.fromhex("c011222211c0")
        assert stim.beacon_type == "iBeacon"
        assert stim.start_time_usec == 1_000_000
        assert stim.duration_usec == 5_000_000
        assert stim.channel == 37

    def test_register_multiple_stimuli(self):
        correlator = StimulusResponseCorrelator()
        s1 = correlator.register_stimulus(
            adv_a="c0:11:22:22:11:c0",
            beacon_type="iBeacon",
            burst_id=1,
            start_time_usec=1_000_000,
        )
        s2 = correlator.register_stimulus(
            adv_a="c0:33:44:44:33:c0",
            beacon_type="AltBeacon",
            burst_id=2,
            start_time_usec=6_000_000,
        )

        assert len(correlator._stimuli) == 2
        assert correlator._stimuli_by_id[s1.stimulus_id] == s1
        assert correlator._stimuli_by_id[s2.stimulus_id] == s2
        assert len(correlator._stimuli_by_mac["C0:11:22:22:11:C0"]) == 1

    def test_invalid_mac_raises(self):
        correlator = StimulusResponseCorrelator()
        with pytest.raises(ValueError):
            correlator.register_stimulus(adv_a="invalid_mac")
        with pytest.raises(ValueError):
            correlator.register_stimulus(adv_a=b"\x00" * 5)


class TestScanReqCorrelation:
    """Tests matching of incoming elicitations against active stimuli."""

    def test_matching_scan_req(self):
        correlator = StimulusResponseCorrelator()
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            beacon_type="iBeacon",
            burst_id=1,
            start_time_usec=1_000_000,
            duration_usec=5_000_000,
        )

        # Scanner issues SCAN_REQ probing our stimulus MAC
        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            scan_a_raw=bytes.fromhex("40aabbccdd40"),
            scan_a_type="RPA",
            adv_a="C0:11:22:22:11:C0",
            adv_a_raw=bytes.fromhex("c011222211c0"),
            adv_a_type="Random Static",
            channel=37,
            rssi=-62,
            timestamp_usec=1_250_000,
        )

        match = correlator.process_frame(frame)
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.stimulus_adv_a == "C0:11:22:22:11:C0"
        assert match.responder_mac == "40:AA:BB:CC:DD:40"
        assert match.responder_type == "RPA"
        assert match.response_pdu_type == "SCAN_REQ"
        assert match.latency_usec == 250_000
        assert match.latency_ms == 250.0
        assert match.channel == 37
        assert match.rssi == -62

    def test_unrelated_scan_req_ignored(self):
        correlator = StimulusResponseCorrelator()
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            beacon_type="iBeacon",
            start_time_usec=1_000_000,
        )

        # SCAN_REQ targeting someone else
        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            adv_a="FF:EE:DD:CC:BB:AA",
            timestamp_usec=1_200_000,
        )

        match = correlator.process_frame(frame)
        assert match is None

    def test_matching_connect_ind(self):
        correlator = StimulusResponseCorrelator()
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            beacon_type="iBeacon",
            start_time_usec=1_000_000,
        )

        frame = DissectedBleFrame(
            pdu_type="CONNECT_IND",
            pdu_type_id=0x05,
            tx_add=1,
            rx_add=1,
            length=34,
            init_a="50:60:70:80:90:A0",
            init_a_raw=bytes.fromhex("5060708090a0"),
            init_a_type="RPA",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=1_100_000,
        )

        match = correlator.process_frame(frame)
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.responder_mac == "50:60:70:80:90:A0"
        assert match.latency_ms == 100.0

    def test_process_frames_batch(self):
        correlator = StimulusResponseCorrelator()
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=1_000_000,
        )

        f1 = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:01",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=1_100_000,
        )
        f2 = DissectedBleFrame(
            pdu_type="ADV_IND",
            pdu_type_id=0x00,
            tx_add=0,
            rx_add=0,
            length=10,
            adv_a="99:88:77:66:55:44",
            timestamp_usec=1_150_000,
        )
        f3 = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:02",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=1_200_000,
        )

        matches = correlator.process_frames([f1, f2, f3])
        assert len(matches) == 2
        assert matches[0].responder_mac == "40:AA:BB:CC:DD:01"
        assert matches[1].responder_mac == "40:AA:BB:CC:DD:02"


class TestTimingWindowsAndThresholds:
    """Tests latency window limits, clock jitter tolerance, and modulo-32 wrap."""

    def test_post_burst_latency_margin(self):
        """Response arriving within max_latency_usec after burst end correlates."""
        correlator = StimulusResponseCorrelator(max_latency_usec=2_000_000)
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=1_000_000,
            duration_usec=5_000_000,  # ends at 6_000_000, max allowed is 8_000_000
        )

        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=7_500_000,
        )

        match = correlator.process_frame(frame)
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.latency_usec == 6_500_000

    def test_expired_response_ignored(self):
        """Response arriving after burst end + max_latency_usec returns None."""
        correlator = StimulusResponseCorrelator(max_latency_usec=2_000_000)
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=1_000_000,
            duration_usec=5_000_000,  # window ends at 8_000_000
        )

        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=8_500_000,  # 8.5s > 8.0s
        )

        match = correlator.process_frame(frame)
        assert match is None

    def test_clock_jitter_tolerance(self):
        """Slightly negative latency (within clock_tolerance_usec) clamped to 0."""
        correlator = StimulusResponseCorrelator(clock_tolerance_usec=200_000)
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=1_000_000,
        )

        # Response timestamp is 50ms before stimulus timestamp due to host buffer jitter
        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=950_000,
        )

        match = correlator.process_frame(frame)
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.latency_usec == 0
        assert match.latency_ms == 0.0

    def test_modulo_32_timestamp_wraparound(self):
        """Hardware 32-bit timestamp wrapping past 2^32 correctly correlates."""
        correlator = StimulusResponseCorrelator()
        stim = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=4_294_960_000,  # Near 2^32 (4_294_967_296)
            duration_usec=5_000_000,
        )

        # Response arrived after counter wrapped around to 10_000
        # Expected delta: (10_000 - 4_294_960_000) & 0xFFFFFFFF = 17_296 us
        frame = DissectedBleFrame(
            pdu_type="SCAN_REQ",
            pdu_type_id=0x03,
            tx_add=1,
            rx_add=1,
            length=12,
            scan_a="40:AA:BB:CC:DD:40",
            adv_a="C0:11:22:22:11:C0",
            timestamp_usec=10_000,
        )

        match = correlator.process_frame(frame)
        assert match is not None
        assert match.stimulus_id == stim.stimulus_id
        assert match.latency_usec == 17_296


class TestSummaryAnalytics:
    """Tests summary statistics, distribution calculation, and export format."""

    def test_summary_calculation(self):
        correlator = StimulusResponseCorrelator()

        # Register 10 stimuli
        for i in range(10):
            correlator.register_stimulus(
                adv_a=f"C0:11:22:22:11:{i:02X}",
                beacon_type="iBeacon" if i % 2 == 0 else "AltBeacon",
                burst_id=i,
                start_time_usec=i * 10_000_000,
            )

        # Stimulate responses for 8 of them from 5 unique devices
        responders = [
            "40:AA:BB:CC:DD:01",
            "40:AA:BB:CC:DD:02",
            "40:AA:BB:CC:DD:03",
            "40:AA:BB:CC:DD:04",
            "40:AA:BB:CC:DD:05",
        ]

        for i in range(8):
            responder_mac = responders[i % len(responders)]
            frame = DissectedBleFrame(
                pdu_type="SCAN_REQ",
                pdu_type_id=0x03,
                tx_add=1,
                rx_add=1,
                length=12,
                scan_a=responder_mac,
                scan_a_type="RPA",
                adv_a=f"C0:11:22:22:11:{i:02X}",
                timestamp_usec=(i * 10_000_000) + 100_000 * (i + 1),
            )
            correlator.process_frame(frame)

        summary = correlator.get_summary()
        assert summary.total_stimuli == 10
        assert summary.total_responses == 8
        assert summary.correlated_stimuli_count == 8
        assert summary.response_rate_percent == 80.0
        assert summary.unique_responders_count == 5
        assert summary.responder_type_distribution == {"RPA": 8}
        assert summary.min_latency_ms == 100.0
        assert summary.max_latency_ms == 800.0
        assert summary.avg_latency_ms == 450.0

    def test_zero_responses_no_divide_by_zero(self):
        correlator = StimulusResponseCorrelator()
        summary = correlator.get_summary()
        assert summary.total_stimuli == 0
        assert summary.total_responses == 0
        assert summary.response_rate_percent == 0.0
        assert summary.min_latency_ms is None
        assert summary.max_latency_ms is None
        assert summary.avg_latency_ms is None

    def test_export_summary_dict(self):
        correlator = StimulusResponseCorrelator()
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            beacon_type="iBeacon",
            start_time_usec=1_000_000,
        )
        d = correlator.export_summary_dict()
        assert "total_stimuli" in d
        assert "total_responses" in d
        assert "response_rate_percent" in d
        assert "unique_responders_count" in d
        assert "latency_ms" in d
        assert d["total_stimuli"] == 1
        assert d["total_responses"] == 0

    def test_reset_and_evict_expired(self):
        correlator = StimulusResponseCorrelator(history_retention_sec=10.0)
        correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=1_000_000,  # 1.0s
        )
        s2 = correlator.register_stimulus(
            adv_a="C0:11:22:22:11:C0",
            start_time_usec=20_000_000,  # 20.0s
        )
        assert len(correlator._stimuli) == 2

        # Evict at current time 25.0s (retention 10s -> cutoff 15s)
        evicted = correlator.evict_expired(current_time_usec=25_000_000)
        assert evicted == 1
        assert len(correlator._stimuli) == 1
        assert correlator._stimuli[0].stimulus_id == s2.stimulus_id

        correlator.reset()
        assert len(correlator._stimuli) == 0
        assert len(correlator._matches) == 0
