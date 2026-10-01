"""Unit tests for Sniffle wire protocol serialization, Base64 framing, and message decoding."""

import base64
from struct import pack

import pytest

from bluetooth_sniffle.protocol.wire import (
    COMMAND_RESET,
    MEASUREMENT_VERSION,
    MESSAGE_BLEFRAME,
    MESSAGE_DEBUG,
    MESSAGE_MARKER,
    MESSAGE_MEASURE,
    MESSAGE_STATE,
    PHY_1M,
    PHY_2M,
    PHY_CODED_S2,
    PHY_CODED_S8,
    STATE_ADVERTISING,
    STATE_STATIC,
    DebugMessage,
    MarkerMessage,
    MeasurementMessage,
    PacketMessage,
    StateMessage,
    decode_msg,
    encode_cmd,
    encode_msg,
    parse_sniffle_message,
)


class TestWireFraming:
    """Tests for Base64+CRLF command and response line framing."""

    def test_encode_cmd_basic(self) -> None:
        """Test encoding of basic commands into Base64+CRLF."""
        # 1-byte command (e.g. RESET 0x17)
        # len=1 -> b0 = (1 + 3) // 3 = 1
        # raw = bytes([1, 0x17]) = b'\x01\x17'
        cmd_wire = encode_cmd([COMMAND_RESET])
        assert cmd_wire.endswith(b"\r\n")

        raw_b64 = cmd_wire.rstrip(b"\r\n")
        decoded = base64.b64decode(raw_b64)
        assert decoded[0] == 1  # word_cnt b0
        assert decoded[1] == COMMAND_RESET

    def test_encode_cmd_word_count_calculation(self) -> None:
        """Test word count prefix calculation across various command lengths."""
        for length in [1, 2, 3, 4, 10, 31, 65]:
            dummy_bytes = bytes([0x55] * length)
            wire = encode_cmd(dummy_bytes)
            assert wire.endswith(b"\r\n")

            decoded = base64.b64decode(wire.rstrip(b"\r\n"))
            expected_b0 = (length + 3) // 3
            assert decoded[0] == expected_b0
            assert decoded[1:] == dummy_bytes

    def test_decode_msg_success(self) -> None:
        """Test decoding valid dongle-to-host Base64 lines."""
        # Dongle payload: word_cnt=2, msg_type=0x13, state=0x08
        payload = bytes([2, MESSAGE_STATE, STATE_ADVERTISING])
        wire = base64.b64encode(payload) + b"\r\n"

        word_cnt, msg_type, body = decode_msg(wire)
        assert word_cnt == 2
        assert msg_type == MESSAGE_STATE
        assert body == bytes([STATE_ADVERTISING])

    def test_decode_msg_whitespace_tolerance(self) -> None:
        """Test that decode_msg handles leading/trailing whitespace and Unix newlines."""
        payload = bytes([1, MESSAGE_DEBUG, 0x41])
        wire = b"   " + base64.b64encode(payload) + b"\n"
        word_cnt, _msg_type, body = decode_msg(wire)
        assert word_cnt == 1
        assert body == b"A"

    def test_decode_msg_empty_error(self) -> None:
        """Test that empty or whitespace-only lines raise ValueError."""
        with pytest.raises(ValueError, match="Cannot decode empty wire line"):
            decode_msg(b"   \r\n")

    def test_decode_msg_malformed_base64(self) -> None:
        """Test that corrupted Base64 strings raise ValueError."""
        with pytest.raises(ValueError, match="Malformed Base64 line"):
            decode_msg(b"!!!NotBase64???\r\n")

    def test_decode_msg_too_short(self) -> None:
        """Test that decoded payloads shorter than 2 bytes raise ValueError."""
        # 1 single byte
        short_b64 = base64.b64encode(b"\x01") + b"\r\n"
        with pytest.raises(ValueError, match="too short"):
            decode_msg(short_b64)

    def test_encode_msg_round_trip(self) -> None:
        """Test encode_msg generates valid wire frames that decode_msg parses."""
        sample_body = b"HelloWorld123"
        wire = encode_msg(MESSAGE_DEBUG, sample_body)
        assert wire.endswith(b"\r\n")

        word_cnt, msg_type, body = decode_msg(wire)
        expected_word_cnt = (len(sample_body) + 4) // 3
        assert word_cnt == expected_word_cnt
        assert msg_type == MESSAGE_DEBUG
        assert body == sample_body


class TestPacketMessage:
    """Tests for PacketMessage (MESSAGE_BLEFRAME) header unpacking and packing."""

    def test_packet_message_unpack_fields(self) -> None:
        """Test bit-exact unpacking of 10-byte hardware header."""
        pdu = bytes([0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02])
        ts = 2_500_000
        event = 42
        rssi = -65
        chan = 37
        phy = PHY_1M

        l_field = len(pdu) & 0x3FFF
        chan_phy = (chan & 0x3F) | ((phy & 0x03) << 6)
        raw_hdr = pack("<LHHbB", ts, l_field, event, rssi, chan_phy)
        raw_msg = raw_hdr + pdu

        pkt = PacketMessage(raw_msg)
        assert pkt.ts == ts
        assert pkt.pkt_dir == 0
        assert pkt.direction == 0
        assert pkt.crc_err is False
        assert pkt.event == event
        assert pkt.rssi == rssi
        assert pkt.chan == 37
        assert pkt.phy == PHY_1M
        assert pkt.body == pdu
        assert pkt.raw == raw_msg

    def test_packet_message_crc_err_and_direction_flags(self) -> None:
        """Test flag bit unpacking for CRC error and Peripheral->Central direction."""
        pdu = b"\x02\x00"
        ts = 100_000
        raw_body = PacketMessage.pack(
            body=pdu,
            ts=ts,
            chan=38,
            rssi=-72,
            phy=PHY_2M,
            event=12,
            crc_err=True,
            direction=1,
        )

        pkt = PacketMessage(raw_body)
        assert pkt.crc_err is True
        assert pkt.direction == 1
        assert pkt.pkt_dir == 1
        assert pkt.chan == 38
        assert pkt.phy == PHY_2M
        assert pkt.rssi == -72
        assert pkt.body == pdu

    def test_packet_message_phy_modes(self) -> None:
        """Test unpacking of various PHY modes (1M, 2M, Coded S8, Coded S2)."""
        for phy_val in [PHY_1M, PHY_2M, PHY_CODED_S8, PHY_CODED_S2]:
            raw = PacketMessage.pack(body=b"\x00", chan=39, phy=phy_val)
            pkt = PacketMessage(raw)
            assert pkt.phy == phy_val
            assert pkt.chan == 39

    def test_packet_message_negative_rssi(self) -> None:
        """Test signed int8 RSSI range handling (-128 to 0 dBm)."""
        for rssi_val in [-128, -95, -60, -1, 0]:
            raw = PacketMessage.pack(body=b"\x00", rssi=rssi_val)
            pkt = PacketMessage(raw)
            assert pkt.rssi == rssi_val

    def test_packet_message_too_short_raises(self) -> None:
        """Test that PacketMessage with fewer than 10 bytes raises ValueError."""
        with pytest.raises(ValueError, match="PacketMessage body too short"):
            PacketMessage(bytes(9))


class TestAuxiliaryMessages:
    """Tests for Marker, State, Measurement, and Debug messages."""

    def test_marker_message_pack_unpack(self) -> None:
        """Test MarkerMessage serialization and deserialization."""
        token = b"\x12\x34\x56\x78"
        ts = 987_654
        raw = MarkerMessage.pack(marker_data=token, ts=ts)

        marker = MarkerMessage(raw)
        assert marker.ts == ts
        assert marker.marker_data == token

    def test_marker_message_short_raises(self) -> None:
        """Test that truncated MarkerMessage raises ValueError."""
        with pytest.raises(ValueError, match="MarkerMessage body too short"):
            MarkerMessage(bytes(3))

    def test_state_message_pack_unpack(self) -> None:
        """Test StateMessage serialization and deserialization."""
        raw = StateMessage.pack(STATE_STATIC)
        state_msg = StateMessage(raw)
        assert state_msg.state == STATE_STATIC

    def test_state_message_short_raises(self) -> None:
        """Test that empty StateMessage raises ValueError."""
        with pytest.raises(ValueError, match="StateMessage body too short"):
            StateMessage(b"")

    def test_measurement_message_version(self) -> None:
        """Test MeasurementMessage parsing of firmware version subtype."""
        raw = MeasurementMessage.pack_version(major=1, minor=8, revision=2, api_level=1)
        meas = MeasurementMessage(raw)
        assert meas.measure_type == MEASUREMENT_VERSION
        assert meas.version == (1, 8, 2, 1)

    def test_debug_message_pack_unpack(self) -> None:
        """Test DebugMessage text encoding and decoding."""
        text = "CC2652P Radio Ready"
        raw = DebugMessage.pack(text)
        debug_msg = DebugMessage(raw)
        assert debug_msg.text == text


class TestParseSniffleMessageDispatcher:
    """Tests for parse_sniffle_message dispatching across wire lines."""

    def test_dispatch_ble_frame(self) -> None:
        raw_pkt = PacketMessage.pack(body=b"\x00\x01\x02", chan=37, rssi=-55)
        wire = encode_msg(MESSAGE_BLEFRAME, raw_pkt)

        mtype, obj = parse_sniffle_message(wire)
        assert mtype == MESSAGE_BLEFRAME
        assert isinstance(obj, PacketMessage)
        assert obj.chan == 37
        assert obj.rssi == -55

    def test_dispatch_marker(self) -> None:
        raw_marker = MarkerMessage.pack(b"TEST", ts=100)
        wire = encode_msg(MESSAGE_MARKER, raw_marker)

        mtype, obj = parse_sniffle_message(wire)
        assert mtype == MESSAGE_MARKER
        assert isinstance(obj, MarkerMessage)
        assert obj.marker_data == b"TEST"

    def test_dispatch_state(self) -> None:
        wire = encode_msg(MESSAGE_STATE, StateMessage.pack(STATE_ADVERTISING))
        mtype, obj = parse_sniffle_message(wire)
        assert mtype == MESSAGE_STATE
        assert isinstance(obj, StateMessage)
        assert obj.state == STATE_ADVERTISING

    def test_dispatch_measure(self) -> None:
        wire = encode_msg(MESSAGE_MEASURE, MeasurementMessage.pack_version(1, 8, 0, 1))
        mtype, obj = parse_sniffle_message(wire)
        assert mtype == MESSAGE_MEASURE
        assert isinstance(obj, MeasurementMessage)
        assert obj.version == (1, 8, 0, 1)

    def test_dispatch_debug(self) -> None:
        wire = encode_msg(MESSAGE_DEBUG, DebugMessage.pack("Firmware started"))
        mtype, obj = parse_sniffle_message(wire)
        assert mtype == MESSAGE_DEBUG
        assert isinstance(obj, DebugMessage)
        assert "Firmware started" in obj.text
