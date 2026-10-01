"""Unit tests for MockSerialInterface, VirtualRadioBus, port discovery, and SniffleDeviceController."""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from bluetooth_sniffle.device.controller import SniffleDeviceController
from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.device.serial_port import (
    CATSNIFFER_PID,
    CATSNIFFER_VID,
    SONOFF_PID,
    SONOFF_VID,
    TI_XDS110_PID,
    TI_XDS110_VID,
    allocate_dual_ports,
    is_cp2102_non_n,
    is_sniffle_device,
)
from bluetooth_sniffle.protocol.wire import (
    COMMAND_MARKER,
    COMMAND_SETCHANAAPHY,
    COMMAND_VERSION,
    MESSAGE_BLEFRAME,
    MESSAGE_MARKER,
    MESSAGE_MEASURE,
    MESSAGE_STATE,
    STATE_ADVERTISING,
    STATE_STATIC,
    PacketMessage,
    decode_msg,
    encode_cmd,
)


class TestMockSerialInterface:
    """Tests for MockSerialInterface buffering, threading, and operations."""

    def test_basic_read_write(self) -> None:
        ser = MockSerialInterface(port="mock://test", timeout=0.1)
        assert ser.is_open
        assert ser.in_waiting == 0

        ser.inject_rx_bytes(b"hello\r\n")
        assert ser.in_waiting == 7

        line = ser.readline()
        assert line == b"hello\r\n"
        assert ser.in_waiting == 0

    def test_read_chunking(self) -> None:
        ser = MockSerialInterface(timeout=0.1)
        ser.inject_rx_bytes(b"0123456789")

        c1 = ser.read(4)
        assert c1 == b"0123"
        c2 = ser.read(6)
        assert c2 == b"456789"
        c3 = ser.read(2)
        assert c3 == b""

    def test_cancel_read(self) -> None:
        ser = MockSerialInterface(timeout=5.0)

        def canceller():
            time.sleep(0.05)
            ser.cancel_read()

        t = threading.Thread(target=canceller)
        t.start()
        start = time.monotonic()
        res = ser.read(10)
        elapsed = time.monotonic() - start

        assert res == b""
        assert elapsed < 1.0
        t.join()

    def test_close_unblocks_readers(self) -> None:
        ser = MockSerialInterface(timeout=5.0)

        def closer():
            time.sleep(0.05)
            ser.close()

        t = threading.Thread(target=closer)
        t.start()
        res = ser.readline()
        assert res == b""
        assert not ser.is_open
        t.join()

    def test_write_closed_raises(self) -> None:
        ser = MockSerialInterface()
        ser.close()
        with pytest.raises(RuntimeError, match="closed"):
            ser.write(b"data")

    def test_reset_buffers(self) -> None:
        ser = MockSerialInterface()
        ser.inject_rx_bytes(b"buffer data")
        assert ser.in_waiting > 0
        ser.reset_input_buffer()
        assert ser.in_waiting == 0


class TestVirtualRadioBus:
    """Tests for VirtualRadioBus command routing, channel filtering, and responses."""

    def test_marker_echo(self) -> None:
        bus = VirtualRadioBus()
        ser = MockSerialInterface(bus=bus, timeout=0.5)

        token = b"\xde\xad\xbe\xef"
        ser.write(encode_cmd([COMMAND_MARKER, *token]))

        line = ser.readline()
        assert line != b""
        _word_cnt, msg_type, body = decode_msg(line)
        assert msg_type == MESSAGE_MARKER
        assert body[4:] == token

    def test_version_query(self) -> None:
        bus = VirtualRadioBus()
        ser = MockSerialInterface(bus=bus, timeout=0.5)

        ser.write(encode_cmd([COMMAND_VERSION]))
        line = ser.readline()
        assert line != b""
        _, msg_type, body = decode_msg(line)
        assert msg_type == MESSAGE_MEASURE
        assert body[0] == 4  # length
        assert body[1] == 5  # MEASUREMENT_VERSION
        assert body[2:6] == bytes([1, 8, 0, 1])

    def test_set_channel(self) -> None:
        bus = VirtualRadioBus()
        ser = MockSerialInterface(bus=bus, timeout=0.5)

        ser.write(encode_cmd([COMMAND_SETCHANAAPHY, 38, 0xD6, 0xBE, 0x89, 0x8E, 0, 0x55, 0x55, 0x55]))
        line = ser.readline()
        assert line != b""
        _, msg_type, body = decode_msg(line)
        assert msg_type == MESSAGE_STATE
        assert body[0] == STATE_STATIC

        st = bus.get_state(ser)
        assert st is not None
        assert st.channel == 38

    def test_advertising_broadcast_delivery(self) -> None:
        bus = VirtualRadioBus()
        dev_tx = MockSerialInterface(port="mock://tx", bus=bus, timeout=0.5)
        dev_rx37 = MockSerialInterface(port="mock://rx37", bus=bus, timeout=0.5)
        dev_rx38 = MockSerialInterface(port="mock://rx38", bus=bus, timeout=0.5)

        # Tune dev_rx37 to Ch 37 and dev_rx38 to Ch 38
        st37 = bus.get_state(dev_rx37)
        assert st37 is not None
        st37.channel = 37

        st38 = bus.get_state(dev_rx38)
        assert st38 is not None
        st38.channel = 38

        # Configure Dev TX MAC
        mac = bytes.fromhex("c011222211c0")
        dev_tx.write(encode_cmd([0x1B, 1, *mac]))

        # Broadcast advertisement on Ch 37 only
        ad_data = bytes([0x02, 0x01, 0x06])
        padded_adv = [len(ad_data), *ad_data] + [0] * (31 - len(ad_data))
        padded_scan = [0] * 32
        # Command 0x1C ADVERTISE
        dev_tx.write(encode_cmd([0x1C, 2, *padded_adv, *padded_scan]))

        # Dev TX gets state notification
        line_tx = dev_tx.readline()
        _, mtype_tx, body_tx = decode_msg(line_tx)
        assert mtype_tx == MESSAGE_STATE
        assert body_tx[0] == STATE_ADVERTISING

        # Dev RX37 must receive the broadcast BLE frame
        line_rx = dev_rx37.readline()
        assert line_rx != b""
        _, mtype_rx, body_rx = decode_msg(line_rx)
        assert mtype_rx == MESSAGE_BLEFRAME
        pkt = PacketMessage(body_rx)
        assert pkt.chan == 37
        assert mac in pkt.body  # AdvA in body

        # Dev RX38 also receives on Ch 38 because broadcast spans (37, 38, 39)
        line_rx38 = dev_rx38.readline()
        assert line_rx38 != b""
        _, mtype_rx38, body_rx38 = decode_msg(line_rx38)
        assert mtype_rx38 == MESSAGE_BLEFRAME
        pkt38 = PacketMessage(body_rx38)
        assert pkt38.chan == 38

    def test_single_channel_direct_delivery(self) -> None:
        """Test deliver_raw_packet only reaches devices matching the channel."""
        bus = VirtualRadioBus()
        dev_rx37 = MockSerialInterface(port="mock://rx37", bus=bus, timeout=0.1)
        dev_rx38 = MockSerialInterface(port="mock://rx38", bus=bus, timeout=0.1)

        bus.get_state(dev_rx37).channel = 37
        bus.get_state(dev_rx38).channel = 38

        # Deliver packet specifically on Channel 37
        bus.deliver_raw_packet(pdu=b"\x00\x06\x11\x22\x33\x44\x55\x66", chan=37)

        # dev_rx37 gets it
        line37 = dev_rx37.readline()
        assert line37 != b""

        # dev_rx38 does NOT get it (timed out reading empty)
        line38 = dev_rx38.readline()
        assert line38 == b""


class TestSniffleDeviceController:
    """Tests for SniffleDeviceController state, asynchronous queues, and commands."""

    def test_controller_open_close(self) -> None:
        bus = VirtualRadioBus()
        ctrl = SniffleDeviceController(port="mock://dev", mock=True, bus=bus)
        assert not ctrl.is_open

        ctrl.open()
        assert ctrl.is_open
        ctrl.close()
        assert not ctrl.is_open

    def test_controller_context_manager(self) -> None:
        bus = VirtualRadioBus()
        with SniffleDeviceController(port="mock://ctx", mock=True, bus=bus) as ctrl:
            assert ctrl.is_open
        assert not ctrl.is_open

    def test_controller_mark_and_flush(self) -> None:
        bus = VirtualRadioBus()
        with SniffleDeviceController(port="mock://sync", mock=True, bus=bus) as ctrl:
            success = ctrl.mark_and_flush(timeout=0.5)
            assert success is True

    def test_controller_get_version(self) -> None:
        bus = VirtualRadioBus()
        with SniffleDeviceController(port="mock://ver", mock=True, bus=bus) as ctrl:
            ver = ctrl.get_firmware_version(timeout=0.5)
            assert ver == (1, 8, 0, 1)

    def test_controller_set_mac_and_power(self) -> None:
        bus = VirtualRadioBus()
        with SniffleDeviceController(port="mock://cfg", mock=True, bus=bus) as ctrl:
            ctrl.set_mac_address("C0:11:22:22:11:C0", is_random=True)
            assert ctrl.mac_address == bytes.fromhex("c011222211c0")
            assert ctrl.is_random_mac is True

            ctrl.set_tx_power(5)
            assert ctrl.tx_power == 5

    def test_controller_advertising_and_sniffing(self) -> None:
        bus = VirtualRadioBus()
        tx = SniffleDeviceController(port="mock://tx", mock=True, bus=bus)
        rx = SniffleDeviceController(port="mock://rx", mock=True, bus=bus)

        tx.open()
        rx.open()

        rx.start_sniffing(chan=37, hop=False)
        assert rx.is_sniffing
        assert rx.channel == 37

        mac = bytes.fromhex("c011222211c0")
        tx.set_mac_address(mac, is_random=True)
        adv_payload = bytes([0x02, 0x01, 0x06, 0x05, 0x09, 0x54, 0x65, 0x73, 0x74])
        tx.configure_advertising(adv_data=adv_payload, interval_ms=50, mode=2)
        assert tx.is_advertising

        # Read packet on RX
        pkt = rx.read_packet(timeout=1.0)
        assert pkt is not None
        assert isinstance(pkt, PacketMessage)
        assert pkt.chan == 37
        assert mac in pkt.body

        # Batch read returns empty or list
        batch = rx.read_packets_batch(max_count=10, timeout=0.05)
        assert isinstance(batch, list)

        tx.close()
        rx.close()


class TestHardwareSerialPortDiscovery:
    """Tests for VID/PID autodetection, CP2102 capping, and dual-port allocation."""

    def test_is_sniffle_device(self) -> None:
        port_sonoff = MagicMock(vid=SONOFF_VID, pid=SONOFF_PID, description="Sonoff Dongle Plus", product="Dongle")
        assert is_sniffle_device(port_sonoff) is True

        port_ti = MagicMock(vid=TI_XDS110_VID, pid=TI_XDS110_PID, description="XDS110 Debug Probe", product="")
        assert is_sniffle_device(port_ti) is True

        port_catsniffer = MagicMock(vid=CATSNIFFER_VID, pid=CATSNIFFER_PID, description="CatSniffer", product="")
        assert is_sniffle_device(port_catsniffer) is True

        port_generic = MagicMock(vid=0x1234, pid=0x5678, description="Generic USB", product="")
        assert is_sniffle_device(port_generic) is False

    def test_cp2102_baud_capping(self) -> None:
        port_non_n = MagicMock(description="CP2102 USB to UART Bridge", product="Sonoff")
        assert is_cp2102_non_n(port_non_n) is True

        port_n = MagicMock(description="Silicon Labs CP2102N USB to UART Bridge Controller", product="CP2102N")
        assert is_cp2102_non_n(port_n) is False

    def test_allocate_dual_ports_explicit_distinct(self) -> None:
        p1, p2 = allocate_dual_ports("/dev/ttyUSB0", "/dev/ttyUSB1")
        assert p1 == "/dev/ttyUSB0"
        assert p2 == "/dev/ttyUSB1"

    def test_allocate_dual_ports_explicit_identical_raises(self) -> None:
        with pytest.raises(ValueError, match="Conflicting port allocation"):
            allocate_dual_ports("/dev/ttyUSB0", "/dev/ttyUSB0")

    @patch("bluetooth_sniffle.device.serial_port.discover_sniffle_ports")
    def test_allocate_dual_ports_auto_discovery(self, mock_discover: MagicMock) -> None:
        mock_discover.return_value = ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2"]
        p1, p2 = allocate_dual_ports()
        assert p1 == "/dev/ttyUSB0"
        assert p2 == "/dev/ttyUSB1"

    @patch("bluetooth_sniffle.device.serial_port.discover_sniffle_ports")
    def test_allocate_dual_ports_insufficient_raises(self, mock_discover: MagicMock) -> None:
        mock_discover.return_value = ["/dev/ttyUSB0"]
        with pytest.raises(RuntimeError, match="requires 2 Sniffle dongles"):
            allocate_dual_ports()
