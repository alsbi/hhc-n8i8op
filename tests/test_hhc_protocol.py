"""Tests for hhc_protocol.py — binary format conformance and safety guards.

Every test either:
  - Validates correct encoding/decoding of protocol fields
  - Protects against a known footgun (e.g. AT+STATUS=10)
"""

from __future__ import annotations

import struct
import pytest

# We test the module directly, no HA dependency
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "hhc_n8i8op"))

from hhc_protocol import (
    HHCDeviceConfig,
    parse_tlv,
    parse_search_response,
    AT_PORT,
    AT_SOURCE_PORT,
)


# ────────────────────────────────────────────────────────────────────────
# Real captured data from Wireshark (Tool.exe ↔ HHC-N8I8OP device)
# ────────────────────────────────────────────────────────────────────────

# Full SEARCH response payload (after UDP header, ~273 bytes useful + padding)
CAPTURED_SEARCH_RESPONSE_HEX = (
    "5345415243484950"     # SEARCHIP
    "c0a80069"             # 192.168.0.105
    "5355424e4554"         # SUBNET
    "ffffff00"             # 255.255.255.0
    "47415445574159"       # GATEWAY
    "c0a80001"             # 192.168.0.1
    "4d4143"               # MAC
    "485300575500"         # 48:53:00:57:55:00
    "52454d4f54454950"     # REMOTEIP
    "c0a80065"             # 192.168.0.101
    "4c4f43414c504f5254"   # LOCALPORT
    "1388"                 # 5000
    "52454d4f5445504f5254" # REMOTEPORT
    "1388"                 # 5000
    "4d4f4445"             # MODE
    "00"                   # 0 = TCP Server
    "44484350"             # DHCP
    "00"                   # 0 = Static
    "53455249414c504f5254" # SERIALPORT
    "05010000"             # raw bytes
    "4e414d45"             # NAME
    "0a"                   # len=10
    "4848432d4e3849384f50" # HHC-N8I8OP
    "00"                   # null terminator / padding
    "444e5341"             # DNSA
    "00"                   # empty
    "4d544350"             # MTCP
    "00"                   # 0
    "4845415254"           # HEART
    "00"                   # 0
    "4d455353414745"       # MESSAGE
    "0a"                   # len=10
    "4848432d4e3849384f50" # HHC-N8I8OP
    "4354494d45"           # CTIME
    "0000"                 # empty (2 null bytes)
    "494e4d4f4445"         # INMODE
    "00"                   # 0 = Unlinked
    "535441545553"         # STATUS
    "00"                   # 0
)

# Full write payload — Wireshark-verified from real Tool.exe traffic.
# Key format notes:
#   - MTCP: RAW BYTE \x00, NOT ASCII '0' — confirmed by Wireshark capture
#   - SERIALPORT: raw bytes \x05,\x01,\x00,\x00, with comma separators
#   - UDP uses length-based framing so null bytes are fine
CAPTURED_WRITE_PAYLOAD_HEX = (
    "41542b5345543d223139322e3136382e302e31303522"
    "41542b49503d223139322e3136382e302e31303522"
    "41542b5355424e45543d223235352e3235352e3235352e3022"
    "41542b474154455741593d223139322e3136382e302e3122"
    "41542b52454d4f544549503d223139322e3136382e302e31303122"
    "41542b4d41433d2234383533303035373535303022"
    "41542b4e414d453d2252454c415922"
    "41542b4d4f44453d30"
    "41542b53455249414c504f52543d052c012c002c002c"
    "41542b4c4f43414c504f52543d223530303022"
    "41542b52454d4f5445504f52543d223530303022"
    "41542b444843503d31"
    "41542b444e53413d2222"
    "41542b48454152543d223022"
    "41542b4d5443503d00"          # AT+MTCP=\x00 — RAW NULL BYTE! Wireshark-verified!
    "41542b4d4553534147453d224848432d4e3849384f5022"
    "41542b4354494d453d223022"
    "41542b494e4d4f44453d31"
    "41542b5354415455533d30"
    "41542b534156453d31"
)

# Search request packets
CAPTURED_SEARCH_0_HEX = (
    "41542b5345415243483d223022"      # AT+SEARCH="0"
)
CAPTURED_SEARCH_105_HEX = (
    "41542b5345415243483d2231303522"  # AT+SEARCH="105"
)
CAPTURED_READIP_HEX = (
    "41542b5245414449503d223139322e3136382e302e31303522"  # AT+READIP="192.168.0.105"
)


# ────────────────────────────────────────────────────────────────────────
# TLV Parser Tests
# ────────────────────────────────────────────────────────────────────────

class TestTLVParser:
    """Tests for parse_tlv() with real captured data."""

    def test_full_search_response(self):
        """Parse complete real SEARCH response — all fields must match."""
        data = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        tlv = parse_tlv(data)

        assert tlv["SEARCHIP"] == "192.168.0.105", f"SEARCHIP wrong: {tlv.get('SEARCHIP')}"
        assert tlv["SUBNET"] == "255.255.255.0", f"SUBNET wrong: {tlv.get('SUBNET')}"
        assert tlv["GATEWAY"] == "192.168.0.1", f"GATEWAY wrong: {tlv.get('GATEWAY')}"
        assert tlv["MAC"] == "485300575500", f"MAC wrong: {tlv.get('MAC')}"
        assert tlv["REMOTEIP"] == "192.168.0.101", f"REMOTEIP wrong: {tlv.get('REMOTEIP')}"
        assert tlv["LOCALPORT"] == 5000, f"LOCALPORT wrong: {tlv.get('LOCALPORT')}"
        assert tlv["REMOTEPORT"] == 5000, f"REMOTEPORT wrong: {tlv.get('REMOTEPORT')}"
        assert tlv["MODE"] == 0, f"MODE wrong: {tlv.get('MODE')}"
        assert tlv["DHCP"] == 0, f"DHCP wrong: {tlv.get('DHCP')}"
        assert tlv["SERIALPORT"] == "05010000", f"SERIALPORT wrong: {tlv.get('SERIALPORT')}"
        assert tlv["NAME"] == "HHC-N8I8OP", f"NAME wrong: {tlv.get('NAME')}"
        assert tlv["DNSA"] == "", f"DNSA wrong: {tlv.get('DNSA')!r}"
        assert tlv["MTCP"] == 0, f"MTCP wrong: {tlv.get('MTCP')}"
        assert tlv["HEART"] == 0, f"HEART wrong: {tlv.get('HEART')}"
        assert tlv["MESSAGE"] == "HHC-N8I8OP", f"MESSAGE wrong: {tlv.get('MESSAGE')}"
        assert tlv["CTIME"] == 0, f"CTIME wrong: {tlv.get('CTIME')!r}"
        assert tlv["INMODE"] == 0, f"INMODE wrong: {tlv.get('INMODE')}"
        assert tlv["STATUS"] == 0, f"STATUS wrong: {tlv.get('STATUS')}"

    def test_ip_fields_are_text_not_binary(self):
        """IP fields MUST be dotted-decimal strings, not raw ints."""
        data = bytes.fromhex("5345415243484950c0a80069")  # SEARCHIP + 192.168.0.105
        tlv = parse_tlv(data)
        assert isinstance(tlv["SEARCHIP"], str)
        assert tlv["SEARCHIP"] == "192.168.0.105"

    def test_port_fields_are_int_not_string(self):
        """Port fields MUST be integers."""
        data = bytes.fromhex("4c4f43414c504f52541388")  # LOCALPORT + 5000
        tlv = parse_tlv(data)
        assert isinstance(tlv["LOCALPORT"], int)
        assert tlv["LOCALPORT"] == 5000

    def test_mac_no_colons(self):
        """MAC MUST be stored without colons (matches AT+MAC= format)."""
        data = bytes.fromhex("4d4143485300575500")  # MAC + 48:53:00:57:55:00
        tlv = parse_tlv(data)
        assert ":" not in tlv["MAC"]
        assert tlv["MAC"] == "485300575500"

    def test_string_field_with_length_prefix(self):
        """String fields: keyword + length byte + data."""
        # NAME \x0A HHC-N8I8OP
        name_hex = "4e414d450a4848432d4e3849384f50"
        data = bytes.fromhex(name_hex)
        tlv = parse_tlv(data)
        assert tlv["NAME"] == "HHC-N8I8OP"

    def test_empty_string_field(self):
        """Empty strings: keyword + \\x00."""
        dnsa_hex = "444e534100"  # DNSA + \x00
        data = bytes.fromhex(dnsa_hex)
        tlv = parse_tlv(data)
        assert tlv["DNSA"] == ""

    def test_byte_field_zero(self):
        """Byte field with value 0."""
        mode_hex = "4d4f444500"  # MODE + \x00
        data = bytes.fromhex(mode_hex)
        tlv = parse_tlv(data)
        assert tlv["MODE"] == 0

    def test_byte_field_nonzero(self):
        """Byte field with value > 0."""
        inmode_hex = "494e4d4f444501"  # INMODE + \x01
        data = bytes.fromhex(inmode_hex)
        tlv = parse_tlv(data)
        assert tlv["INMODE"] == 1

    def test_serialport_raw4(self):
        """SERIALPORT is stored as hex string of 4 raw bytes."""
        sp_hex = "53455249414c504f525405010000"  # SERIALPORT + 05 01 00 00
        data = bytes.fromhex(sp_hex)
        tlv = parse_tlv(data)
        assert tlv["SERIALPORT"] == "05010000"

    def test_greedy_keyword_match(self):
        """REMOTEPORT must match before REMOTEIP prefix conflict.

        Keywords are sorted by length desc so longer names match first.
        """
        full = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        tlv = parse_tlv(full)
        # Both must exist and have correct types
        assert isinstance(tlv["REMOTEPORT"], int)
        assert isinstance(tlv["REMOTEIP"], str)

    def test_padded_response(self):
        """Real responses are padded with zeros to ~1088 bytes.
        
        The TLV parser must handle trailing null padding gracefully.
        """
        core = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        padded = core + b"\x00" * 800  # pad like the real packet
        tlv = parse_tlv(padded)
        assert tlv["SEARCHIP"] == "192.168.0.105"
        assert tlv["NAME"] == "HHC-N8I8OP"


class TestParseSearchResponse:
    """Tests for parse_search_response() → HHCDeviceConfig."""

    def test_real_capture_to_config(self):
        """Full round-trip: real binary response → HHCDeviceConfig object."""
        data = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        cfg = parse_search_response(data)
        assert cfg is not None

        assert cfg.ip == "192.168.0.105"
        assert cfg.mask == "255.255.255.0"
        assert cfg.gateway == "192.168.0.1"
        assert cfg.dest_ip == "192.168.0.101"
        assert cfg.local_port == 5000
        assert cfg.dest_port == 5000
        assert cfg.mode == 0
        assert cfg.inmode == 0
        assert cfg.dhcp == 0
        assert cfg.mtcp == 0
        assert cfg.heartbeat == 0
        assert cfg.mac == "485300575500"  # no colons!
        assert cfg.name == "HHC-N8I8OP"
        assert cfg.message == "HHC-N8I8OP"
        assert cfg.serialport_raw is not None
        assert cfg.serialport_raw == bytes([0x05, 0x01, 0x00, 0x00])

    def test_short_response_rejected(self):
        """Responses < 24 bytes must return None."""
        assert parse_search_response(b"\x00" * 23) is None
        assert parse_search_response(b"") is None

    def test_missing_searchip_rejected(self):
        """Response without SEARCHIP or IP key must return None."""
        # Just some random valid-looking TLV but no IP field
        data = b"MODE\x00NAME\x04test" 
        assert parse_search_response(data) is None


# ────────────────────────────────────────────────────────────────────────
# to_at_bytes() Tests — THE MOST DANGEROUS PART
# ────────────────────────────────────────────────────────────────────────

class TestToAtBytes:
    """Tests for HHCDeviceConfig.to_at_bytes() — verified against Wireshark capture.

    These tests protect against format regressions that could:
    - Reset all relays (wrong STATUS value)
    - Corrupt config (wrong MAC/SERIALPORT/MTCP encoding)
    - Brick device (missing fields in full-config write)
    """

    def _make_config_from_capture(self) -> HHCDeviceConfig:
        """Build a config matching the Tool.exe write capture."""
        cfg = HHCDeviceConfig()
        cfg.ip = "192.168.0.105"
        cfg.mask = "255.255.255.0"
        cfg.gateway = "192.168.0.1"
        cfg.dest_ip = "192.168.0.101"
        cfg.mac = "485300575500"
        cfg.name = "RELAY"
        cfg.mode = 0
        # SERIALPORT stores 4 raw data bytes; commas are added during write
        cfg.serialport_raw = bytes([0x05, 0x01, 0x00, 0x00])
        cfg.local_port = 5000
        cfg.dest_port = 5000
        cfg.dhcp = 1
        cfg.dns = ""
        cfg.heartbeat = 0
        cfg.mtcp = 0
        cfg.message = "HHC-N8I8OP"
        cfg.ctime = 0
        cfg.inmode = 1
        return cfg

    def test_exact_match_with_wireshark_capture(self):
        """Generated payload MUST byte-for-byte match real Tool.exe traffic.

        This is the golden test. Verified against Wireshark capture of Tool.exe.
        """
        cfg = self._make_config_from_capture()
        our_payload = cfg.to_at_bytes("192.168.0.105")

        # Add SAVE=1 like the real capture includes
        our_payload += b"AT+SAVE=1"

        real_payload = bytes.fromhex(CAPTURED_WRITE_PAYLOAD_HEX)

        if our_payload != real_payload:
            for i in range(max(len(our_payload), len(real_payload))):
                a = our_payload[i] if i < len(our_payload) else None
                b = real_payload[i] if i < len(real_payload) else None
                if a != b:
                    ca = chr(a) if a and 32 <= a < 127 else f"\\x{a:02x}" if a else "EOF"
                    cb = chr(b) if b and 32 <= b < 127 else f"\\x{b:02x}" if b else "EOF"
                    pytest.fail(
                        f"Payload mismatch at byte {i}: ours={ca} real={cb}\n"
                        f"Our : {our_payload[max(0,i-10):i+10].hex()}\n"
                        f"Real: {real_payload[max(0,i-10):i+10].hex()}"
                    )

        assert our_payload == real_payload

    # ── Footgun protection ──

    def test_status_never_equals_ten(self):
        """CRITICAL: AT+STATUS=10 RESETS ALL RELAYS TO OFF!

        No matter what, to_at_bytes() MUST produce STATUS=0.
        """
        cfg = self._make_config_from_capture()
        payload = cfg.to_at_bytes("192.168.0.105")

        # Must NOT contain AT+STATUS=10 anywhere
        assert b"AT+STATUS=10" not in payload, \
            "FATAL: AT+STATUS=10 would reset all relays!"
        assert b"AT+STATUS=00" not in payload, \
            "AT+STATUS=00 is also wrong — should be single digit =0"

        # Must contain exactly AT+STATUS=0
        assert b"AT+STATUS=0" in payload

    def test_mac_without_colons(self):
        """MAC MUST NOT contain colons in the output payload.

        Tool.exe sends "485300575500", NOT "48:53:00:57:55:00".
        Colons in AT+MAC= would corrupt the MAC address on device.
        """
        cfg = self._make_config_from_capture()
        cfg.mac = "AABBCCDDEEFF"
        payload = cfg.to_at_bytes("192.168.0.105")

        mac_section = payload[payload.find(b'AT+MAC="'):payload.find(b'AT+MAC="') + 30]
        assert b":" not in mac_section, f"Colons found in MAC: {mac_section!r}"

    def test_mtcp_is_raw_null_not_ascii_zero(self):
        """CRITICAL: MTCP=0 means raw NULL byte (0x00) after '='.

        Wireshark-verified: Tool.exe sends AT+MTCP=\\x00.
        UDP uses length-based framing — null bytes do NOT truncate payload.
        ASCII "0" (0x30) would be WRONG and the device would reject it.
        """
        cfg = self._make_config_from_capture()
        cfg.mtcp = 0
        payload = cfg.to_at_bytes("192.168.0.105")

        mtcp_pos = payload.find(b"AT+MTCP=")
        assert mtcp_pos >= 0, "AT+MTCP= missing from payload"

        # Byte right after 'AT+MTCP=' should be 0x00 (raw null), NOT 0x30 ('0')
        mtcp_val_byte = payload[mtcp_pos + len(b"AT+MTCP=")]
        assert mtcp_val_byte == 0x00, \
            f"MTCP value byte is 0x{mtcp_val_byte:02x}, expected 0x00 (raw null)"

    def test_mtcp_value_one_is_raw_byte(self):
        """MTCP=1 should send raw byte 0x01, not ASCII '1' (0x31)."""
        cfg = self._make_config_from_capture()
        cfg.mtcp = 1
        payload = cfg.to_at_bytes("192.168.0.105")

        mtcp_pos = payload.find(b"AT+MTCP=")
        mtcp_val_byte = payload[mtcp_pos + len(b"AT+MTCP=")]
        assert mtcp_val_byte == 0x01, \
            f"MTCP=1 sent as 0x{mtcp_val_byte:02x}, expected raw 0x01"

    def test_serialport_is_raw_bytes(self):
        """SERIALPORT must contain raw binary bytes with comma separators.

        Wireshark-verified: Tool.exe sends AT+SERIALPORT=\\x05\\x2C\\x01\\x2C\\x00\\x2C\\x00\\x2C
        The data model stores 4 raw bytes [0x05,0x01,0x00,0x00];
        commas (0x2C) are inserted after each byte during to_at_bytes().
        """
        cfg = self._make_config_from_capture()
        payload = cfg.to_at_bytes("192.168.0.105")

        sp_pos = payload.find(b"AT+SERIALPORT=")
        assert sp_pos >= 0, "AT+SERIALPORT= missing"

        # After 'AT+SERIALPORT=': raw bytes with commas: \x05,\x01,\x00,\x00,
        sp_data = payload[sp_pos + len(b"AT+SERIALPORT="):sp_pos + len(b"AT+SERIALPORT=") + 8]
        assert sp_data == bytes([0x05, 0x2C, 0x01, 0x2C, 0x00, 0x2C, 0x00, 0x2C]), \
            f"SERIALPORT bytes wrong: {sp_data.hex()}"

    def test_set_filter_always_first(self):
        """AT+SET="<ip>" address filter MUST be the very first command."""
        cfg = self._make_config_from_capture()
        payload = cfg.to_at_bytes("192.168.0.105")

        assert payload.startswith(b'AT+SET="192.168.0.105"'), \
            f"Payload does not start with AT+SET: starts with {payload[:30]!r}"

    def test_status_always_last_before_save(self):
        """AT+STATUS=0 must appear as the last command before optional SAVE."""
        cfg = self._make_config_from_capture()
        payload = cfg.to_at_bytes("192.168.0.105")
        save_suffix = b"AT+SAVE=1"

        # Without SAVE
        status_pos = payload.rfind(b"AT+STATUS=0")
        assert status_pos >= 0

        # Nothing meaningful after STATUS except possible SAVE
        after_status = payload[status_pos + len(b"AT+STATUS=0"):]
        assert after_status == b"", \
            f"Unexpected content after STATUS: {after_status!r}"

    def test_all_fields_present_in_output(self):
        """When all config fields are set, ALL corresponding AT+ commands must appear."""
        cfg = self._make_config_from_capture()
        payload = cfg.to_at_bytes("192.168.0.105")

        required = [
            b'AT+SET=',
            b'AT+IP=',
            b'AT+SUBNET=',
            b'AT+GATEWAY=',
            b'AT+REMOTEIP=',
            b'AT+MAC=',
            b'AT+NAME=',
            b'AT+MODE=',
            b'AT+SERIALPORT=',
            b'AT+LOCALPORT=',
            b'AT+REMOTEPORT=',
            b'AT+DHCP=',
            b'AT+DNSA=',
            b'AT+HEART=',
            b'AT+MTCP=',
            b'AT+MESSAGE=',
            b'AT+CTIME=',
            b'AT+INMODE=',
            b'AT+STATUS=',
        ]
        for cmd in required:
            assert cmd in payload, f"Missing command: {cmd.decode()}"

    def test_none_fields_are_skipped(self):
        """Fields set to None must NOT appear in the output."""
        cfg = HHCDeviceConfig()
        cfg.ip = "10.0.0.1"
        cfg.name = None  # explicitly omitted
        payload = cfg.to_at_bytes("10.0.0.1")

        assert b"AT+NAME=" not in payload
        assert b'AT+IP="10.0.0.1"' in payload

    def test_dhcp_as_number_not_quoted(self):
        """DHCP is an unquoted number: AT+DHCP=1, NOT AT+DHCP="1"."""
        cfg = HHCDeviceConfig()
        cfg.dhcp = 1
        payload = cfg.to_at_bytes("1.2.3.4")

        assert b"AT+DHCP=1" in payload
        assert b'AT+DHCP="1"' not in payload

    def test_mode_as_number_not_quoted(self):
        """MODE is unquoted: AT+MODE=0, NOT AT+MODE="0"."""
        cfg = HHCDeviceConfig()
        cfg.mode = 2
        payload = cfg.to_at_bytes("1.2.3.4")

        assert b"AT+MODE=2" in payload
        assert b'AT+MODE="2"' not in payload

    def test_inmode_as_number_not_quoted(self):
        """INMODE is unquoted: AT+INMODE=1, NOT AT+INMODE="1"."""
        cfg = HHCDeviceConfig()
        cfg.inmode = 1
        payload = cfg.to_at_bytes("1.2.3.4")

        assert b"AT+INMODE=1" in payload
        assert b'AT+INMODE="1"' not in payload

    def test_ports_are_quoted_strings(self):
        """Ports are quoted: AT+LOCALPORT="5000", NOT AT+LOCALPORT=5000."""
        cfg = HHCDeviceConfig()
        cfg.local_port = 5000
        cfg.dest_port = 6000
        payload = cfg.to_at_bytes("1.2.3.4")

        assert b'AT+LOCALPORT="5000"' in payload
        assert b'AT+REMOTEPORT="6000"' in payload

    def test_dns_empty_string_produces_empty_quotes(self):
        """Empty DNS: AT+DNSA="", NOT AT+DNSA= or AT+DNSA="\"\""""
        cfg = HHCDeviceConfig()
        cfg.dns = ""
        payload = cfg.to_at_bytes("1.2.3.4")

        assert b'AT+DNSA=""' in payload


# ────────────────────────────────────────────────────────────────────────
# Round-trip Tests: READ → WRITE back unchanged
# ────────────────────────────────────────────────────────────────────────

class TestRoundTrip:
    """Verify that reading config then writing it back produces consistent output.

    If you read a device's config and immediately write it back,
    the written payload should correctly represent what was read.
    This catches cases where parsing loses information needed for writes.
    """

    def test_roundtrip_preserves_all_fields(self):
        """Parse a real response, build AT payload, verify all values present."""
        data = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        cfg = parse_search_response(data)
        assert cfg is not None

        # Build AT payload from parsed config
        payload = cfg.to_at_bytes(cfg.ip)
        
        # Verify each parsed value appears in the output
        assert b'AT+IP="192.168.0.105"' in payload
        assert b'AT+SUBNET="255.255.255.0"' in payload
        assert b'AT+GATEWAY="192.168.0.1"' in payload
        assert b'AT+REMOTEIP="192.168.0.101"' in payload
        assert b'AT+MAC="485300575500"' in payload
        assert b'AT+NAME="HHC-N8I8OP"' in payload
        assert b"AT+MODE=0" in payload
        assert b"AT+DHCP=0" in payload
        assert b'AT+LOCALPORT="5000"' in payload
        assert b'AT+REMOTEPORT="5000"' in payload
        assert b"AT+INMODE=0" in payload

    def test_roundtrip_serialport_preserved(self):
        """The serialport raw bytes must survive READ→WRITE unchanged.

        If we lose these bytes, the UART config gets corrupted.
        """
        data = bytes.fromhex(CAPTURED_SEARCH_RESPONSE_HEX)
        cfg = parse_search_response(data)
        assert cfg is not None

        payload = cfg.to_at_bytes(cfg.ip)

        # Find SERIALPORT in payload and check raw bytes match Wireshark
        sp_marker = b"AT+SERIALPORT="
        pos = payload.find(sp_marker)
        assert pos >= 0

        # After marker: raw bytes with commas: \x05,\x01,\x00,\x00,
        sp_after = payload[pos + len(sp_marker):]
        # First non-SERIALPORT command marks end of values
        next_cmd_pos = len(sp_after)
        for i in range(len(sp_after) - 2):
            if sp_after[i:i+3] == b"AT+":
                next_cmd_pos = i
                break
        
        sp_raw = sp_after[:next_cmd_pos]
        # Should be: \x05,\x01,\x00,\x00, (raw bytes with commas, Wireshark-verified)
        assert sp_raw == bytes([0x05, 0x2C, 0x01, 0x2C, 0x00, 0x2C, 0x00, 0x2C]), \
            f"SERIALPORT roundtrip wrong: {sp_raw.hex()}"


# ────────────────────────────────────────────────────────────────────────
# Relay Response Parser Tests
# ────────────────────────────────────────────────────────────────────────

class TestRelayParsing:
    """Tests for relay/input state string parsing."""

    def test_relay_channel_1_on(self):
        """relay00000001 → CH1 ON, rest OFF.

        Device sends MSB-first: leftmost char = CH8.
        Parser reverses so index 0 = CH1.
        String "00000001" → reversed → "10000000" → index 0 = '1' = ON.
        """
        from hhc_protocol import HHCRelayClient
        states = HHCRelayClient.parse_relay_response("relay00000001")
        assert states == [True, False, False, False, False, False, False, False]

    def test_relay_all_off(self):
        """relay00000000 → all channels OFF."""
        from hhc_protocol import HHCRelayClient
        states = HHCRelayClient.parse_relay_response("relay00000000")
        assert states == [False] * 8

    def test_relay_all_on(self):
        """relay11111111 → all channels ON."""
        from hhc_protocol import HHCRelayClient
        states = HHCRelayClient.parse_relay_response("relay11111111")
        assert states == [True] * 8

    def test_relay_ch8_on(self):
        """relay10000000 → only CH8 ON (MSB = CH8 in device string).
        
        String "10000000" → reversed → "00000001" → only last index = True.
        """
        from hhc_protocol import HHCRelayClient
        states = HHCRelayClient.parse_relay_response("relay10000000")
        assert states == [False, False, False, False, False, False, False, True]

    def test_input_parse(self):
        """inputXXXXXXXXXX → 8 channel inputs + 2 global.
        
        Same bit-reversal as relay: "input...0000000001" = CH1 ON.
        """
        from hhc_protocol import HHCRelayClient
        states = HHCRelayClient.parse_input_response("input00000001")
        assert states[0] is True   # CH1 ON
        assert states[1:] == [False] * 7

    def test_invalid_relay_raises(self):
        from hhc_protocol import HHCRelayClient
        with pytest.raises(ValueError):
            HHCRelayClient.parse_relay_response("garbage")

    def test_invalid_input_raises(self):
        from hhc_protocol import HHCRelayClient
        with pytest.raises(ValueError):
            HHCRelayClient.parse_input_response("garbage")


# ────────────────────────────────────────────────────────────────────────
# Protocol Constants
# ────────────────────────────────────────────────────────────────────────

class TestConstants:
    """Verify protocol constants match Tool.exe behavior."""

    def test_at_port(self):
        """Tool.exe communicates on UDP port 65535."""
        assert AT_PORT == 65535

    def test_source_port(self):
        """Tool.exe binds source port to 65535 (verified in Wireshark)."""
        assert AT_SOURCE_PORT == 65535


# ────────────────────────────────────────────────────────────────────────
# Regression: specific bugs we've hit
# ────────────────────────────────────────────────────────────────────────

class TestRegressions:
    """Tests for specific bugs we've encountered and fixed."""

    def test_bug_mac_colons_in_write(self):
        """BUG: MAC with colons was being sent as AT+MAC="48:53:..." 
        
        Device expects AT+MAC="485300575500" (no colons).
        With colons, device would interpret colons as part of MAC data.
        """
        cfg = HHCDeviceConfig()
        cfg.mac = "AABBCCDDEEFF"  # correct format from parser
        payload = cfg.to_at_bytes("1.2.3.4")

        mac_pos = payload.find(b'AT+MAC="')
        mac_end = payload.find(b'"', mac_pos + 8)
        mac_value = payload[mac_pos + 8:mac_end].decode()
        assert ":" not in mac_value, f"MAC has colons: {mac_value}"

    def test_bug_mtcp_raw_null_not_ascii(self):
        """BUG: MTCP=0 was sending ASCII '0' (0x30) instead of raw null byte (0x00).
        
        Wireshark-verified: Tool.exe sends AT+MTCP=\\x00 — a raw null byte.
        UDP uses length-based framing, so \\x00 does NOT truncate payload.
        Sending ASCII '0' (0x30) would be wrong — device expects raw byte.
        """
        cfg = HHCDeviceConfig()
        cfg.mtcp = 0
        payload = cfg.to_at_bytes("1.2.3.4")

        idx = payload.find(b"AT+MTCP=") + len(b"AT+MTCP=")
        val = payload[idx]
        assert val == 0x00, f"MTCP sent as 0x{val:02x} instead of 0x00 (raw null)"

    def test_bug_status_double_digit(self):
        """BUG: STATUS was sent as =00 (two digits) instead of =0 (one digit).
        
        Even worse: =10 would RESET ALL RELAYS!
        """
        cfg = HHCDeviceConfig()
        payload = cfg.to_at_bytes("1.2.3.4")

        # Find AT+STATUS= and check what follows the '0'
        status_pos = payload.find(b"AT+STATUS=")
        after_eq = payload[status_pos + len(b"AT+STATUS="):]
        first_char = after_eq[0:1]
        second_char = after_eq[1:2]

        assert first_char == b"0", f"STATUS value doesn't start with 0: {first_char!r}"
        # Second char should be the next AT+ command start ('A'), not another digit
        if second_char.isdigit():
            pytest.fail(f"STATUS has extra digit after 0: ...{payload[status_pos:status_pos+20]!r}")

    def test_bug_serialport_null_byte_truncation(self):
        """REGRESSION: SERIALPORT must use raw bytes with comma separators.
        
        Wireshark-verified: Tool.exe sends AT+SERIALPORT=\\x05,\\x01,\\x00,\\x00,
        (raw bytes from ComboBox indices, each followed by 0x2C comma).
        UDP uses length-based framing — \\x00 bytes are safe.
        """
        cfg = HHCDeviceConfig()
        cfg.serialport_raw = bytes([0x05, 0x01, 0x00, 0x00])
        payload = cfg.to_at_bytes("1.2.3.4")

        sp_pos = payload.find(b"AT+SERIALPORT=")
        after = payload[sp_pos + len(b"AT+SERIALPORT="):]
        # Find end of SERIALPORT value (next AT+ command or end of payload)
        end = after.find(b"AT+")
        sp_value = after[:end] if end >= 0 else after
        
        # Must be raw bytes with commas — matches Tool.exe exactly
        assert sp_value == bytes([0x05, 0x2C, 0x01, 0x2C, 0x00, 0x2C, 0x00, 0x2C]), \
            f"Expected raw bytes but got: {sp_value.hex()}"

    def test_bug_dnsa_trailing_null_in_string(self):
        """BUG: DNSA with IP address had trailing \\x00 in parsed string.

        Device includes null terminator in the length count for string fields.
        Without stripping, AT+DNSA="8.8.8.8\\x00" would send a null byte
        to the device, potentially corrupting the DNS configuration.
        """
        data = b"DNSA\x088.8.8.8\x00"  # slen=8 but "8.8.8.8" is only 7 chars + \x00
        tlv = parse_tlv(data)
        dnsa_val = tlv.get("DNSA", "")
        assert "\x00" not in dnsa_val, f"DNSA has trailing null: {dnsa_val!r}"
        assert dnsa_val == "8.8.8.8"

    def test_empty_string_field_still_works_after_null_strip(self):
        """After rstrip('\\x00') fix, empty strings must still be empty."""
        data = bytes.fromhex("444e534100")  # DNSA + \x00 (empty)
        tlv = parse_tlv(data)
        assert tlv["DNSA"] == ""
