# HHC-N8I8OP Protocol Specification

> **Protocol Version**: 1.0 (Firmware)  
> **Integration Version**: 3.0.0  
> **Status**: ✅ Verified via Wireshark + real-device testing

## Table of Contents

- [1. Network Architecture](#1-network-architecture)
- [2. Discovery Port (UDP 65535)](#2-discovery-port-udp-65535)
- [3. Data Port (TCP/UDP 5000)](#3-data-port-tcpudp-5000)
- [4. Configuration Write (AT+ Commands)](#4-configuration-write-at-commands)
- [5. Integration Checklist](#5-integration-checklist)
- [A. Appendix: Wireshark Tips](#a-appendix-wireshark-tips)

---

## 1. Network Architecture

The device exposes **two independent network services**:

| Port | Protocol | Scope | Purpose |
|------|----------|-------|---------|
| **65535** | UDP | Broadcast / Unicast | Device discovery & configuration |
| **5000** | TCP or UDP | Unicast | Relay control & input reading |

> **Source port requirement**: for AT+ commands, the sender **must** use source port 65535. The device replies from its own port 65535 or 65534 (firmware-dependent).

### Supported Work Modes

| Mode | Name | Protocol | HA Support | Notes |
|------|------|----------|------------|-------|
| 0 | TCP Server | TCP | ✅ | HA connects to device |
| 1 | TCP Client | TCP | ❌ | Device connects to remote server |
| 2 | UDP Service | UDP | ✅ | Stateless, recommended for HA |
| 3 | UDP Client | UDP | ❌ | Device sends to remote server |

**Recommended for Home Assistant**: `MODE=2` (UDP Service) — fewer reconnect issues, simpler error handling.

---

## 2. Discovery Port (UDP 65535)

### 2.1 Query Commands

AT+ commands are ASCII strings, packet-terminated (no `\r\n` delimiter):

```
AT+SEARCH="123"           # Search by last IP octet, broadcast
AT+READIP="172.16.10.16"  # Read specific device config, unicast
```

### 2.2 Response Format — Binary TLV

The device replies with a **binary packet**, not ASCII.

```
[KEYWORD][VALUE] [KEYWORD][VALUE] ...
```

Keywords are literal ASCII strings. Value type depends on keyword. There are **no length prefixes or delimiters** — parsing relies on keyword matching.

#### TLV Field Reference

| Keyword | Type | Bytes | Description | Example |
|---------|------|-------|-------------|---------|
| `IP` / `SEARCHIP` | `ip` | 4 | Device IP address | `172.16.10.16` |
| `SUBNET` | `ip` | 4 | Network mask | `255.255.0.0` |
| `GATEWAY` | `ip` | 4 | Default gateway | `172.16.0.2` |
| `REMOTEIP` | `ip` | 4 | Destination IP (mode 1/3) | `192.168.1.100` |
| `LOCALPORT` | `port` | 2 | Data port | `5000` |
| `REMOTEPORT` | `port` | 2 | Destination port | `5000` |
| `MODE` | `byte` | 1 | Work mode | `0`–`3` |
| `INMODE` | `byte` | 1 | Input trigger mode | `0`–`2` |
| `DHCP` | `byte` | 1 | DHCP enable | `0`=static, `1`=dhcp |
| `MTCP` | `byte` | 1 | Multi-connection TCP | `0` or `1` |
| `HEART` | `byte` | 1 | Heartbeat interval (sec) | `0`=off |
| `STATUS` | `byte` | 1 | Preserve state on reboot | `0`=off, `1`=on |
| `CTIME` | `uint16` | 2 | Hold time in 0.1s units | `30` = 3.0s |
| `MAC` | `mac` | 6 | MAC address (raw) | `485300123456` |
| `NAME` | `string` | variable | Device name | `"hhc n8i8op"` |
| `DNSA` | `string` | variable | DNS server | `"8.8.8.8"` |
| `MESSAGE` | `string` | variable | Custom message | `"Hello"` |
| `SERIALPORT` | `raw4` | 4 | Serial config bytes | `115,0,0,0` |

#### Value Encoding Details

**`ip`** — 4 bytes, big-endian:
```
\xAC\x10\x0A\x10  →  172.16.10.16
```

**`port` / `uint16`** — 2 bytes, big-endian:
```
\x13\x88  →  5000
```

**`mac`** — 6 raw bytes, no colons:
```
\x48\x53\x00\x12\x34\x56  →  "485300123456"
```

**`string`** — length-prefixed:
```
\x08MyRelay\x00  →  len=8, value="MyRelay\0"
```

**`byte`** — single unsigned byte:
```
\x02  →  2
```

**`raw4`** — 4 raw bytes (serial port configuration):
```
\x73\x00\x00\x00  →  (interpreted by firmware)
```

### 2.3 Parsing Algorithm

```python
def parse_tlv(data: bytes) -> dict[str, Any]:
    """Parse binary TLV response from device."""
    result = {}
    pos = 0
    
    # Keywords sorted by descending length for greedy matching
    defs = sorted(TLV_DEFS.items(), key=lambda kv: -len(kv[0]))
    
    while pos < len(data) - 2:
        for keyword, vtype in defs:
            klen = len(keyword)
            if pos + klen > len(data):
                continue
            if data[pos:pos + klen] != keyword.encode():
                continue
            
            vs = pos + klen
            val, consumed = _parse_value(data, vs, vtype)
            result[keyword] = val
            pos = vs + consumed
            break
        else:
            pos += 1  # No match — advance by 1 byte
    
    return result
```

### 2.4 Validation Rules

A response is **valid** only if it contains at least one of:
- `IP` field
- `SEARCHIP` field

Responses without `IP`/`SEARCHIP` are noise — ignore them.

### 2.5 Real Packet Example

```hex
4848300003A7961100000054385A0000AC100A10800100000001A8C002000000AC1000000C0A8FF00100AC10002001000...
```

Parsed:
- `IP` = `172.16.10.16`
- `SUBNET` = `255.255.0.0`
- `GATEWAY` = `172.16.0.2`
- `NAME` = `hhc n8i8op`
- `MAC` = `485300123456`
- `MODE` = `0` (TCP Server)
- `INMODE` = `1` (Trigger)
- `LOCALPORT` = `5000`

---

## 3. Data Port (TCP/UDP 5000)

### 3.1 Command Format

ASCII commands, **no delimiter** (no `\r\n`), raw string in packet:

| Command | Action | Response |
|---------|--------|----------|
| `read` | Read all 8 relay states | `relayXXXXXXXX` |
| `{N}on` | Turn relay N ON | `relayXXXXXXXX` |
| `{N}off` | Turn relay N OFF | `relayXXXXXXXX` |
| `allon` | Turn all relays ON | `relayXXXXXXXX` |
| `alloff` | Turn all relays OFF | `relayXXXXXXXX` |
| `inread` | Read input states | `inXXXXXXXX` |

Where `N` = `1`–`8`.

### 3.2 Response Format: `relayXXXXXXXX`

```
relay00000000   # All OFF
relay10000000   # Relay 1 ON
relay10101010   # Relays 1,3,5,7 ON
relay11111111   # All ON
```

- Prefix: `relay` (5 ASCII bytes)
- States: 8 characters (`0` or `1`)
- Order: **relay 1 → relay 8** (left to right)

### 3.3 Response Format: `inXXXXXXXX`

For digital inputs (`inread` command):
- Same structure as relay response
- `in` prefix instead of `relay`

### 3.4 UDP Interaction Example (MODE=2)

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0)

# Send command
sock.sendto(b"read", ("172.16.10.16", 5000))

# Receive response
data, addr = sock.recvfrom(64)
response = data.decode("ascii").strip()

# Parse
if response.startswith("relay") and len(response) == 13:
    states = [c == "1" for c in response[5:]]
    print(f"Relay states: {states}")
```

### 3.5 TCP Interaction Example (MODE=0)

```python
import asyncio

async def read_relays(ip: str, port: int = 5000) -> list[bool]:
    reader, writer = await asyncio.open_connection(ip, port)
    writer.write(b"read")
    await writer.drain()
    
    data = await asyncio.wait_for(reader.read(64), timeout=5.0)
    response = data.decode("ascii").strip()
    
    writer.close()
    await writer.wait_closed()
    
    if response.startswith("relay") and len(response) == 13:
        return [c == "1" for c in response[5:]]
    return []
```

> **Important**: Each command reads/writes **all 8 relays at once**. There is no single-relay read command.

---

## 4. Configuration Write (AT+ Commands)

### 4.1 SET Command

Every configuration write must start with:

```
AT+SET="172.16.10.16"
```

This targets a specific device by IP. All subsequent AT+ commands in the same packet apply to this device.

### 4.2 AT+ Command Reference

#### IP Network Settings

```
AT+IP="172.16.10.16"         # Device IP
AT+SUBNET="255.255.0.0"      # Network mask
AT+GATEWAY="172.16.0.2"      # Default gateway
AT+REMOTEIP="192.168.1.100"  # Destination IP (modes 1,3)
```

Format: **quoted dotted-decimal**.

#### MAC Address

```
AT+MAC="485300123456"
```

Format: **quoted hex-string, NO COLONS**:
- ✅ `AT+MAC="485300123456"`
- ❌ `AT+MAC="48:53:00:12:34:56"` — device will NOT accept

#### Device Name

```
AT+NAME="Pool Controller"
```

Format: **quoted ASCII**, max ~16–32 chars (firmware-dependent).

#### Work Mode

```
AT+MODE=0   # TCP Server
AT+MODE=2   # UDP Service (recommended)
```

Format: **unquoted digit** (`0`–`3`).

#### Serial Port

```
AT+SERIALPORT=115,0,0,0,
```

Format: **raw bytes** — 4 value bytes + `0x2C` (`,`) after each:
```python
# Construction
sp = bytearray()
for val in [115, 0, 0, 0]:
    sp.append(val)
    sp.append(0x2C)  # ','
# Result: b"AT+SERIALPORT=" + bytes(sp)
```

#### Ports

```
AT+LOCALPORT="5000"
AT+REMOTEPORT="5000"
```

Format: **quoted decimal string**.

#### DHCP

```
AT+DHCP=0   # Static IP
AT+DHCP=1   # DHCP enabled
```

Format: **unquoted digit**.

#### DNS

```
AT+DNSA="8.8.8.8"
AT+DNSA=""     # Empty — no DNS
```

Format: **quoted string**.

#### Heartbeat

```
AT+HEART="0"    # Disabled
AT+HEART="60"   # Every 60 seconds
```

Format: **quoted string** with seconds.

#### Multi-TCP

```python
b"AT+MTCP=" + bytes([0x00])   # Single connection
b"AT+MTCP=" + bytes([0x01])   # Multi-connection
```

Format: **raw byte**, NOT ASCII!
- ❌ `b"AT+MTCP=0"` — device will NOT accept

#### Message

```
AT+MESSAGE="Hello"
AT+MESSAGE=""
```

Format: **quoted string**.

#### Hold Time (CTIME)

```
AT+CTIME="0"    # Disabled
AT+CTIME="30"   # 3.0 seconds (30 × 0.1s)
```

Format: **quoted string**, value in tenths of a second.

#### Input Mode

```
AT+INMODE=0   # Unlinked — inputs independent
AT+INMODE=1   # Trigger — momentary toggle
AT+INMODE=2   # Auto — hold=ON, release=OFF
```

Format: **unquoted digit**.

#### State Preservation

```
AT+STATUS=0   # All OFF after power cycle
AT+STATUS=1   # Preserve current state
```

⚠️ **CRITICAL**: `AT+STATUS=10` is interpreted as `AT+STATUS=1` + garbage, causing **all relays to reset OFF**! Always use exactly `0` or `1`.

Format: **unquoted digit**.

### 4.3 Full SET Packet Example

All commands concatenated without separators:

```
AT+SET="172.16.10.16"AT+NAME="Pool Controller"AT+MODE=2AT+STATUS=1AT+IP="172.16.10.16"AT+SUBNET="255.255.0.0"AT+GATEWAY="172.16.0.2"AT+LOCALPORT="5000"AT+DHCP=0AT+DNSA=""AT+HEART="0"AT+CTIME="0"AT+INMODE=0
```

### 4.4 Command Order

| Priority | Command | Reason |
|----------|---------|--------|
| 1st | `AT+SET` | Must be first — targets the device |
| Last | `AT+STATUS` | Avoid side effects during configuration |

Other commands: order is practically irrelevant.

### 4.5 SET Response

Device replies with **echo of the full payload** prefixed with `OK`:

```
OK+SET="192.168.0.105"AT+IP="192.168.0.105"AT+MODE=0...AT+SAVE=1
```

```python
if response.startswith(b"OK"):
    print("Configuration saved successfully")
```

### 4.6 Optional Fields

Tool.exe does not always send all fields:
- `AT+REMOTEIP` / `AT+REMOTEPORT` — only if configured in UI
- `AT+DNSA` — empty string `""` if not set
- `AT+MESSAGE` — often empty

Missing fields retain their previous values on the device.

---

## 5. Integration Checklist

### Device Communication

- [x] TLV response parsing (binary)
- [x] AT+SEARCH broadcast discovery
- [x] AT+READIP unicast read
- [x] UDP relay control (mode=2)
- [x] TCP relay control (mode=0)
- [x] Input state reading (`inread`)

### Home Assistant Features

- [x] DHCP discovery handler
- [x] Config Flow (automatic + manual)
- [x] Options Flow (rename, input types, intervals)
- [x] MAC-based entity naming
- [x] Unique device ID generation
- [x] Coordinator with polling

### Polish

- [ ] Auto-failover TCP↔UDP on timeouts
- [ ] UDP heartbeat keepalive
- [ ] Batch relay state commands
- [ ] Input trigger automations

---

## A. Appendix: Wireshark Tips

1. **Filter for discovery**:
   ```
   udp.port == 65535
   ```

2. **Filter for relay control**:
   ```
   tcp.port == 5000 || udp.port == 5000
   ```

3. **Follow UDP stream** to see ASCII commands.

4. **Export bytes** (hex dump) for TLV analysis.

5. Enable **Decode As → Data** for port 65535 if Wireshark misidentifies protocol.

---

## File Locations

| Component | Path |
|-----------|------|
| Configuration parser | `hhc_protocol/config.py` |
| Discovery methods | `hhc_protocol/_discovery.py` |
| Relay client | `hhc_protocol/relay.py` |
| Main client | `hhc_protocol/client.py` |
| UDP helpers | `hhc_protocol/_udp_helpers.py` |
| HA Config Flow | `config_flow.py` |
| HA Coordinator | `coordinator.py` |
| This document | `docs/PROTOCOL_SPEC.md` |

---

> **License**: MIT — see repository root  
> **Author**: alsbi  
> **Repo**: https://github.com/alsbi/hhc-n8i8op
