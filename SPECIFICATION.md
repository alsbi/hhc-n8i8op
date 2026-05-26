# HHC-N8I8OP Integration v3.1.0 — Specification

## Overview
Home Assistant custom integration for the HHC-N8I8OP 8-channel network relay board.
Three communication channels:
- **Discovery** (UDP 65535): AT+SEARCH broadcast + AT+READIP unicast
- **Config** (UDP 65535): AT+WRITE commands for device settings
- **Control** (TCP/UDP 5000): Relay on/off/read/input commands

## Key Architecture Decisions

### Discovery & Onboarding
- **Active SEARCH**: Background task (5 min interval) calls `HHCClient.scan_subnet()` which sends 256 `AT+SEARCH="N"` packets (N=0..255) on broadcast 255.255.255.255:65535
- **Short SEARCH responses (<24 bytes)**: Accept them, use UDP sender address as device IP. MAC obtained via READIP unicast later.
- **DHCP**: Standard HA DHCP discovery from manifest.json. Known MAC changed IP → auto-update+reload. New MAC → show discovery_confirm form.
- **SOURCE_INTEGRATION_DISCOVERY**: When scan_subnet() finds new devices, init ConfigFlow with this source so HA shows "Discovered" badge in Devices & Services.
- **Unified pipeline**: Regardless of source (SEARCH/DHCP/manual), go through forced discovery: READIP unicast + probe.
  - Both succeed → pre-filled form, user clicks OK
  - Partial/full fail → manual form with IP pre-filled, no protocol dropdown
- **L3-only support**: Device may be in different subnet accessible only by routing. Manual IP entry always available and never depends on broadcast.

### Protocol Auto-Detection
- `probe(ip)`: Send `read\n` simultaneously over TCP and UDP to port 5000. First valid `relayXXXXXXXX` response wins. On tie, prefer UDP.
- No protocol dropdown in UI. Auto-detected or fallback to "tcp".

### Naming Convention (_build_title)
- User-defined name (e.g., "Kitchen") → use it
- No name + MAC available → `hhc-n8i8op-{last4mac}` (lowercase hex, last 4 chars of MAC without colons)
- No name + no MAC → `hhc-n8i8op-{entry_id[:8]}` (first 8 chars of HA entry UUID)
- **NEVER include IP address anywhere in title/device_name**

### Options Flow — Conditional Relay Settings
- Single form always visible
- **HA Settings** (always): poll_interval, channel_types
- **Relay Settings** (only if `read_device_live()` succeeds): device_name, input_mode, work_mode
- If `read_device_live()` returns None: description_placeholder warning, relay fields excluded from schema
- Write path: strict `read_device_live()` → diff against current → write only changed fields via coordinator.transition_mode()

### Strict Write Operations
- All config writes (services, options flow) must do `read_device_live()` first
- If returns None → abort/skip write
- Diff the returned config against desired changes
- Write only changed fields via `coordinator.at_client.write_config(modified_config)`
- NO cache fallback for writes. Cache only used internally by coordinator for entity polling.

### Coordinator Lifecycle
- `read_device_live()`: strict READIP unicast, returns `HHCDeviceConfig | None`, never falls back to cache
- `get_known_config()`: best-effort read or cached config, for entity polling internal use
- `device_id`: equals `entry.unique_id` (MAC when known, host/UUID fallback). Never changes after forward_setups.
- `device_name`: uses `_build_title()` logic — no IP anywhere
- MAC-upgrade hook in `async_setup_entry` BEFORE `forward_entry_setups`: if strict READIP returns MAC different from current unique_id, update unique_id (if not already taken)

### YAML Deprecation
- `CONFIG_SCHEMA` wrapped with `cv.deprecated(DOMAIN)`
- YAML import does best-effort probe (5s timeout) to detect protocol
- Uses `_abort_if_unique_id_configured()` after setting unique_id

### v2 Migration Notification
- On first startup, check for entries in old domain `HHC_N8I8OP`
- Show `persistent_notification` urging manual cleanup

## File Structure & Module Splits
Files must be ≤300 lines each. Large files split into submodules:

```
custom_components/hhc_n8i8op/
├── __init__.py          (~280) Services, entry setup, YAML deprecation, v2 notification, start discovery
├── config_flow.py       (~300) ConfigFlow + OptionsFlow split into:
│   └── (see below — may need _config_flow.py + _options_flow.py)
├── coordinator.py       (~290) HHCCoordinator, HHCDeviceState
├── hhc_protocol/
│   ├── __init__.py      Re-exports public API
│   ├── config.py        HHCDeviceConfig, parse_tlv, parse_search_response, TLV definitions
│   ├── client.py        HHCClient (discover, scan_subnet, read_config_unicast, probe, write)
│   └── relay.py         HHCRelayClient (on/off/read/input/send_command, TCP/UDP transport)
│   └── _udp_helpers.py  Internal protocols: _FutureProtocol, _BinaryResponseProtocol, etc.
├── discovery.py         (~100) HHCDiscoveryManager background polling wrapper
├── const.py             Constants
├── entity.py            Base entity classes
├── switch.py / light.py / binary_sensor.py / button.py  Entity platforms
├── strings.json / translations/{en,ru}.json
├── manifest.json
└── services.yaml
```

## Specific Changes Per File

### const.py additions
```python
DISCOVERY_SCAN_INTERVAL: float = 300.0    # 5 minutes between background scans
DISCOVERY_SCAN_TIMEOUT: float = 4.0       # subnet scan collection time
CONFIG_READ_TIMEOUT: float = 10.0         # READIP unicast timeout
PROBE_TIMEOUT: float = 5.0                # dual TCP/UDP probe timeout
V2_DOMAIN = "HHC_N8I8OP"                 # old domain for migration notification
```

### hhc_protocol/ changes
- Split into submodules (config.py, client.py, relay.py, _udp_helpers.py)
- Add `scan_subnet()` improvement: short packets use sender address as IP
- Add `read_config_unicast(ip, timeout)` static method
- Add `probe(ip, timeout)` static method returning "tcp"|"udp"|None
- Keep old `discover()` for backward compat but mark as deprecated
- `_BinaryResponseProtocol` modified: accept responses <24 bytes (for scan_subnet)

### config_flow.py changes
- Remove CONF_PROTOCOL from manual form schema
- Add `async_step_integration_discovery()` for SOURCE_INTEGRATION_DISCOVERY
- Modify `async_step_dhcp()`: new MAC → show form, never auto-create entry
- `_build_title(name, mac, entry_id)` helper — no IP anywhere
- OptionsFlow: conditional relay settings based on read_device_live()
- OptionsFlow write methods: strict read → diff → write

### coordinator.py changes
- Add `read_device_live()` — strict, returns None on fail
- Rename/keep `read_device_config()` as best-effort (for services/entity display)
- Change `device_id` property to return entry.unique_id
- Change `device_name` property to use _build_title logic (no IP)

### __init__.py changes
- Wrap CONFIG_SCHEMA with cv.deprecated(DOMAIN)
- YAML import: probe protocol instead of hardcoding "udp"
- Strict services using read_device_live()
- persistent_notification for v2 domain cleanup
- Start HHCDiscoveryManager in async_setup()

### Entity platforms
- No file changes needed (they use coordinator.device_id/device_name computed properties)

## Test Requirements
- All existing tests must pass unchanged
- New tests for: scan_subnet short packet handling, read_config_unicast, probe
- ruff lint clean
- basedpyright type-check clean
- radon complexity grade A for all classes/methods
