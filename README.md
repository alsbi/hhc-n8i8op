<div align="center">

<img src="https://raw.githubusercontent.com/alsbi/hhc-n8i8op/main/images/relay-board.jpg" width="400" alt="hhc-n8i8op relay board">

# hhc-n8i8op

**Home Assistant custom integration for the hhc-n8i8op relay board**

8 relays · 10 inputs · TCP/UDP · DHCP auto-discovery

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![release](https://img.shields.io/github/v/release/alsbi/hhc-n8i8op?include_prereleases)](https://github.com/alsbi/hhc-n8i8op/releases)

</div>

---

## Features

- **Config Flow** — add devices through UI, no YAML required
- **DHCP auto-discovery** — devices detected by MAC OUI `48:53:00`
- **Per-channel type** — each relay as `switch` or `light`
- **Input & Work mode** — switch button behavior and TCP ↔ UDP from Options
- **Binary sensors** — all 10 inputs monitored (IN1–IN10)
- **Button entities** — one-click All On / All Off
- **Services** — bulk control, mode changes, device config readout
- **Translations** — English + Russian

## Install

**HACS:** add `https://github.com/alsbi/hhc-n8i8op` as a custom repository.

**Manual:** copy `custom_components/hhc_n8i8op/` into `<config>/custom_components/hhc_n8i8op/`.

After installation → **Settings → Devices & Services → Add Integration → hhc-n8i8op**.

## Setup

| Parameter | Default | Description |
|-----------|---------|-------------|
| IP address | — | Device address on your LAN |
| Port | 5000 | Control port |
| Protocol | TCP | Must match the device work mode setting |
| Channel count | 8 | Physical output channels on the board (1–8) |

## Options

Click **Configure → Options** on the device entry.

| Option | Description |
|--------|-------------|
| Poll interval | State polling period in seconds (`0.2`–`10`) |
| Device name | Name stored on the board via `AT+NAME` |
| Input mode | Physical button behavior: *Unlinked* / *Trigger* |
| Work mode | Network protocol: *TCP Service* / *UDP Service* |
| Channel N type | Per-channel entity type — `switch` or `light` |

> **Dropdown behavior:** when the device is reachable, dropdowns pre-select the value read from hardware. When unreachable, a *"Don't change"* option appears so you aren't forced to overwrite an unknown state. On Save the chosen value is always pushed to the device — even if it visually matches the old one.

## Entities

### Per channel (1–8)

| Entity | Purpose |
|--------|---------|
| `switch` or `light` | Relay output — type configurable per channel |
| `binary_sensor` | Physical input state (IN1–IN8) |

### Device-level

| Entity | Purpose |
|--------|---------|
| `binary_sensor` | IN9 — global All On input (hardware override) |
| `binary_sensor` | IN10 — global All Off input (hardware override) |
| `button` | All On — sends `allon` command |
| `button` | All Off — sends `alloff` command |

The global inputs (IN9/IN10) are hardware-level overrides — when active, the board forces all relays on or off directly, bypassing any software settings.

## Input Modes

Independent of network work mode. Set via Options or `set_input_mode` service.

| Mode | AT+INMODE | Behavior |
|------|-----------|----------|
| **Unlinked** | 0 | Buttons decoupled from relays — control only via network |
| **Trigger** | 1 | Each button toggles its matching relay |

> **Factory default is Unlinked (INMODE=0)** — after a factory reset, physical buttons do NOT control relays. You must switch to Trigger mode for button control.

## Factory Reset

To reset the device to factory defaults:

1. Power off the device
2. Press and hold the RESET button
3. While holding RESET, power on the device
4. Continue holding RESET for ~10 seconds
5. Release — the device reboots with factory settings

After reset: INMODE=0 (buttons unlinked), STATUS=0 (relay states not preserved), static IP.

## Known Limitations

- **Changing IP and work mode simultaneously may not apply correctly.** Change them in separate steps: first change one → save → wait for reboot (~5 sec) → then change the other.
- **DHCP support exists but may not work reliably on all hardware revisions.** Keep a static IP connection available as fallback.

## Services

All services are under the `hhc_n8i8op` domain (shown as `hhc_n8i8op` in the UI).

| Service | Parameter | Description |
|---------|-----------|-------------|
| `set_input_mode` | `mode`: unlinked / trigger / auto | Change physical button behavior |
| `set_work_mode` | `mode`: 0 or 2 | Switch network protocol. ⚠️ May break current connection! |
| `read_device_config` | — | Query full device config via SEARCH (returns response data) |
| `all_on` | — | Turn all relays on |
| `all_off` | — | Turn all relays off |

> **Target filtering:** All services support device/entity targets. When targets
> are specified, the service applies only to the selected devices. Without
> targets, services apply to all loaded devices (backward compatible).

## Discovery

| Method | Trigger |
|--------|---------|
| **DHCP** | HA detects MAC addresses starting with `48:53:00` and offers to add the device automatically |
| **Manual scan** | Clicking *Add Integration* scans local `/24` subnets using AT+SEARCH broadcasts |
| **IP update** | If an already-configured device gets a new IP via DHCP, the stored address is updated automatically |

## Protocol

Relay control — TCP/UDP on port 5000:

```
on<N>     turn on channel N       off<N>    turn off channel N
allon     turn everything on      alloff    turn everything off
read      read relay states       input     read input states
```

Configuration — UDP broadcast on port 65535. All `AT+` commands must be sent as one concatenated string in a single datagram. `AT+SET="<ip>"` filters by device address.

Full protocol details: [SPECIFICATION.md](SPECIFICATION.md).

## Changelog

### Unreleased (post-refactor)

**Protocol & transport**
- **Persistent TCP connection** — `HHCRelayClient` now reuses a single TCP connection with
  automatic reconnect on `ConnectionResetError`, eliminating per-command connect/disconnect
  overhead. UDP mode still uses one-shot datagrams.
- **UDP transport tracking** — `HHCClient` stores `_udp_transport` reference to prevent
  accidental closure in cleanup paths.
- **Improved debug logging** — `parse_search_response` now emits separate messages for
  "too short", "did not parse as TLV" (with hex data), and "missing IP field".
- **Source port fallback warning** — logs WARNING when port 65535 is unavailable and
  discovery falls back to a random port.

**Lifecycle & reliability**
- **DHCP IP-change reload** — when a configured device gets a new IP via DHCP, the
  integration now calls `async_reload()` after updating the entry, so the coordinator
  reconnects to the new address automatically.
- **Shutdown cleanup** — `coordinator.shutdown()` cancels background transition tasks,
  closes persistent TCP connections, and shuts down the AT client. Called on
  `async_unload_entry`. New `async_remove_entry` hook logs entry removal.
- **Transition mode polling pause** — `_async_update_data()` returns early when
  `_transitioning=True`, preventing polls to a rebooting device.
- **Narrow exceptions** — replaced blanket `except Exception` with specific tuples
  (`TimeoutError`, `OSError`, `UnicodeDecodeError`) in relay/input reads and setup.

**Service targets**
- Service handlers now filter coordinators by `device_id`/`entity_id` targets.
  Only `LOADED` config entries are used. Backward compatible: no targets = all devices.

## Requirements

- Home Assistant ≥ 2025.4
- No external Python packages
