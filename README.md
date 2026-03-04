# Palo Alto Firewall Automation

Two automation scripts for Palo Alto firewalls:

1. **palo_alto_setup.py** – Modular setup from scratch (zones, VLANs, interfaces, NAT, policies)
2. **palo_alto_rule_automation.py** – Policy rule automation (REST API, JSON input)

Setup-specific instructions are in `README_SETUP.md`.

---

## palo_alto_setup.py – Full Configuration

Modular functions for configuring a fresh Palo Alto firewall:

| Module | Function | Description |
|--------|----------|-------------|
| Zones | `create_zones()` | Security zones |
| Interfaces | `create_interfaces()` | VLAN subinterfaces, IPs, zone binding |
| NAT | `create_nat()` | Source NAT for outgoing traffic |
| Policies | `create_policies()` | Security policy rules |

**Device and credentials** are read from environment variables. See `README_SETUP.md`.

```bash
# Run all modules
python3.11 palo_alto_setup.py --config network_config.json --all

# Run specific modules
python3.11 palo_alto_setup.py --config network_config.json --zones --interfaces
python3.11 palo_alto_setup.py --config network_config.json --policies
python3.11 palo_alto_setup.py --config network_config.json --nat

# Create untrust zone/interface first (for NAT)
python3.11 palo_alto_setup.py --config network_config.json --untrust
```

**network_config.json** – Edit `interface_settings` to match your hardware:
- `vlan_trunk_interface`: Physical port for VLANs (default: ethernet1/1)
- `untrust_interface`: Egress port for NAT (default: ethernet1/2)

---

## palo_alto_rule_automation.py – Policy Rules

End-to-end Python automation for creating security policy rules. Follows a 5-phase flow from user input through policy deployment.

## Flow Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: USER INPUT                                                         │
│  Collect: source, destination, destination_ports, protocol, action, zones   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: CONNECTION & DATA COLLECTION                                      │
│  • Connect via REST API (API key auth)                                       │
│  • Gather: zones, interfaces, virtual routers, address objects, services    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: CORRELATION & VALIDATION                                          │
│  • Validate source/dest against zones and existing objects                   │
│  • Determine: create address objects? create service object?                 │
│  • Build deployment plan                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 4: PAYLOAD PREPARATION                                                │
│  • Build address object payloads (if new IPs/CIDRs)                          │
│  • Build service object payload (if custom ports)                             │
│  • Build security rule payload                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 5: PUSH TO FIREWALL                                                  │
│  • POST address objects                                                      │
│  • POST service object                                                       │
│  • POST security rule                                                        │
│  • Commit configuration (XML API)                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## JSON Input Format

```json
{
  "rule_name": "allow-web-to-db",
  "description": "Allow web servers to reach database",
  "source": "192.168.10.0/24",
  "destination": "192.168.20.10",
  "destination_ports": "5432",
  "protocol": "tcp",
  "action": "allow",
  "source_zone": "trust",
  "destination_zone": "dmz",
  "application": "any",
  "log_start": true,
  "log_end": false
}
```

Alternatively, wrap in a `policy` key: `{"policy": { ... }}`

## Phase 1: User Input

| Field | Required | Description |
|-------|----------|-------------|
| `rule_name` | Yes | Alphanumeric name (e.g. `allow-web-to-db`) |
| `source` | Yes | Source IP, CIDR, `any`, or zone name |
| `destination` | Yes | Destination IP, CIDR, `any`, or zone name |
| `destination_ports` | Yes | Port(s): `443`, `80,443`, `8080-8090` |
| `protocol` | Yes | `tcp`, `udp`, or `any` |
| `action` | Yes | `allow` or `deny` |
| `source_zone` | No | Zone name (e.g. `trust`) |
| `destination_zone` | No | Zone name (e.g. `untrust`) |
| `description` | No | Rule description |
| `application` | No | `any` or app name (default: `any`) |
| `log_start` | No | Log session start (default: true) |
| `log_end` | No | Log session end (default: false) |

## Phase 2: Connection & Data Collection

- **Authentication**: API key via `X-PAN-KEY` header or `key` query param
- **Endpoints used**:
  - `GET /restapi/v11.0/Network/Zones` – zones
  - `GET /restapi/v11.0/Network/EthernetInterfaces` – interfaces
  - `GET /restapi/v11.0/Network/VirtualRouters` – routing
  - `GET /restapi/v11.0/Objects/Addresses` – address objects
  - `GET /restapi/v11.0/Objects/Services` – service objects
  - `GET /restapi/v11.0/Policies/SecurityRules` – existing rules

## Phase 3: Correlation & Validation

- Validates source/destination against existing address objects and zones
- Creates address objects when source/destination are new IPs or CIDRs
- Creates service object when custom ports are used

## Phase 4: Payload Preparation

- Address objects: `ip-netmask` format (e.g. `192.168.1.0/24`)
- Service objects: `protocol.tcp.port` or `protocol.udp.port`
- Security rule: `source`, `destination`, `service`, `from`, `to`, `action`, etc.

## Phase 5: Push

1. Create address objects (if needed)
2. Create service object (if needed)
3. Create security rule
4. Commit via XML API

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

- **Device**: Edit the `DEVICE` dict at the top of `palo_alto_rule_automation.py` (host, api_key, vsys, etc.)
- **Input**: JSON payload file with policy fields

## Usage

```bash
# Dry run (validate and plan only)
python palo_alto_rule_automation.py --input input.example.json --dry-run

# Create rule and commit
python palo_alto_rule_automation.py --input policy.json

# Create rule without commit
python palo_alto_rule_automation.py --input policy.json --no-commit
```

## API Key

Generate an API key on the firewall:

1. Device → Setup → Management
2. API Key section → Generate API Key

## Requirements

- PAN-OS 8.1+ with REST API enabled
- Python 3.9+
- `requests`

## GitHub Safety Checklist

Before pushing this project to GitHub:

- Do not commit real credentials (`PA_USERNAME`, `PA_PASSWORD`, `PA_API_KEY`)
- Keep secrets only in shell environment or a local `.env` file
- Ensure local virtual environment is not committed (`.venv/` is ignored)
- Avoid committing private cert/key files (`*.pem`, `*.key`, `*.crt`)
- If credentials were ever committed, rotate them immediately before publishing

## Virtual Environment Setup

```bash
# 1) Create venv (recommended Python 3.11 for this project)
python3.11 -m venv .venv

# 2) Activate venv
source .venv/bin/activate

# 3) Install dependencies
pip install -r requirements.txt

# 4) Run automation
python palo_alto_rule_automation.py --input input.example.json --dry-run
```

To deactivate:

```bash
deactivate
```
