# Palo Alto Setup Automation

This README is specifically for `deployment_one_time/palo_alto_setup.py` (fresh firewall setup).

## Current Status

The setup flow has been successfully tested on the target firewall with:

- zones created
- VLAN subinterfaces (`801` to `806`) created and mapped
- outgoing source NAT created
- service objects auto-created from policy ports
- security policies created
- host objects generated from every subnet (`*.10` and `*.99`)
- commits completed successfully

## Lab Inventory (Deployed)

### Zones

- `trust`, `dmz`
- `embedded`, `printer`, `cameras`, `voip`, `internal-tools`
- `k8sm01`, `k8sm02`
- `untrust`

### VLANs / Subnets

| VLAN | Subnet | Gateway | Zone |
|---|---|---|---|
| 10 | `192.168.10.0/24` | `192.168.10.1` | `trust` |
| 20 | `192.168.20.0/24` | `192.168.20.1` | `dmz` |
| 970 | `172.18.70.0/24` | `172.18.70.1` | `embedded` |
| 971 | `172.18.71.0/24` | `172.18.71.1` | `printer` |
| 972 | `172.18.72.0/24` | `172.18.72.1` | `cameras` |
| 973 | `172.18.73.0/24` | `172.18.73.1` | `voip` |
| 974 | `172.18.74.0/24` | `172.18.74.1` | `internal-tools` |
| 801 | `172.18.4.0/24` | `172.18.4.1` | `k8sm01` |
| 802 | `172.18.2.0/24` | `172.18.2.1` | `k8sm01` |
| 803 | `172.18.5.0/24` | `172.18.5.1` | `k8sm01` |
| 804 | `172.18.6.0/24` | `172.18.6.1` | `k8sm02` |
| 805 | `172.18.7.0/24` | `172.18.7.1` | `k8sm02` |
| 806 | `172.18.8.0/24` | `172.18.8.1` | `k8sm02` |

### NAT

- Outbound source NAT rule: `outgoing-source-nat`
- From zones: `trust`, `dmz`, `embedded`, `printer`, `cameras`, `voip`, `internal-tools`, `k8sm01`, `k8sm02`
- To zone: `untrust`
- Translation interface: `ethernet1/2`

### Security Policies

- `vlan10-trust-to-vlan20-dmz-db`
- `k8ms01-cp-to-agents`
- `k8ms01-lb-to-agents`
- `k8ms01-lb-to-ms02-agents`
- `k8ms02-cp-to-agents`
- `k8ms02-lb-to-agents`

### Host Objects

- Generated from every configured subnet using:
  - Name pattern: `h_obj_<x.y.z>.10`, `h_obj_<x.y.z>.99`
  - Address pattern: `<x.y.z>.10/32`, `<x.y.z>.99/32`

## What It Configures

- Security zones
- VLAN subinterfaces and gateway IPs
- Outbound source NAT
- Security policies
- Host address objects (from every subnet)

## Environment Variables

Credentials are read from environment variables:

- `PA_HOST` (**required**)
- `PA_PORT` (**required**)
- `PA_VSYS` (default: `vsys1`)
- `PA_USERNAME` (**required**)
- `PA_PASSWORD` (**required**)

Example:

```bash
export PA_HOST="your-firewall-hostname-or-ip"
export PA_PORT="443"
export PA_VSYS="vsys1"
export PA_USERNAME="admin"
export PA_PASSWORD="your-password"
```

## Config File

Use `deployment_one_time/network_config.json` for:

- zones
- VLANs/subnets
- policies
- NAT settings
- interface mapping
- host object generation settings (`host_objects`)

## Run

```bash
# all modules
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --all

# specific modules
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --zones
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --interfaces
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --nat
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --policies
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --untrust
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --objects
```

## Day-2 Operations (Safe Updates)

- **Only VLAN/Zone changes**:
  - `python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --zones --interfaces`
- **Only NAT changes**:
  - `python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --nat`
- **Only policy changes**:
  - `python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --policies`
- **Only host objects**:
  - `python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --objects`

## Recommended Execution Order

For first-time setup:

```bash
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --all
```

If running in steps:

```bash
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --untrust
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --zones
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --interfaces
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --nat
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --policies
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --objects
```

## Expected Success Indicators

You should see logs similar to:

- `Commit successful`
- `Created zone: <zone-name>`
- `Created subinterface ethernet1/1.<vlan-id>`
- `Created NAT rule: outgoing-source-nat`
- `Applied security rule: <rule-name>`
- `Applied host object: h_obj_<subnet>.10 -> <ip>/32`
- `Setup complete`

## Verification Checklist (GUI)

- `Network -> Interfaces`: verify subinterfaces `ethernet1/1.<vlan>`
- `Network -> Zones`: verify each zone has expected interfaces
- `Policies -> NAT`: verify `outgoing-source-nat`
- `Policies -> Security`: verify expected rule names
- `Objects -> Addresses`: verify `h_obj_*` objects

## Troubleshooting

- **`python: command not found`**  
  Use `python3.11` explicitly.

- **`No module named distutils` with Python 3.14**  
  Use Python `3.11`; `pan-os-python` is not compatible with Python 3.14.

- **NAT or policy reference errors**  
  Re-run module-by-module and verify `deployment_one_time/network_config.json` zone/interface names match actual device config.

- **Warnings: interface already in use / zone layer3 invalid**  
  Common during re-apply on existing config. If final commit is successful and expected mappings are present, this is usually non-fatal.

## Notes

- Use Python `3.11` for `pan-os-python` compatibility.
- If credentials are missing, the script exits with a clear error.
