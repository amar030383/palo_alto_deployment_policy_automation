#!/usr/bin/env python3
"""
Palo Alto Firewall Setup - Modular Configuration Automation

Modular functions for configuring Palo Alto firewall from scratch:
  - create_zones()      - Security zones
  - create_interfaces() - VLAN subinterfaces, IPs, zone binding
  - create_nat()        - Source NAT for outgoing traffic
  - create_policies()   - Security policy rules

Device connection is read from environment variables.

Usage:
  python palo_alto_setup.py --config network_config.json --all
  python palo_alto_setup.py --config network_config.json --zones --interfaces --policies --nat
  python palo_alto_setup.py --config network_config.json --zones
  python palo_alto_setup.py --config network_config.json --policies
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
from pathlib import Path

from panos.firewall import Firewall
from panos.network import EthernetInterface, Layer3Subinterface, VirtualRouter, Zone
from panos.objects import AddressObject, ServiceObject
from panos.policies import NatRule, Rulebase, SecurityRule

# ---------------------------------------------------------------------------
# Device Configuration (from environment variables)
# ---------------------------------------------------------------------------

DEVICE = {
    "host": os.getenv("PA_HOST"),
    "port": os.getenv("PA_PORT"),
    "username": os.getenv("PA_USERNAME"),
    "password": os.getenv("PA_PASSWORD"),
    "vsys": os.getenv("PA_VSYS", "vsys1"),
}

LOG = logging.getLogger(__name__)


def get_firewall() -> Firewall:
    """Return configured Firewall instance."""
    if not DEVICE["host"] or not DEVICE["port"]:
        raise ValueError("Set PA_HOST and PA_PORT environment variables before running")
    if not DEVICE["username"] or not DEVICE["password"]:
        raise ValueError("Set PA_USERNAME and PA_PASSWORD environment variables before running")
    try:
        port = int(DEVICE["port"])
    except ValueError as e:
        raise ValueError(f"PA_PORT must be an integer: {DEVICE['port']}") from e
    return Firewall(
        hostname=DEVICE["host"],
        api_username=DEVICE["username"],
        api_password=DEVICE["password"],
        vsys=DEVICE["vsys"],
        port=port,
    )


def load_config(config_path: str) -> dict:
    """Load network configuration from JSON."""
    with open(config_path) as f:
        return json.load(f)


def commit(fw: Firewall) -> None:
    """Commit configuration to firewall."""
    result = fw.commit(sync=True)
    if result:
        LOG.info("Commit successful: %s", result)
    else:
        LOG.warning("Commit returned no result")


# ---------------------------------------------------------------------------
# Module 1: Create Zones
# ---------------------------------------------------------------------------


def create_zones(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create security zones. Zones are created without interfaces first;
    interfaces are bound when create_interfaces() runs.
    Skips 'untrust' - created by create_untrust_interface().
    """
    if fw is None:
        fw = get_firewall()

    zones = [z for z in config.get("zones", []) if z != "untrust"]
    if not zones:
        LOG.warning("No zones in config")
        return False

    for zone_name in zones:
        zone = Zone(name=zone_name, mode="layer3")
        fw.add(zone)
        try:
            zone.create()
            LOG.info("Created zone: %s", zone_name)
        except Exception as e:
            if "already exists" in str(e).lower() or "ObjectAlreadyExists" in str(e):
                LOG.info("Zone %s already exists", zone_name)
            else:
                LOG.error("Failed to create zone %s: %s", zone_name, e)
                raise

    if commit_config:
        commit(fw)
    return True


# ---------------------------------------------------------------------------
# Module 2: Create Interfaces (VLANs, subnets)
# ---------------------------------------------------------------------------


def create_interfaces(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create VLAN subinterfaces with IPs and bind to zones.
    Requires: parent trunk interface (e.g. ethernet1/1), virtual router.
    """
    if fw is None:
        fw = get_firewall()

    vlans = config.get("vlans", [])
    iface_settings = config.get("interface_settings", {})
    trunk = iface_settings.get("vlan_trunk_interface", "ethernet1/1")

    # Ensure virtual router exists
    vr = VirtualRouter("default")
    fw.add(vr)
    try:
        vr.create()
        LOG.info("Virtual router default ready")
    except Exception as e:
        if "already exists" in str(e).lower():
            pass
        else:
            LOG.debug("Virtual router: %s", e)

    # Parent interface in layer3 mode for subinterfaces
    parent = EthernetInterface(trunk, mode="layer3")
    fw.add(parent)
    try:
        parent.create()
        LOG.info("Parent interface %s ready", trunk)
    except Exception as e:
        if "already exists" in str(e).lower():
            pass
        else:
            LOG.debug("Parent interface: %s", e)

    for vlan in vlans:
        vlan_id = vlan["vlan_id"]
        gateway = vlan["gateway"]
        zone_name = vlan["zone"]
        sub_name = f"{trunk}.{vlan_id}"

        sub = Layer3Subinterface(
            name=sub_name,
            tag=vlan_id,
            ip=gateway,
        )
        parent.add(sub)
        try:
            sub.create()
            sub.set_virtual_router("default", update=True)
            LOG.info("Created subinterface %s with IP %s", sub_name, gateway)
        except Exception as e:
            if "already exists" in str(e).lower():
                LOG.info("Subinterface %s already exists", sub_name)
            else:
                LOG.error("Failed to create %s: %s", sub_name, e)
                raise

        # Add interface to zone
        zone = Zone(name=zone_name, mode="layer3", interface=[sub_name])
        fw.add(zone)
        try:
            zone.apply()
            LOG.info("Bound %s to zone %s", sub_name, zone_name)
        except Exception as e:
            LOG.warning("Zone update for %s: %s", zone_name, e)

    if commit_config:
        commit(fw)
    return True


# ---------------------------------------------------------------------------
# Module 3: Create NAT
# ---------------------------------------------------------------------------


def create_nat(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create source NAT rule for outgoing traffic (internal zones -> untrust).
    """
    if fw is None:
        fw = get_firewall()

    nat_cfg = config.get("nat", {})
    if not nat_cfg.get("enabled", True):
        LOG.info("NAT disabled in config")
        return False

    rule_cfg = nat_cfg.get("outgoing_rule", {})
    if not rule_cfg:
        LOG.warning("No outgoing NAT rule in config")
        return False

    rulebase = Rulebase()
    fw.add(rulebase)

    nat_rule = NatRule(
        name=rule_cfg.get("name", "outgoing-source-nat"),
        description=rule_cfg.get("description", "NAT for outgoing traffic"),
        fromzone=rule_cfg.get("from_zones", ["any"]),
        tozone=[rule_cfg.get("to_zone", "untrust")],
        source=["any"],
        destination=["any"],
        source_translation_type=rule_cfg.get("source_translation_type", "dynamic-ip-and-port"),
        source_translation_address_type="interface-address",
        source_translation_interface=rule_cfg.get("source_translation_interface", "ethernet1/2"),
    )
    rulebase.add(nat_rule)
    try:
        nat_rule.apply()
        LOG.info("Applied NAT rule: %s", nat_rule.name)
    except Exception as e:
        LOG.error("Failed to apply NAT rule: %s", e)
        raise

    if commit_config:
        commit(fw)
    return True


# ---------------------------------------------------------------------------
# Module 4: Create Security Policies
# ---------------------------------------------------------------------------


def create_policies(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create security policy rules from config.
    """
    if fw is None:
        fw = get_firewall()

    policies = config.get("policies", [])
    if not policies:
        LOG.warning("No policies in config")
        return False

    rulebase = Rulebase()
    fw.add(rulebase)

    # Ensure referenced service objects exist
    service_map = ensure_service_objects(config, fw)

    for pol in policies:
        mapped_services = []
        for svc in pol.get("service", ["application-default"]):
            mapped_services.append(service_map.get(svc, svc))
        rule = SecurityRule(
            name=pol["name"],
            fromzone=[pol["source_zone"]],
            tozone=[pol["destination_zone"]],
            source=pol.get("source", ["any"]),
            destination=pol.get("destination", ["any"]),
            service=mapped_services,
            action="allow",
            description=pol.get("description", ""),
            log_start=True,
            log_end=False,
        )
        rulebase.add(rule)
        try:
            rule.apply()
            LOG.info("Applied security rule: %s", pol["name"])
        except Exception as e:
            LOG.error("Failed to apply rule %s: %s", pol["name"], e)
            raise

    if commit_config:
        commit(fw)
    return True


def ensure_service_objects(config: dict, fw: Firewall) -> dict[str, str]:
    """
    Create service objects for 'tcp/port' or 'udp/port-range' tokens used in policy config.
    Returns a map of raw token to service object name.
    """
    service_specs = set()
    for pol in config.get("policies", []):
        for svc in pol.get("service", []):
            service_specs.add(svc.strip())

    service_map: dict[str, str] = {}
    for spec in sorted(service_specs):
        if "/" not in spec:
            # Already an existing object keyword like 'application-default' or 'any'
            service_map[spec] = spec
            continue

        proto, port = spec.split("/", 1)
        proto = proto.strip().lower()
        port = port.strip()
        if proto not in ("tcp", "udp"):
            service_map[spec] = spec
            continue

        obj_name = f"svc-{proto}-{port.replace(',', '-').replace('/', '-')}"
        svc_obj = ServiceObject(name=obj_name, protocol=proto, destination_port=port)
        fw.add(svc_obj)
        try:
            svc_obj.create()
            LOG.info("Created service object: %s (%s/%s)", obj_name, proto, port)
        except Exception as e:
            if "already exists" in str(e).lower():
                LOG.info("Service object %s already exists", obj_name)
            else:
                LOG.error("Failed creating service object %s: %s", obj_name, e)
                raise
        service_map[spec] = obj_name

    return service_map


# ---------------------------------------------------------------------------
# Module 5: Create Host Address Objects
# ---------------------------------------------------------------------------


def create_host_objects(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create host address objects from every configured subnet.
    Default pattern per subnet: *.10/32 and *.99/32
    Example names: h_obj_172.18.70.10, h_obj_172.18.70.99
    """
    if fw is None:
        fw = get_firewall()

    vlans = config.get("vlans", [])
    if not vlans:
        LOG.warning("No VLAN subnets in config")
        return False

    host_suffixes = config.get("host_objects", {}).get("host_suffixes", [10, 99])
    prefix = config.get("host_objects", {}).get("name_prefix", "h_obj")

    created = 0
    for vlan in vlans:
        subnet = vlan.get("subnet")
        if not subnet:
            continue

        net = ipaddress.ip_network(subnet, strict=False)
        # IPv4-only for current environment
        if net.version != 4:
            continue

        octets = str(net.network_address).split(".")
        # Build base from first three octets (for /24 style naming)
        base = ".".join(octets[:3])

        for suffix in host_suffixes:
            ip_str = f"{base}.{suffix}"
            obj_name = f"{prefix}_{base}.{suffix}"
            addr = AddressObject(name=obj_name, value=f"{ip_str}/32", type="ip-netmask")
            fw.add(addr)
            try:
                addr.apply()
                LOG.info("Applied host object: %s -> %s/32", obj_name, ip_str)
                created += 1
            except Exception as e:
                if "already exists" in str(e).lower():
                    LOG.info("Host object %s already exists", obj_name)
                else:
                    LOG.error("Failed host object %s: %s", obj_name, e)
                    raise

    if created == 0:
        LOG.warning("No host objects created")
    if commit_config:
        commit(fw)
    return True


# ---------------------------------------------------------------------------
# Optional: Create untrust zone and interface for NAT
# ---------------------------------------------------------------------------


def create_untrust_interface(config: dict, fw: Firewall | None = None, commit_config: bool = True) -> bool:
    """
    Create untrust zone and egress interface for NAT.
    Call this before create_nat() if untrust does not exist.
    """
    if fw is None:
        fw = get_firewall()

    iface_settings = config.get("interface_settings", {})
    untrust_iface = iface_settings.get("untrust_interface", "ethernet1/2")

    # Create untrust zone (without interface first)
    zone = Zone(name="untrust", mode="layer3")
    fw.add(zone)
    try:
        zone.create()
        LOG.info("Created untrust zone")
    except Exception as e:
        if "already exists" in str(e).lower():
            LOG.info("Untrust zone already exists")
        else:
            LOG.debug("Untrust zone: %s", e)

    # Create egress interface (DHCP or static - using DHCP as placeholder)
    eth = EthernetInterface(untrust_iface, mode="layer3")
    fw.add(eth)
    try:
        eth.create()
        LOG.info("Created untrust interface %s", untrust_iface)
    except Exception as e:
        if "already exists" in str(e).lower():
            LOG.info("Interface %s already exists", untrust_iface)
        else:
            LOG.debug("Interface: %s", e)

    # Bind untrust interface to untrust zone
    zone_bind = Zone(name="untrust", mode="layer3", interface=[untrust_iface])
    fw.add(zone_bind)
    try:
        zone_bind.apply()
        LOG.info("Bound %s to untrust zone", untrust_iface)
    except Exception as e:
        LOG.warning("Failed to bind %s to untrust zone: %s", untrust_iface, e)

    if commit_config:
        commit(fw)
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Palo Alto Firewall Setup")
    parser.add_argument("--config", "-c", default="network_config.json", help="Path to network config JSON")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--zones", action="store_true", help="Create zones only")
    parser.add_argument("--interfaces", action="store_true", help="Create VLAN interfaces only")
    parser.add_argument("--nat", action="store_true", help="Create NAT rules only")
    parser.add_argument("--policies", action="store_true", help="Create security policies only")
    parser.add_argument("--objects", action="store_true", help="Create host address objects only")
    parser.add_argument("--untrust", action="store_true", help="Create untrust zone/interface for NAT")
    parser.add_argument("--no-commit", action="store_true", help="Do not commit after each module")
    parser.add_argument("--dry-run", action="store_true", help="Load config and validate only")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        LOG.error("Config not found: %s", config_path)
        return 1

    config = load_config(str(config_path))
    LOG.info("Loaded config: %d zones, %d vlans, %d policies",
             len(config.get("zones", [])),
             len(config.get("vlans", [])),
             len(config.get("policies", [])))

    if args.dry_run:
        LOG.info("Dry run - config validated")
        return 0

    run_all = args.all or not any([args.zones, args.interfaces, args.nat, args.policies, args.objects, args.untrust])
    commit_each = not args.no_commit

    fw = get_firewall()

    try:
        if run_all or args.untrust:
            create_untrust_interface(config, fw, commit_config=commit_each)
        if run_all or args.zones:
            create_zones(config, fw, commit_config=commit_each)
        if run_all or args.interfaces:
            create_interfaces(config, fw, commit_config=commit_each)
        if run_all or args.nat:
            create_nat(config, fw, commit_config=commit_each)
        if run_all or args.policies:
            create_policies(config, fw, commit_config=commit_each)
        if run_all or args.objects:
            create_host_objects(config, fw, commit_config=commit_each)
    except Exception as e:
        LOG.exception("Setup failed: %s", e)
        return 1

    LOG.info("Setup complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
