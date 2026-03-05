#!/usr/bin/env python3
"""
Palo Alto Firewall Rule Automation - End-to-End Flow

This script automates the complete lifecycle of creating security policy rules on
Palo Alto firewalls:

  Phase 1: User Input     - Collect policy requirements (source, destination, ports, etc.)
  Phase 2: Connection     - Connect to firewall and gather topology (zones, interfaces, routing)
  Phase 3: Correlation    - Validate and correlate user input with firewall state
  Phase 4: Payload Prep   - Build address objects, service objects, and rule payload
  Phase 5: Push           - Create objects, create rule, commit configuration

Usage:
  python palo_alto_rule_automation.py --input policy.json
  python palo_alto_rule_automation.py --input policy.json --dry-run
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests

# ---------------------------------------------------------------------------
# Device Configuration (environment variables only)
# ---------------------------------------------------------------------------

DEVICE = {
    "host": os.getenv("PA_HOST"),
    "port": os.getenv("PA_PORT"),
    "api_key": os.getenv("PA_API_KEY"),
    "username": os.getenv("PA_USERNAME"),
    "password": os.getenv("PA_PASSWORD"),
    "vsys": os.getenv("PA_VSYS", "vsys1"),
    "api_version": os.getenv("PA_API_VERSION"),
    "verify_ssl": os.getenv("PA_VERIFY_SSL", "false").lower() == "true",
}

API_VERSION_CANDIDATES = ["v12.1", "v11.2", "v11.1", "v11.0", "v10.2", "v10.1", "v10.0", "v9.1"]

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

LOG = logging.getLogger(__name__)


@dataclass
class PolicyRequest:
    """User-provided policy requirements (Phase 1 input)."""

    rule_name: str
    source: str  # IP, CIDR, or zone name
    destination: str  # IP, CIDR, or zone name
    destination_ports: str  # e.g. "443", "80,443", "8080-8090"
    description: str = ""
    protocol: str = "tcp"  # tcp, udp, or any
    action: str = "allow"  # allow or deny
    source_zone: Optional[str] = None  # Optional: trust, untrust, etc.
    destination_zone: Optional[str] = None
    application: str = "any"  # any or specific app names
    log_start: bool = True
    log_end: bool = False
    validate_existing_subnets: bool = True


@dataclass
class FirewallContext:
    """Data gathered from firewall (Phase 2)."""

    zones: list[dict] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)
    virtual_routers: list[dict] = field(default_factory=list)
    address_objects: list[dict] = field(default_factory=list)
    service_objects: list[dict] = field(default_factory=list)
    existing_rules: list[dict] = field(default_factory=list)
    logical_interfaces: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 1: User Input Collection
# ---------------------------------------------------------------------------


def load_policy_from_json(input_path: str) -> PolicyRequest:
    """Load policy request from JSON payload file."""
    with open(input_path) as f:
        data = json.load(f)

    policy = data.get("policy", data)
    return PolicyRequest(
        rule_name=policy["rule_name"],
        source=policy["source"],
        destination=policy["destination"],
        destination_ports=policy["destination_ports"],
        description=policy.get("description", ""),
        protocol=policy.get("protocol", "tcp"),
        action=policy.get("action", "allow"),
        source_zone=policy.get("source_zone"),
        destination_zone=policy.get("destination_zone"),
        application=policy.get("application", "any"),
        log_start=policy.get("log_start", True),
        log_end=policy.get("log_end", False),
        validate_existing_subnets=policy.get("validate_existing_subnets", True),
    )


def validate_policy_request(req: PolicyRequest) -> list[str]:
    """Validate user input. Returns list of error messages."""
    errors = []
    if not req.rule_name or not re.match(r"^[a-zA-Z0-9_-]+$", req.rule_name):
        errors.append("rule_name must be alphanumeric with - or _ only")
    if not req.source:
        errors.append("source is required")
    if not req.destination:
        errors.append("destination is required")
    if not req.destination_ports:
        errors.append("destination_ports is required")
    if req.protocol.lower() not in ("tcp", "udp", "any"):
        errors.append("protocol must be tcp, udp, or any")
    if req.action.lower() not in ("allow", "deny"):
        errors.append("action must be allow or deny")
    return errors


def generate_api_key(host: str, port: int, username: str, password: str, verify_ssl: bool) -> str:
    """Generate PAN-OS API key from username/password."""
    from urllib.parse import quote

    keygen_url = f"https://{host}:{port}/api/?type=keygen&user={quote(username)}&password={quote(password)}"
    resp = requests.get(keygen_url, verify=verify_ssl, timeout=30)
    resp.raise_for_status()
    m = re.search(r"<key>([^<]+)</key>", resp.text)
    if not m:
        raise RuntimeError("Could not parse API key from keygen response")
    return m.group(1)


def detect_api_version(host: str, port: int, api_key: str, verify_ssl: bool, preferred: Optional[str] = None) -> str:
    """
    Detect a working REST API version by probing known endpoints.
    If preferred is provided (PA_API_VERSION), try it first.
    """
    versions = []
    if preferred:
        versions.append(preferred)
    versions.extend([v for v in API_VERSION_CANDIDATES if v not in versions])

    for version in versions:
        base = f"https://{host}:{port}/restapi/{version}/Network/Zones"
        # Most versions accept location/vsys for zones endpoint.
        attempts = [
            {"location": "vsys", "vsys": DEVICE["vsys"]},
            {},
        ]
        for params in attempts:
            try:
                r = requests.get(
                    base,
                    headers={"X-PAN-KEY": api_key},
                    params=params,
                    verify=verify_ssl,
                    timeout=15,
                )
                # 200 means supported endpoint
                if r.status_code == 200:
                    return version
            except Exception:
                continue

    raise RuntimeError("Could not detect a working REST API version for this firewall")


# ---------------------------------------------------------------------------
# Phase 2: Firewall Connection & Data Collection
# ---------------------------------------------------------------------------


class PaloAltoClient:
    """REST API client for Palo Alto firewall."""

    def __init__(
        self,
        host: str,
        port: int,
        api_key: str,
        api_version: str = "v11.0",
        vsys: str = "vsys1",
        verify_ssl: bool = False,
    ):
        self.base_url = f"https://{host}:{port}/restapi/{api_version}/"
        self.xml_api_url = f"https://{host}:{port}/api/"
        self.api_key = api_key
        self.vsys = vsys
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers["X-PAN-KEY"] = api_key
        self.session.headers["Content-Type"] = "application/json"
        self.session.verify = verify_ssl

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = urljoin(self.base_url, path)
        r = self.session.get(url, params=params or {}, timeout=30)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, params: Optional[dict] = None, json_body: Optional[dict] = None) -> dict:
        url = urljoin(self.base_url, path)
        r = self.session.post(url, params=params or {}, json=json_body, timeout=30)
        r.raise_for_status()
        return r.json() if r.text else {}

    def _put(self, path: str, params: Optional[dict] = None, json_body: Optional[dict] = None) -> dict:
        url = urljoin(self.base_url, path)
        r = self.session.put(url, params=params or {}, json=json_body, timeout=30)
        r.raise_for_status()
        return r.json() if r.text else {}

    def _delete(self, path: str, params: Optional[dict] = None) -> None:
        url = urljoin(self.base_url, path)
        r = self.session.delete(url, params=params or {}, timeout=30)
        r.raise_for_status()

    def test_connection(self) -> bool:
        """Verify API connectivity."""
        try:
            self._get("Policies/SecurityRules", params={"location": "vsys", "vsys": self.vsys})
            return True
        except Exception as e:
            LOG.error("Connection test failed: %s", e)
            return False

    def get_zones(self) -> list[dict]:
        """Fetch security zones."""
        try:
            data = self._get("Network/Zones", params={"location": "vsys", "vsys": self.vsys})
            entries = data.get("result", {}).get("entry", [])
            return entries if isinstance(entries, list) else [entries] if entries else []
        except Exception as e:
            LOG.warning("Could not fetch zones: %s", e)
            return []

    def get_interfaces(self) -> list[dict]:
        """Fetch network interfaces."""
        # Different PAN-OS versions handle query params differently for this endpoint.
        param_attempts = [
            {"location": "vsys", "vsys": self.vsys},
            {},
        ]
        for params in param_attempts:
            try:
                data = self._get("Network/EthernetInterfaces", params=params)
                entries = data.get("result", {}).get("entry", [])
                return entries if isinstance(entries, list) else [entries] if entries else []
            except Exception:
                continue
        LOG.warning("Could not fetch interfaces from REST API")
        return []

    def get_virtual_routers(self) -> list[dict]:
        """Fetch virtual routers and routing info."""
        param_attempts = [
            {"location": "vsys", "vsys": self.vsys},
            {},
        ]
        for params in param_attempts:
            try:
                data = self._get("Network/VirtualRouters", params=params)
                entries = data.get("result", {}).get("entry", [])
                return entries if isinstance(entries, list) else [entries] if entries else []
            except Exception:
                continue
        LOG.warning("Could not fetch virtual routers from REST API")
        return []

    def get_address_objects(self) -> list[dict]:
        """Fetch address objects."""
        try:
            data = self._get("Objects/Addresses", params={"location": "vsys", "vsys": self.vsys})
            entries = data.get("result", {}).get("entry", [])
            return entries if isinstance(entries, list) else [entries] if entries else []
        except Exception as e:
            LOG.warning("Could not fetch address objects: %s", e)
            return []

    def get_service_objects(self) -> list[dict]:
        """Fetch service objects."""
        try:
            data = self._get("Objects/Services", params={"location": "vsys", "vsys": self.vsys})
            entries = data.get("result", {}).get("entry", [])
            return entries if isinstance(entries, list) else [entries] if entries else []
        except Exception as e:
            LOG.warning("Could not fetch service objects: %s", e)
            return []

    def get_security_rules(self) -> list[dict]:
        """Fetch existing security rules."""
        try:
            data = self._get("Policies/SecurityRules", params={"location": "vsys", "vsys": self.vsys})
            entries = data.get("result", {}).get("entry", [])
            return entries if isinstance(entries, list) else [entries] if entries else []
        except Exception as e:
            LOG.warning("Could not fetch security rules: %s", e)
            return []

    def get_interface_zone_ip_map(self) -> list[dict]:
        """
        Build interface->zone->IP mapping using REST data only.
        Combines Network/Zones and Network/EthernetInterfaces responses.
        """
        rows: list[dict] = []
        try:
            zones = self.get_zones()
            interfaces = self.get_interfaces()

            iface_to_ips: dict[str, list[str]] = {}
            for iface in interfaces:
                iface_name = iface.get("@name") or iface.get("name")
                if not iface_name:
                    continue
                ips: list[str] = []
                for cidr in _extract_cidrs_from_obj(iface):
                    try:
                        ip_obj = ipaddress.ip_interface(cidr).ip
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            ips.append(str(ip_obj))
                    except ValueError:
                        continue
                if ips:
                    iface_to_ips[iface_name] = sorted(set(ips))

            for zone in zones:
                zone_name = zone.get("@name") or zone.get("name")
                if not zone_name:
                    continue
                members = ((zone.get("network") or {}).get("layer3") or {}).get("member")
                if isinstance(members, str):
                    members = [members]
                if not isinstance(members, list):
                    continue

                for member in members:
                    for ip_str in iface_to_ips.get(member, []):
                        rows.append({"name": member, "zone": zone_name, "ip": ip_str})

            return rows
        except Exception as e:
            LOG.warning("Could not build interface-zone map from REST API: %s", e)
            return []

    def gather_context(self) -> FirewallContext:
        """Collect all firewall topology and object data."""
        LOG.info("Gathering firewall context...")
        ctx = FirewallContext(
            zones=self.get_zones(),
            interfaces=self.get_interfaces(),
            virtual_routers=self.get_virtual_routers(),
            address_objects=self.get_address_objects(),
            service_objects=self.get_service_objects(),
            existing_rules=self.get_security_rules(),
            logical_interfaces=self.get_interface_zone_ip_map(),
        )
        LOG.info(
            "Context: %d zones, %d interfaces, %d address objects, %d services, %d rules",
            len(ctx.zones),
            len(ctx.interfaces),
            len(ctx.address_objects),
            len(ctx.service_objects),
            len(ctx.existing_rules),
        )
        return ctx


# ---------------------------------------------------------------------------
# Phase 3: Correlation & Validation
# ---------------------------------------------------------------------------


def is_ip_or_cidr(s: str) -> bool:
    """Check if string is IP or CIDR."""
    if s.lower() in ("any",):
        return False
    # Simple CIDR or IP
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", s):
        return True
    return False


def get_existing_address_names(ctx: FirewallContext) -> set[str]:
    """Extract address object names from context."""
    names = set()
    for obj in ctx.address_objects:
        name = obj.get("@name") or obj.get("name")
        if name:
            names.add(name)
    return names


def get_existing_service_names(ctx: FirewallContext) -> set[str]:
    """Extract service object names from context."""
    names = set()
    for obj in ctx.service_objects:
        name = obj.get("@name") or obj.get("name")
        if name:
            names.add(name)
    return names


def get_zone_names(ctx: FirewallContext) -> set[str]:
    """Extract zone names from context."""
    names = set()
    for z in ctx.zones:
        name = z.get("@name") or z.get("name")
        if name:
            names.add(name)
    return names


def _extract_cidrs_from_obj(obj: Any) -> set[str]:
    """Recursively extract IPv4 CIDR strings from arbitrary dict/list structures."""
    found = set()
    if isinstance(obj, dict):
        for v in obj.values():
            found |= _extract_cidrs_from_obj(v)
    elif isinstance(obj, list):
        for item in obj:
            found |= _extract_cidrs_from_obj(item)
    elif isinstance(obj, str):
        # Match strings like 172.18.70.1/24
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", obj.strip()):
            found.add(obj.strip())
        # Some REST responses return interface IPs without prefix length.
        elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", obj.strip()):
            found.add(f"{obj.strip()}/32")
    return found


def get_existing_subnets(ctx: FirewallContext) -> set[str]:
    """
    Build known subnet set from interface IP CIDRs and address objects.
    Converts host-ip CIDRs to network CIDRs (e.g. 172.18.70.1/24 -> 172.18.70.0/24).
    """
    subnets: set[str] = set()

    # From interfaces
    for iface in ctx.interfaces:
        for cidr in _extract_cidrs_from_obj(iface):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    subnets.add(str(net))
            except ValueError:
                pass

    # From address objects
    for addr in ctx.address_objects:
        cidr = addr.get("ip-netmask")
        if isinstance(cidr, str):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    subnets.add(str(net))
            except ValueError:
                pass

    return subnets


def get_known_ipv4_ips(ctx: FirewallContext) -> set[ipaddress.IPv4Address]:
    """
    Collect individual IPv4 addresses seen on firewall objects/interfaces.
    Useful when subnet endpoints are not exposed but host objects exist.
    """
    ips: set[ipaddress.IPv4Address] = set()

    for iface in ctx.interfaces:
        for cidr in _extract_cidrs_from_obj(iface):
            try:
                iface_ip = ipaddress.ip_interface(cidr).ip
                if isinstance(iface_ip, ipaddress.IPv4Address):
                    ips.add(iface_ip)
            except ValueError:
                pass

    for addr in ctx.address_objects:
        cidr = addr.get("ip-netmask")
        if isinstance(cidr, str):
            try:
                iface_ip = ipaddress.ip_interface(cidr).ip
                if isinstance(iface_ip, ipaddress.IPv4Address):
                    ips.add(iface_ip)
            except ValueError:
                pass

    return ips


def subnet_exists(value: str, known_subnets: set[str], known_ips: set[ipaddress.IPv4Address]) -> bool:
    """Return True if value CIDR/IP belongs to existing known subnets."""
    try:
        if "/" in value:
            req_net = ipaddress.ip_network(value, strict=False)
            if str(req_net) in known_subnets:
                return True
            # Fallback: if any known IP falls inside requested subnet, accept as existing
            return any(ip in req_net for ip in known_ips)
        # single IP: check membership in any known subnet
        ip_obj = ipaddress.ip_address(value)
        if any(ip_obj in ipaddress.ip_network(sn) for sn in known_subnets):
            return True
        return ip_obj in known_ips
    except ValueError:
        return False


def infer_zone_for_value(value: str, logical_interfaces: list[dict]) -> Optional[str]:
    """
    Infer zone from source/destination IP or CIDR by matching against logical interface IPs.
    For CIDR input, if a logical-interface IP falls inside the network, use its zone.
    """
    if not logical_interfaces:
        return None

    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            matches = []
            for row in logical_interfaces:
                ip_obj = ipaddress.ip_address(row["ip"])
                if ip_obj in net:
                    matches.append(row["zone"])
            uniq = sorted(set(matches))
            if len(uniq) == 1:
                return uniq[0]
            return None

        ip_obj = ipaddress.ip_address(value)
        for row in logical_interfaces:
            if ipaddress.ip_address(row["ip"]) == ip_obj:
                return row["zone"]
    except Exception:
        return None

    return None


def correlate_and_validate(req: PolicyRequest, ctx: FirewallContext) -> tuple[list[str], dict]:
    """
    Correlate user input with firewall state. Returns (errors, plan).
    plan describes what objects need to be created and final rule config.
    """
    errors = []
    plan: dict[str, Any] = {
        "create_source_address": False,
        "create_dest_address": False,
        "create_service": False,
        "source_ref": req.source,
        "dest_ref": req.destination,
        "service_ref": "any",
        "from_zone": req.source_zone or "any",
        "to_zone": req.destination_zone or "any",
    }

    addr_names = get_existing_address_names(ctx)
    zone_names = get_zone_names(ctx)
    known_subnets = get_existing_subnets(ctx)
    known_ips = get_known_ipv4_ips(ctx)

    # Validate zones if specified
    if req.source_zone and zone_names and req.source_zone not in zone_names:
        errors.append(f"Source zone '{req.source_zone}' not found. Available: {sorted(zone_names)}")
    if req.destination_zone and zone_names and req.destination_zone not in zone_names:
        errors.append(f"Destination zone '{req.destination_zone}' not found. Available: {sorted(zone_names)}")

    # Source: use as-is if "any" or existing address; else create address object
    if req.source.lower() == "any":
        plan["source_ref"] = "any"
    elif req.source in addr_names:
        plan["source_ref"] = req.source
    elif is_ip_or_cidr(req.source):
        plan["create_source_address"] = True
        plan["source_ref"] = f"addr-{req.rule_name}-src"
    else:
        # Could be zone name - use as source zone hint
        if req.source in zone_names:
            plan["from_zone"] = req.source
            plan["source_ref"] = "any"
        else:
            errors.append(f"Source '{req.source}' is not a valid IP/CIDR, zone, or existing address object")

    # Destination: same logic
    if req.destination.lower() == "any":
        plan["dest_ref"] = "any"
    elif req.destination in addr_names:
        plan["dest_ref"] = req.destination
    elif is_ip_or_cidr(req.destination):
        plan["create_dest_address"] = True
        plan["dest_ref"] = f"addr-{req.rule_name}-dst"
    else:
        if req.destination in zone_names:
            plan["to_zone"] = req.destination
            plan["dest_ref"] = "any"
        else:
            errors.append(f"Destination '{req.destination}' is not valid")

    # Dynamic zone discovery when user doesn't provide zones.
    if not req.source_zone and is_ip_or_cidr(req.source):
        inferred_src_zone = infer_zone_for_value(req.source, ctx.logical_interfaces)
        if inferred_src_zone:
            plan["from_zone"] = inferred_src_zone
        else:
            errors.append(
                f"Could not infer source zone for '{req.source}'. Provide source_zone explicitly."
            )
    if not req.destination_zone and is_ip_or_cidr(req.destination):
        inferred_dst_zone = infer_zone_for_value(req.destination, ctx.logical_interfaces)
        if inferred_dst_zone:
            plan["to_zone"] = inferred_dst_zone
        else:
            errors.append(
                f"Could not infer destination zone for '{req.destination}'. Provide destination_zone explicitly."
            )

    # Standard-process validation: user-entered subnet/IP must already exist on firewall
    if req.validate_existing_subnets:
        if is_ip_or_cidr(req.source) and not subnet_exists(req.source, known_subnets, known_ips):
            errors.append(f"Source subnet/IP '{req.source}' does not exist on firewall interfaces/objects")
        if is_ip_or_cidr(req.destination) and not subnet_exists(req.destination, known_subnets, known_ips):
            errors.append(f"Destination subnet/IP '{req.destination}' does not exist on firewall interfaces/objects")

    # Service: if custom ports, create service object
    if req.destination_ports.lower() in ("any", "application-default"):
        plan["service_ref"] = "application-default" if req.application != "any" else "any"
    else:
        plan["create_service"] = True
        plan["service_ref"] = f"svc-{req.rule_name}"

    return errors, plan


# ---------------------------------------------------------------------------
# Phase 4: Payload Preparation
# ---------------------------------------------------------------------------


def build_address_payload(name: str, ip_or_cidr: str, description: str = "") -> dict:
    """Build address object payload."""
    entry = {
        "@location": "vsys",
        "@name": name,
        "@vsys": "vsys1",
        "ip-netmask": ip_or_cidr if "/" in ip_or_cidr else f"{ip_or_cidr}/32",
    }
    if description:
        entry["description"] = description
    return {"entry": [entry]}


def build_service_payload(
    name: str,
    ports: str,
    protocol: str = "tcp",
    description: str = "",
) -> dict:
    """Build service object payload. ports can be '443', '80,443', or '8080-8090'."""
    proto_key = protocol.lower() if protocol.lower() in ("tcp", "udp") else "tcp"
    entry = {
        "@location": "vsys",
        "@name": name,
        "@vsys": "vsys1",
        "protocol": {proto_key: {"port": ports}},
    }
    if description:
        entry["description"] = description
    return {"entry": [entry]}


def build_security_rule_payload(req: PolicyRequest, plan: dict) -> dict:
    """Build security policy rule payload."""
    from_members = [plan["from_zone"]] if plan["from_zone"] != "any" else ["any"]
    to_members = [plan["to_zone"]] if plan["to_zone"] != "any" else ["any"]

    entry = {
        "@location": "vsys",
        "@name": req.rule_name,
        "@vsys": "vsys1",
        "action": req.action.lower(),
        "application": {"member": [req.application]},
        "category": {"member": ["any"]},
        "destination": {"member": [plan["dest_ref"]]},
        "from": {"member": from_members},
        "to": {"member": to_members},
        "source": {"member": [plan["source_ref"]]},
        "source-user": {"member": ["any"]},
        "source-hip": {"member": ["any"]},
        "destination-hip": {"member": ["any"]},
        "service": {"member": [plan["service_ref"]]},
        "log-start": "yes" if req.log_start else "no",
        "log-end": "yes" if req.log_end else "no",
    }
    if req.description:
        entry["description"] = req.description
    return {"entry": [entry]}


# ---------------------------------------------------------------------------
# Phase 5: Push to Firewall
# ---------------------------------------------------------------------------


def create_address(client: PaloAltoClient, name: str, ip_or_cidr: str, description: str = "") -> bool:
    """Create address object."""
    payload = build_address_payload(name, ip_or_cidr, description)
    params = {"location": "vsys", "vsys": client.vsys, "name": name}
    try:
        client._post("Objects/Addresses", params=params, json_body=payload)
        LOG.info("Created address object: %s -> %s", name, ip_or_cidr)
        return True
    except requests.HTTPError as e:
        if e.response.status_code == 409:
            LOG.info("Address object %s already exists", name)
            return True
        raise


def create_service(
    client: PaloAltoClient,
    name: str,
    ports: str,
    protocol: str = "tcp",
    description: str = "",
) -> bool:
    """Create service object."""
    payload = build_service_payload(name, ports, protocol, description)
    params = {"location": "vsys", "vsys": client.vsys, "name": name}
    try:
        client._post("Objects/Services", params=params, json_body=payload)
        LOG.info("Created service object: %s -> %s/%s", name, protocol, ports)
        return True
    except requests.HTTPError as e:
        if e.response.status_code == 409:
            LOG.info("Service object %s already exists", name)
            return True
        raise


def create_security_rule(client: PaloAltoClient, req: PolicyRequest, plan: dict) -> bool:
    """Create or update security policy rule."""
    payload = build_security_rule_payload(req, plan)
    params = {"location": "vsys", "vsys": client.vsys, "name": req.rule_name}
    try:
        client._post("Policies/SecurityRules", params=params, json_body=payload)
        LOG.info("Created security rule: %s", req.rule_name)
        return True
    except requests.HTTPError as e:
        if e.response.status_code == 409:
            # Upsert behavior: update existing rule when name already exists.
            client._put("Policies/SecurityRules", params=params, json_body=payload)
            LOG.info("Updated existing security rule: %s", req.rule_name)
            return True
        raise


def commit_configuration(client: PaloAltoClient) -> bool:
    """Commit configuration via XML API (REST API changes require commit)."""
    import urllib.parse

    cmd = urllib.parse.quote("<commit></commit>")
    url = f"{client.xml_api_url}?type=commit&key={client.api_key}&cmd={cmd}"
    try:
        r = requests.get(url, verify=client.verify_ssl, timeout=120)
        r.raise_for_status()
        # Response is XML; check for success
        if "success" in r.text.lower() or "committed" in r.text.lower():
            LOG.info("Commit completed successfully")
        else:
            LOG.info("Commit response: %s", r.text[:200])
        return True
    except Exception as e:
        LOG.error("Commit failed: %s", e)
        return False


def representative_ip(value: str) -> Optional[str]:
    """Pick a representative IP for policy-match test from an IP/CIDR string."""
    try:
        if "/" not in value:
            ipaddress.ip_address(value)
            return value
        net = ipaddress.ip_network(value, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen >= 31:
                return str(net.network_address)
            return str(next(net.hosts()))
        return None
    except Exception:
        return None


def run_policy_match_test(client: PaloAltoClient, req: PolicyRequest, plan: dict, phase: str = "post") -> bool:
    """
    Run PAN-OS policy match test after rule push.
    Verifies if expected rule appears in test output.
    """
    src_ip = representative_ip(req.source)
    dst_ip = representative_ip(req.destination)
    if not src_ip or not dst_ip:
        LOG.warning("Policy match test skipped: source/destination must be IP or CIDR")
        return False

    proto_num = "6" if req.protocol.lower() == "tcp" else "17" if req.protocol.lower() == "udp" else "6"
    # For ranges or lists, pick first concrete port for the test probe.
    raw_port = req.destination_ports.split(",")[0].strip()
    dst_port = raw_port.split("-")[0].strip()
    from_zone = plan.get("from_zone", req.source_zone or "any")
    to_zone = plan.get("to_zone", req.destination_zone or "any")

    # If zones were not provided in payload, resolve from created/updated rule.
    if from_zone == "any" or to_zone == "any":
        try:
            data = client._get(
                "Policies/SecurityRules",
                params={"location": "vsys", "vsys": client.vsys, "name": req.rule_name},
            )
            entry = data.get("result", {}).get("entry", [])
            if isinstance(entry, list):
                entry = entry[0] if entry else {}
            from_members = ((entry.get("from") or {}).get("member") or [])
            to_members = ((entry.get("to") or {}).get("member") or [])
            if isinstance(from_members, str):
                from_members = [from_members]
            if isinstance(to_members, str):
                to_members = [to_members]
            if from_members and from_zone == "any":
                from_zone = from_members[0]
            if to_members and to_zone == "any":
                to_zone = to_members[0]
        except Exception as e:
            LOG.warning("Could not resolve zones from rule for policy match test: %s", e)

    if from_zone == "any" or to_zone == "any":
        LOG.warning("Policy match test skipped: from/to zone unresolved. Add source_zone/destination_zone in payload.")
        return False

    cmd = (
        "<test><security-policy-match>"
        f"<from>{from_zone}</from>"
        f"<to>{to_zone}</to>"
        f"<source>{src_ip}</source>"
        f"<destination>{dst_ip}</destination>"
        f"<protocol>{proto_num}</protocol>"
        f"<destination-port>{dst_port}</destination-port>"
        "</security-policy-match></test>"
    )

    from urllib.parse import quote

    url = f"{client.xml_api_url}?type=op&key={client.api_key}&cmd={quote(cmd)}"
    try:
        r = requests.get(url, verify=client.verify_ssl, timeout=60)
        r.raise_for_status()
        body = r.text
        if req.rule_name in body:
            LOG.info("[%s-check] Policy match passed: rule '%s' matched", phase, req.rule_name)
            return True
        LOG.warning("[%s-check] Policy match did not explicitly match '%s'. Response snippet: %s", phase, req.rule_name, body[:240])
        return False
    except Exception as e:
        LOG.warning("[%s-check] Policy match failed to execute: %s", phase, e)
        return False


def push_policy(client: PaloAltoClient, req: PolicyRequest, plan: dict, do_commit: bool = True) -> bool:
    """Execute full push: create objects, create rule, optionally commit."""
    try:
        if plan["create_source_address"] and is_ip_or_cidr(req.source):
            create_address(client, plan["source_ref"], req.source, req.description)
        if plan["create_dest_address"] and is_ip_or_cidr(req.destination):
            create_address(client, plan["dest_ref"], req.destination, req.description)
        if plan["create_service"]:
            create_service(
                client,
                plan["service_ref"],
                req.destination_ports,
                req.protocol,
                req.description,
            )
        create_security_rule(client, req, plan)
        if do_commit:
            commit_configuration(client)
        return True
    except Exception as e:
        LOG.exception("Push failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Main Entry
# ---------------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Palo Alto Firewall Rule Automation")
    parser.add_argument("--input", "-i", required=True, help="Path to JSON policy payload")
    parser.add_argument("--dry-run", action="store_true", help="Validate and plan only, do not push")
    parser.add_argument("--no-commit", action="store_true", help="Do not commit after push")
    args = parser.parse_args()

    # Load policy from JSON
    input_path = Path(args.input)
    if not input_path.exists():
        LOG.error("Input file not found: %s", input_path)
        return 1

    # Phase 1: Load policy from JSON
    req = load_policy_from_json(str(input_path))

    # Device settings (environment variables)
    host = DEVICE["host"]
    port_raw = DEVICE["port"]
    api_key = DEVICE["api_key"]
    username = DEVICE["username"]
    password = DEVICE["password"]
    vsys = DEVICE["vsys"]
    api_version = DEVICE["api_version"]
    verify_ssl = DEVICE["verify_ssl"]

    if not host:
        LOG.error("Set PA_HOST environment variable")
        return 1
    if not port_raw:
        LOG.error("Set PA_PORT environment variable")
        return 1
    try:
        port = int(port_raw)
    except ValueError:
        LOG.error("PA_PORT must be a valid integer. Current value: %s", port_raw)
        return 1

    if not args.dry_run and not api_key:
        if not username or not password:
            LOG.error("Set PA_API_KEY or PA_USERNAME/PA_PASSWORD env vars")
            return 1
        try:
            api_key = generate_api_key(host, port, username, password, verify_ssl)
            LOG.info("Generated API key using PA_USERNAME/PA_PASSWORD")
        except Exception as e:
            LOG.error("API key generation failed: %s", e)
            return 1

    if not args.dry_run:
        try:
            detected_version = detect_api_version(host, port, api_key, verify_ssl, preferred=api_version)
            api_version = detected_version
            LOG.info("Using REST API version: %s", api_version)
        except Exception as e:
            LOG.error("REST API version detection failed: %s", e)
            return 1
    LOG.info("Policy request: %s", req.rule_name)

    errs = validate_policy_request(req)
    if errs:
        for e in errs:
            LOG.error("Validation: %s", e)
        return 1

    # Phase 2: Connect and gather (skip if dry-run - use empty context)
    if args.dry_run:
        ctx = FirewallContext()
        LOG.info("Dry run: skipping firewall connection, using empty context")
    else:
        client = PaloAltoClient(host, port, api_key, api_version, vsys, verify_ssl)
        if not client.test_connection():
            LOG.error("Cannot connect to firewall at %s", host)
            return 1
        ctx = client.gather_context()

    # Phase 3: Correlate
    errs, plan = correlate_and_validate(req, ctx)
    if errs:
        for e in errs:
            LOG.error("Correlation: %s", e)
        return 1

    LOG.info("Plan: %s", json.dumps(plan, indent=2))

    if args.dry_run:
        LOG.info("Dry run - would create: source_addr=%s, dest_addr=%s, service=%s, rule=%s",
                 plan["create_source_address"], plan["create_dest_address"],
                 plan["create_service"], req.rule_name)
        return 0

    # Pre-change policy match check (separate function call)
    run_policy_match_test(client, req, plan, phase="pre")

    # Phase 4 & 5: Push
    success = push_policy(client, req, plan, do_commit=not args.no_commit)
    if success:
        # Post-change policy match check (separate function call)
        run_policy_match_test(client, req, plan, phase="post")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
