# Palo Alto Rule Automation Flow (Step-by-Step)

This document explains exactly what `palo_alto_rule_automation.py` does while implementing a rule.

## 1) Start and Input Parsing

1. Script starts with:
   - `--input <json-file>` (required)
   - optional `--dry-run`
   - optional `--no-commit`
2. It reads the JSON input and builds a `PolicyRequest` object.
3. It validates required fields:
   - `rule_name`, `source`, `destination`, `destination_ports`
   - `protocol` must be `tcp|udp|any`
   - `action` must be `allow|deny`

If validation fails, script exits before any API change.

## 2) Authentication and API Version Detection

1. Credentials are loaded from environment variables (`PA_HOST`, `PA_PORT`, `PA_USERNAME`, `PA_PASSWORD`, etc.).
2. If `PA_API_KEY` is missing, script generates API key using username/password.
3. It probes REST versions and selects the first working one (for this lab, typically `v10.2`).
4. It initializes the API client with that REST version.

## 3) Collect Firewall Context (Read Phase)

The script fetches current firewall state before planning:

- Zones (`Network/Zones`)
- Ethernet interfaces (`Network/EthernetInterfaces`)
- Virtual routers (`Network/VirtualRouters`)
- Address objects (`Objects/Addresses`)
- Service objects (`Objects/Services`)
- Existing security rules (`Policies/SecurityRules`)

### Dynamic Zone Discovery (REST-only)

When `source_zone` and `destination_zone` are not provided:

1. Build interface-to-IP map from `Network/EthernetInterfaces`.
2. Build zone-to-interface-membership map from `Network/Zones`.
3. Join both maps to get `interface -> zone -> IP`.
4. Infer:
   - `from_zone` from source IP/CIDR
   - `to_zone` from destination IP/CIDR

If zone cannot be inferred uniquely, script stops and asks for explicit zone input.

## 4) Correlation and Validation

The script then decides what to create versus reuse.

For source/destination:
- If value is `any`, use `any`.
- If value matches existing address object name, reuse it.
- If value is IP/CIDR and subnet validation is enabled:
  - verify subnet/IP exists in known firewall networks/objects
  - then plan new address object creation (if needed)

For service:
- If protocol is `any`, use `service:any`.
- Else it computes service object name (for example `svc-<rule-name>`),
  and decides to create or reuse.

Output of this phase is a deployment `plan`:
- what objects to create
- references to use in the final policy
- resolved `from_zone` and `to_zone`

## 5) Pre-Change Policy Match Check

Before creating/updating policy, script runs a separate policy-match test function.

Flow:
1. Build representative source/destination IP from input CIDRs.
2. Resolve zones from plan (or fallback to existing rule members if needed).
3. Run operational policy-match command.
4. Log whether expected rule name matched.

Note: this is currently a warning-style check; it does not block policy deployment.

## 6) Payload Preparation

Script prepares payloads based on `plan`:

1. Address object payload(s), if source/destination need creation.
2. Service object payload, if custom protocol/port is used.
3. Security rule payload with:
   - from/to zones
   - source/destination refs
   - service ref
   - action, logging flags, application, description

## 7) Push Changes

Execution order:

1. Create source address object (if planned)
2. Create destination address object (if planned)
3. Create service object (if planned)
4. Create security rule
   - if rule exists (`409`), script updates it (upsert behavior)
5. Commit (unless `--no-commit`)

`--dry-run` stops before any create/update/commit and only prints the plan.

## 8) Post-Change Policy Match Check

After push/commit, script calls the same policy-match function again:

- confirms behavior after implementation
- logs post-check result

## 9) End Result

Successful run means:

1. Required objects exist (created or reused)
2. Security rule is created or updated
3. Commit is done (unless disabled)
4. Pre and post policy-match checks are logged

---

## Quick Operational Sequence

1. Load input
2. Validate fields
3. Authenticate + detect REST version
4. Read firewall context
5. Infer zones dynamically (if omitted)
6. Build and validate plan
7. Pre-check policy match
8. Push objects + rule
9. Commit
10. Post-check policy match

