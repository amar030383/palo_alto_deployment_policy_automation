# Palo Alto Firewall Automation

The project is now separated into two folders:

1. `deployment_one_time/` - one-time firewall deployment and bootstrap items
2. `policy_automation/` - day-2 policy rule automation

## Folder Layout

- `deployment_one_time/palo_alto_setup.py`
- `deployment_one_time/network_config.json`
- `deployment_one_time/README.md`
- `policy_automation/palo_alto_rule_automation.py`
- `policy_automation/input.example.json`
- `policy_automation/policy_k8sm01_lb_to_k8sm02_agent_9696.json`
- `policy_automation/RULE_AUTOMATION_FLOW.md`
- `policy_automation/README.md`

## Install

```bash
pip install -r requirements.txt
```

## Deployment (One-Time Setup)

See `deployment_one_time/README.md` for full details.

```bash
python3.11 deployment_one_time/palo_alto_setup.py --config deployment_one_time/network_config.json --all
```

## Policy Automation

See `policy_automation/README.md` and `policy_automation/RULE_AUTOMATION_FLOW.md`.

```bash
python3.11 policy_automation/palo_alto_rule_automation.py --input policy_automation/input.example.json --dry-run
```

## GitHub Safety Checklist

- Do not commit real credentials (`PA_USERNAME`, `PA_PASSWORD`, `PA_API_KEY`)
- Keep secrets only in shell environment or a local `.env` file
- Ensure local virtual environment is not committed (`.venv/` is ignored)
- Avoid committing private cert/key files (`*.pem`, `*.key`, `*.crt`)
- If credentials were ever committed, rotate them immediately before publishing
