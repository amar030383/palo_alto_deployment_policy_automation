# Policy Automation

This folder contains the day-2 security policy automation flow.

## Files

- `palo_alto_rule_automation.py` - policy creation/update automation
- `input.example.json` - sample input payload
- `policy_k8sm01_lb_to_k8sm02_agent_9696.json` - policy payload example
- `RULE_AUTOMATION_FLOW.md` - step-by-step flow explanation

## Run

From repository root:

```bash
python3.11 policy_automation/palo_alto_rule_automation.py --input policy_automation/input.example.json --dry-run
```

Apply a policy (with commit):

```bash
python3.11 policy_automation/palo_alto_rule_automation.py --input policy_automation/policy_k8sm01_lb_to_k8sm02_agent_9696.json
```
