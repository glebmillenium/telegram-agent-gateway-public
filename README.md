# Telegram Agent Gateway

A Python gateway for Telegram agents. It applies separate access rules per
identity, stores events, and separates drafts from approved outbound sends.
This source snapshot includes a read-only MCP entry point, optional HTTPS
webhook routing, and synthetic test configurations. It has no settings or
data from a running deployment.

## Offline smoke test

Use Python 3.11+ in a virtual environment and install the project with its
test dependencies:

```text
python -m pip install -e ".[test]"
python -m telegram_gateway.demo --config gateway.fake.json --state-dir ../gateway-demo-state
python -m pytest -q
```

The demo uses a fake backend. Do not add real access tokens, bot usernames,
chat identifiers, local paths, operational records, or private configuration
to the repository. Example credentials are for tests only.
