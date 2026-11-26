"""Prepare multi-agent webhook imports. No save, network call or activation.

Only an explicitly supplied file is read. Names and mentions are metadata, not
authenticated identities. Secrets stay in memory and are omitted from repr/CLI.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from .auth import _principal_id
from .grok_routine import authorization_headers
from .local_secrets import validate_bot_name, validate_webhook_ref
from .runtime_config import _callback

MAX_BYTES = 65536
MAX_ENTRIES = 64
FIELDS = frozenset({'AGENT','TELEGRAM','POST','KEY','HEADER'})


class WebhookImportError(ValueError):
    """Fixed diagnostics only; never echo source fields or parser exceptions."""


@dataclass(frozen=True, slots=True)
class WebhookCandidate:
    agent: str = field(repr=False)
    telegram_username: str | None = field(repr=False)
    url: str = field(repr=False)
    authorization_header: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ImportPlan:
    profiles: tuple[dict, ...] = field(repr=False)
    webhooks: dict[str, dict[str, str]] = field(repr=False)


def parse_bundle(raw: bytes) -> tuple[WebhookCandidate, ...]:
    """Parse bounded UTF-8 key:value blocks without I/O or guessed identities."""
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            raise ValueError()
        text = raw.decode('utf-8-sig')
        if '`' in text or any(ord(c) < 32 and c not in '\r\n\t' for c in text):
            raise ValueError()
        blocks, current = [], {}
        for line in text.splitlines() + ['']:
            if not line.strip():
                if current:
                    if set(current) != FIELDS or len(blocks) >= MAX_ENTRIES:
                        raise ValueError()
                    blocks.append(current); current = {}
                continue
            name, separator, value = line.partition(':')
            name, value = name.strip().upper(), value.strip()
            if not separator or name not in FIELDS or name in current or not value:
                raise ValueError()
            current[name] = value
        if not blocks:
            raise ValueError()
        entries, names, bots, urls, keys = [], set(), set(), set(), set()
        for block in blocks:
            agent = block['AGENT']
            if len(agent) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in agent):
                raise ValueError()
            name = agent.casefold()
            bot = None if block['TELEGRAM'].casefold() == 'нет' else validate_bot_name(block['TELEGRAM'])
            url = _callback(block['POST'])
            key = block['KEY']
            if not 1 <= len(key) <= 4096 or any(not 33 <= ord(c) <= 126 for c in key):
                raise ValueError()
            header_name, separator, value = block['HEADER'].partition(':')
            if not separator or header_name.strip().casefold() != 'authorization':
                raise ValueError()
            value = value.strip()
            authorization_headers(value)
            # The user supplies the full header. Never invent a Bearer prefix.
            scheme, space, remainder = value.partition(' ')
            if value != key and not (space and re.fullmatch(r'[A-Za-z][A-Za-z0-9._~-]*', scheme) and remainder == key):
                raise ValueError()
            if name in names or bot is not None and bot in bots or url in urls or key in keys:
                raise ValueError()
            names.add(name); urls.add(url); keys.add(key)
            if bot is not None: bots.add(bot)
            entries.append(WebhookCandidate(agent, bot, url, value))
        return tuple(entries)
    except Exception:
        raise WebhookImportError('Webhook bundle rejected; check fields, duplicates and header consistency') from None


def load_bundle(path: Path | str) -> tuple[WebhookCandidate, ...]:
    """Explicit read only. Does not discover files, persist keys or delete input."""
    try:
        source = Path(path)
        if not source.is_absolute() or '..' in source.parts or str(source).startswith(('\\\\','//')):
            raise ValueError()
        if source.resolve(strict=True) != source.absolute():
            raise ValueError()
        with source.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        return parse_bundle(raw)
    except Exception:
        raise WebhookImportError('Webhook input unavailable or invalid') from None


def prepare_plan(entries, bindings: dict[str, dict[str, str]]) -> ImportPlan:
    """Operator-supplied IDs/platform produce disabled profiles with zero grants.

    bindings keys are casefolded AGENT labels, values: profile_id, webhook_ref,
    platform. No auth principal, Telegram ID or credentials are generated.
    """
    try:
        if type(entries) is not tuple or not 1 <= len(entries) <= MAX_ENTRIES or any(type(e) is not WebhookCandidate for e in entries):
            raise ValueError()
        if type(bindings) is not dict or set(bindings) != {e.agent.casefold() for e in entries}:
            raise ValueError()
        profiles, webhooks, ids = [], {}, set()
        for entry in entries:
            binding = bindings[entry.agent.casefold()]
            if type(binding) is not dict or set(binding) != {'profile_id','webhook_ref','platform'}:
                raise ValueError()
            identity = _principal_id(binding['profile_id'])
            reference = validate_webhook_ref(binding['webhook_ref'])
            platform = binding['platform']
            if type(platform) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',platform):
                raise ValueError()
            if identity in ids or reference in webhooks:
                raise ValueError()
            ids.add(identity)
            profiles.append({'id':identity,'name':entry.agent,'purpose':'','prompt':'',
                'enabled':False,'telegram_username':entry.telegram_username,'auth_principal':None,'chats':[],
                'integration':{'platform':platform,'enabled':False,'status':'pending',
                               'inbound':{'mode':'webhook'},'outbound':{'mode':'local_commands'}}})
            webhooks[reference]={'url':entry.url,'authorization_header':entry.authorization_header}
        return ImportPlan(tuple(profiles),webhooks)
    except Exception:
        raise WebhookImportError('Webhook import bindings rejected') from None


def merge_private_entries(existing: dict, plan: ImportPlan) -> dict:
    """In-memory reconciliation only. Preserve bot tokens and never overwrite a conflict."""
    try:
        if type(existing) is not dict or type(plan) is not ImportPlan:
            raise ValueError()
        if type(existing.get('version')) is not int or existing['version'] != 1 or type(existing.get('bots')) is not dict:
            raise ValueError()
        result = copy.deepcopy(existing)
        webhooks = result.setdefault('webhooks',{})
        if type(webhooks) is not dict:
            raise ValueError()
        for ref, value in plan.webhooks.items():
            if ref in webhooks and webhooks[ref] != value:
                raise ValueError()
            if any(other != ref and type(item) is dict and
                   (item.get('url') == value['url'] or item.get('authorization_header') == value['authorization_header'])
                   for other,item in webhooks.items()):
                raise ValueError()
            webhooks[ref] = copy.deepcopy(value)
        if len(webhooks)>MAX_ENTRIES or len(json.dumps(result).encode('utf-8'))>MAX_BYTES:
            raise ValueError()
        return result
    except Exception:
        raise WebhookImportError('Existing webhook settings conflict; no changes made') from None


def summary(entries) -> dict:
    return {'valid':True,'entries':len(entries),
            'telegram_missing':sum(e.telegram_username is None for e in entries),
            'endpoints_verified':False,'saved':False,'activated':False,'network_called':False}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2,'Invalid webhook validation command\n')


def main(argv=None):
    parser = _Parser(description='Validate an explicitly supplied webhook file; never save or connect.')
    parser.add_argument('--check',required=True,type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(summary(load_bundle(args.check))))
        return 0
    except Exception:
        print('{"valid":false,"saved":false,"activated":false,"network_called":false}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
