"""Durable principal-scoped gateway with an explicitly injected transport."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .auth import ApprovalChallenge, trusted_bot_message_from_transport
from .policy import GatewayDenied, Scope
from .bot_api import BotRejected, DeliveryUncertain
from .local_secrets import LocalSecretsError, validate_bot_name


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def integer(value, low=1, high=2**53-1):
    if type(value) is not int or not low <= value <= high:
        raise GatewayDenied("Invalid integer")
    return value


class ConsumerBusy(RuntimeError):
    pass


class ProcessLock:
    """OS-held file lock; no lease expiry can create a second live consumer."""
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        try:
            self.file = self.path.open("a+b")
            self.file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if self.file is not None:
                self.file.close()
            self.file = None
            raise ConsumerBusy("Another consumer is active") from None
        return self

    def __exit__(self, *_):
        if self.file is not None:
            self.file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            self.file.close()
            self.file = None


class StateStore:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("State path must be absolute")
        self.path = self.path.resolve()
        if self.path.is_relative_to(Path(__file__).resolve().parents[2]):
            raise ValueError("State must be outside the code checkout")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS gw_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR IGNORE INTO gw_meta VALUES('cursor','0');
        CREATE TABLE IF NOT EXISTS gw_seen(update_id INTEGER PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS gw_messages(
          owner TEXT,chat INTEGER,topic INTEGER,mid INTEGER,body TEXT NOT NULL,
          task TEXT,depth INTEGER,started REAL,created REAL,
          PRIMARY KEY(owner,chat,topic,mid));
        CREATE TABLE IF NOT EXISTS gw_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT,chat INTEGER,topic INTEGER,mid INTEGER,
          body TEXT,status TEXT DEFAULT 'pending',attempts INTEGER DEFAULT 0,
          available REAL,claimed_until REAL,expires REAL,created REAL,
          UNIQUE(owner,chat,topic,mid));
        CREATE TABLE IF NOT EXISTS gw_drafts(
          id TEXT PRIMARY KEY,owner TEXT,body TEXT NOT NULL,digest TEXT NOT NULL,
          status TEXT NOT NULL,expires REAL,created REAL,consumed REAL,
          receipt TEXT,approval_owner INTEGER,approval_message INTEGER,failure TEXT);
        CREATE TABLE IF NOT EXISTS gw_challenges(
          owner TEXT,draft TEXT UNIQUE,chat INTEGER,topic INTEGER,message_id INTEGER,
          PRIMARY KEY(chat,topic,message_id));
        CREATE TABLE IF NOT EXISTS gw_outbound_links(
          owner TEXT,chat INTEGER,topic INTEGER,mid INTEGER,task TEXT,depth INTEGER,started REAL,
          PRIMARY KEY(owner,chat,topic,mid));
        CREATE TABLE IF NOT EXISTS gw_event_exports(
          event_id INTEGER PRIMARY KEY,owner TEXT,exported INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS gw_standing_attempts(
          draft TEXT PRIMARY KEY,owner TEXT NOT NULL,policy TEXT NOT NULL,digest TEXT NOT NULL,
          conversation TEXT NOT NULL,operation TEXT UNIQUE NOT NULL,created REAL NOT NULL);
        ''')
        # Additive migration: historical failures remain unknown in detail.
        with self.transaction() as db:
            if "failure" not in {row[1] for row in db.execute("PRAGMA table_info(gw_drafts)")}:
                db.execute("ALTER TABLE gw_drafts ADD COLUMN failure TEXT")

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def close(self):
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()


class Gateway:
    def __init__(self, store, policy, principals, bot, *, owner_verifier=None,
                 clock=time.time, event_ttl=3600, max_chain_depth=4, max_chain_steps=8,
                 chain_ttl=900, max_events_per_minute=60, max_sends_per_minute=10,
                 bot_reference=None, bot_id=None, standing_send=None, event_lease_seconds=120):
        try:
            self.bot_reference = None if bot_reference is None else validate_bot_name(bot_reference)
        except LocalSecretsError:
            raise GatewayDenied("Invalid bot reference") from None
        self.store, self.policy, self.bot = store, policy, bot
        self._bind_bot_namespace()
        self.principals = tuple(principals)
        self.owner_verifier, self.clock = owner_verifier, clock
        self.event_ttl, self.max_chain_depth = event_ttl, max_chain_depth
        self.event_lease_seconds = integer(event_lease_seconds, 1, 3600)
        self.max_chain_steps, self.chain_ttl = max_chain_steps, chain_ttl
        self.max_events_per_minute, self.max_sends_per_minute = max_events_per_minute, max_sends_per_minute
        if standing_send is not None:
            from .standing import StandingSendPolicy
            if type(standing_send) is not StandingSendPolicy:
                raise GatewayDenied("Invalid standing policy")
        self.standing_send, self.bot_id = standing_send, bot_id
        # Operator-only counters; never message bodies or unauthorized identities.
        self.last_poll_stats = None

    def _bind_bot_namespace(self):
        """A per-bot store cannot be reused under another or omitted identity."""
        with self.store.transaction() as db:
            expected = "" if self.bot_reference is None else self.bot_reference
            row = db.execute("SELECT value FROM gw_meta WHERE key='gateway_bot_reference'").fetchone()
            if row is not None:
                if row["value"] != expected:
                    raise GatewayDenied("Gateway state belongs to a different bot")
                return
            if self.bot_reference is not None:
                # Existing legacy data has no bot provenance; never relabel it.
                for table in ("gw_seen", "gw_messages", "gw_events", "gw_drafts", "gw_challenges", "gw_outbound_links"):
                    if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                        raise GatewayDenied("Legacy gateway state has no bot provenance")
                cursor = db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()
                if cursor is not None and cursor["value"] != "0":
                    raise GatewayDenied("Legacy gateway cursor has no bot provenance")
            db.execute("INSERT INTO gw_meta(key,value) VALUES('gateway_bot_reference',?)", (expected,))

    def _namespace(self, value):
        return value if self.bot_reference is None else f"bot:{self.bot_reference}:{value}"

    def _tag_bot(self, body):
        if self.bot_reference is not None:
            body["bot_reference"] = self.bot_reference
        return body

    def _check_bot(self, body):
        if not isinstance(body,dict) or body.get("bot_reference") != self.bot_reference:
            raise GatewayDenied("Payload belongs to a different bot")

    def _scope(self, chat_id, topic_id=None, all_topics=False):
        # Group Bot API namespace only, isolated from legacy account/Telethon.
        if type(all_topics) is not bool or (all_topics and topic_id is not None):
            raise GatewayDenied("Invalid all-topics selection")
        integer(chat_id, -(2**53-1), -1)
        if topic_id is not None:
            integer(topic_id, 1, 2**31-1)
        return Scope(chat_id, topic_id, all_topics=True) if all_topics else Scope(chat_id, topic_id)

    @staticmethod
    def _scope_dict(scope):
        result = asdict(scope)
        if result.get("all_topics") is False:
            result.pop("all_topics")
        return result

    def _selection(self, principal, scope):
        # SQL fragments are fixed server literals; values stay parameterized.
        where, args = "owner=? AND chat=?", (principal.id, scope.chat_id)
        if not getattr(scope, "all_topics", False):
            where += " AND topic=?"
            args += (self._topic(scope),)
        return where, args

    @staticmethod
    def _topic(scope):
        return scope.topic_id if scope.topic_id is not None else -1

    def _allowed(self, p, action, scope):
        try:
            self.policy.require(p, action, scope)
            return True
        except GatewayDenied:
            return False

    def _identity(self, p):
        if not self.policy.tools_for(p):
            raise GatewayDenied("Unknown principal")
        return p.id

    def ping(self, p):
        self._identity(p)
        return {"status":"ok", "backend":"fake-injected", "telegram_connected":False,
                "cloud_delivery_confirmed":None, "cloud_delivery_status":"not_evaluated",
                "protocol":"2026-07-28"}

    def status(self, p):
        owner = self._identity(p)
        counts = {}
        for row in self.store.db.execute("SELECT status,COUNT(*) n FROM gw_drafts WHERE owner=? GROUP BY status", (owner,)):
            counts[row["status"]] = row["n"]
        return {"principal":owner, "draft_counts":counts, "source":"captured-group-bot-updates",
                "history_before_capture_available":False, "live_transport_configured":False,
                "cloud_delivery_confirmed":None, "cloud_delivery_status":"not_evaluated"}

    def list_allowed_scopes(self, p):
        self._identity(p)
        return {action:[self._scope_dict(s) for s in self.policy.allowed_scopes(p, action)]
                for action in ("history","events","draft","send","forward")}

    async def poll_once(self):
        # Lock includes poll request AND atomic cursor commit. Never call getUpdates twice concurrently.
        self.last_poll_stats = None
        with ProcessLock(self.store.path.with_suffix(".consumer.lock")):
            offset = int(self.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0])
            batch = await self.bot.poll(offset)
            now = self.clock()
            stored = queued = duplicates = 0
            with self.store.transaction() as db:
                for msg in batch.messages:
                    if db.execute("INSERT OR IGNORE INTO gw_seen VALUES(?)", (msg.update_id,)).rowcount == 0:
                        duplicates += 1
                        continue
                    scope = self._scope(msg.chat_id, msg.topic_id)
                    # Approvals are recognized only on trusted poll ingestion, never through tools/call.
                    self._ingest_owner_decision(db, msg)
                    for p in self.principals:
                        history = self._allowed(p, "history", scope)
                        events = self._allowed(p, "events", scope)
                        if not (history or events):
                            continue
                        topic = self._topic(scope)
                        parent = None
                        if msg.reply_to_message_id is not None:
                            args = (p.id,scope.chat_id,topic,msg.reply_to_message_id)
                            parent = db.execute("SELECT task,depth,started FROM gw_outbound_links WHERE owner=? AND chat=? AND topic=? AND mid=?", args).fetchone()
                            if parent is None:
                                parent = db.execute("SELECT task,depth,started FROM gw_messages WHERE owner=? AND chat=? AND topic=? AND mid=?", args).fetchone()
                        task = parent["task"] if parent else self._namespace(f"tg:{scope.chat_id}:{topic}:{msg.message_id}")
                        depth = parent["depth"]+1 if parent else 0
                        started = parent["started"] if parent else now
                        count = db.execute("SELECT COUNT(*) FROM gw_messages WHERE owner=? AND task=?", (p.id,task)).fetchone()[0]
                        within_chain = depth <= self.max_chain_depth and count < self.max_chain_steps and now-started <= self.chain_ttl
                        body = self._tag_bot({"chat_id":scope.chat_id,"topic_id":scope.topic_id,"message_id":msg.message_id,
                                "text":msg.text,"sender_id":msg.sender_id,"task_id":task,
                                "reply_to_message_id":msg.reply_to_message_id,"chain_depth":depth,
                                "content_is_untrusted":True,
                                "provenance":("forwarded" if msg.forwarded else "anonymous" if msg.sender_chat
                                              else "via_bot" if (msg.via_bot or msg.business_origin or msg.guest_origin) else "bot" if msg.sender_is_bot else "human")})
                        # Event-only grants must not gain a queryable history through storage API.
                        inserted = db.execute("INSERT OR IGNORE INTO gw_messages VALUES(?,?,?,?,?,?,?,?,?)",
                                   (p.id,scope.chat_id,topic,msg.message_id,canonical(body),task,depth,started,now))
                        stored += inserted.rowcount
                        recent = db.execute("SELECT COUNT(*) FROM gw_events WHERE owner=? AND created>?", (p.id,now-60)).fetchone()[0]
                        if events and within_chain and recent < self.max_events_per_minute:
                            cursor = db.execute("INSERT OR IGNORE INTO gw_events(owner,chat,topic,mid,body,available,claimed_until,expires,created) VALUES(?,?,?,?,?,?,0,?,?)",
                                                (p.id,scope.chat_id,topic,msg.message_id,canonical(body),now,now+self.event_ttl,now))
                            if cursor.rowcount:
                                queued += 1
                                db.execute("INSERT INTO gw_event_exports(event_id,owner) VALUES(?,?)", (cursor.lastrowid,p.id))
                db.execute("UPDATE gw_meta SET value=? WHERE key='cursor'", (str(batch.next_offset),))
            # Publish only after the messages/events/cursor transaction commits.
            self.last_poll_stats = {
                "offset_before": offset, "offset_after": batch.next_offset,
                "updates_received": batch.received_count, "messages_accepted": len(batch.messages),
                "message_rows_stored": stored, "event_rows_created": queued, "duplicates": duplicates,
                "accepted_bot_senders": sum(m.sender_id is not None and m.sender_is_bot for m in batch.messages),
                "accepted_human_senders": sum(not m.sender_is_bot for m in batch.messages),
                "accepted_threaded": sum(m.topic_id is not None for m in batch.messages),
                "discard_counts": dict(batch.discard_counts),
            }
            return {"received":batch.received_count,"accepted":len(batch.messages),"next_offset":batch.next_offset}

    def read_history(self, p, chat_id, topic_id=None, limit=20, before_id=None, all_topics=False):
        scope = self._scope(chat_id,topic_id,all_topics)
        self.policy.require(p,"history",scope)
        integer(limit,1,100)
        if before_id is not None:
            integer(before_id,1,2**31-1)
        where,args = self._selection(p,scope)
        rows = self.store.db.execute(f"SELECT body FROM gw_messages WHERE {where} AND mid<? ORDER BY mid DESC LIMIT ?",
                                     args+(before_id or 2**31,limit))
        return {"messages":[json.loads(r[0]) for r in rows],"source":"locally captured messages only"}

    def search_history(self,p,chat_id,query,topic_id=None,limit=20,all_topics=False):
        scope=self._scope(chat_id,topic_id,all_topics)
        self.policy.require(p,"history",scope)
        integer(limit,1,100)
        if not isinstance(query,str) or not 1<=len(query)<=200:
            raise GatewayDenied("Invalid query")
        where,args=self._selection(p,scope)
        rows=self.store.db.execute(f"SELECT body FROM gw_messages WHERE {where} ORDER BY mid DESC",args)
        found=[]
        for row in rows:
            body=json.loads(row[0])
            if query.casefold() in body["text"].casefold():
                found.append(body)
                if len(found)==limit:
                    break
        return {"messages":found,"source":"locally captured messages only"}

    def next_events(self,p,chat_id,topic_id=None,limit=20,all_topics=False):
        scope=self._scope(chat_id,topic_id,all_topics)
        self.policy.require(p,"events",scope)
        integer(limit,1,100)
        now=self.clock()
        result=[]
        with self.store.transaction() as db:
            db.execute("UPDATE gw_events SET status='expired' WHERE owner=? AND expires<=? AND status IN ('pending','claimed')",(p.id,now))
            db.execute("UPDATE gw_events SET status='dead' WHERE owner=? AND attempts>=5 AND claimed_until<=? AND status='claimed'",(p.id,now))
            where,args=self._selection(p,scope)
            rows=db.execute(f"SELECT * FROM gw_events WHERE {where} AND expires>? AND available<=? AND (status='pending' OR (status='claimed' AND claimed_until<=?)) AND attempts<5 ORDER BY id LIMIT ?",
                            args+(now,now,now,limit)).fetchall()
            for row in rows:
                attempts=row["attempts"]+1
                wait=self.event_lease_seconds  # Processing lease, not a short retry backoff.
                db.execute("UPDATE gw_events SET status='claimed',attempts=?,claimed_until=?,available=? WHERE id=?",(attempts,now+wait,now+wait,row["id"]))
                result.append({"event_id":row["id"],"attempt":attempts,"data":json.loads(row["body"])})
        return {"events":result,"delivery":"at-least-once within expiry and retry limit"}

    def ack_event(self,p,event_id):
        integer(event_id)
        row=self.store.db.execute("SELECT * FROM gw_events WHERE id=? AND owner=?",(event_id,p.id)).fetchone()
        if row is None:
            raise GatewayDenied("Event unavailable")
        self.policy.require(p,"events",self._scope(row["chat"],None if row["topic"]==-1 else row["topic"]))
        if row["status"] not in ("claimed","acknowledged"):
            raise GatewayDenied("Event was not claimed")
        self.store.db.execute("UPDATE gw_events SET status='acknowledged' WHERE id=? AND owner=?",(event_id,p.id))
        return {"acknowledged":True}

    def create_draft(self,p,chat_id,text,topic_id=None,attachments=None,reply_to_message_id=None,expires_in=300):
        return self._create_draft(p,chat_id,topic_id,text,attachments,reply_to_message_id,expires_in,None)

    def create_forward_draft(self,p,source_chat_id,message_id,chat_id,source_topic_id=None,topic_id=None,expires_in=300):
        source=self._scope(source_chat_id,source_topic_id)
        dest=self._scope(chat_id,topic_id)
        for action in ("history","forward"):
            self.policy.require(p,action,source)
        for action in ("draft","send","forward"):
            self.policy.require(p,action,dest)
        integer(message_id,1,2**31-1)
        row=self.store.db.execute("SELECT body FROM gw_messages WHERE owner=? AND chat=? AND topic=? AND mid=?",(p.id,source_chat_id,self._topic(source),message_id)).fetchone()
        if row is None:
            raise GatewayDenied("Source unavailable")
        snapshot=json.loads(row[0])
        self._check_bot(snapshot)
        source_ref=self._tag_bot({"chat_id":source_chat_id,"topic_id":source_topic_id,"message_id":message_id,
                    "snapshot_sha256":hashlib.sha256(canonical(snapshot).encode()).hexdigest()})
        return self._create_draft(p,chat_id,topic_id,snapshot["text"],[],None,expires_in,source_ref)

    def _create_draft(self,p,chat_id,topic_id,text,attachments,reply_id,expires_in,source_ref):
        scope=self._scope(chat_id,topic_id)
        self.policy.require(p,"draft",scope)
        if not isinstance(text,str) or not 1<=len(text)<=4000:
            raise GatewayDenied("Invalid draft text")
        integer(expires_in,1,900)
        attachments=[] if attachments is None else attachments
        if not isinstance(attachments,list) or len(attachments)>5:
            raise GatewayDenied("Invalid attachments")
        for item in attachments:
            if not isinstance(item,dict) or set(item)!={"sha256","name"} or not isinstance(item["name"],str) or not 1<=len(item["name"])<=128:
                raise GatewayDenied("Invalid attachment descriptor")
            if not isinstance(item["sha256"],str) or len(item["sha256"])!=64 or any(c not in "0123456789abcdef" for c in item["sha256"]):
                raise GatewayDenied("Invalid attachment digest")
        now=self.clock()
        task=self._namespace(f"draft:{uuid.uuid4().hex}")
        depth=0
        started=now
        if reply_id is not None:
            integer(reply_id,1,2**31-1)
            # Reply-link access reveals captured context, so it also needs history permission.
            self.policy.require(p,"history",scope)
            parent=self.store.db.execute("SELECT task,depth,started FROM gw_messages WHERE owner=? AND chat=? AND topic=? AND mid=?",(p.id,chat_id,self._topic(scope),reply_id)).fetchone()
            if parent is None:
                raise GatewayDenied("Reply target unavailable")
            task,depth,started=parent["task"],parent["depth"]+1,parent["started"]
        if depth>self.max_chain_depth or now-started>self.chain_ttl:
            raise GatewayDenied("Chain limit reached")
        count=self.store.db.execute("SELECT COUNT(*) FROM gw_outbound_links WHERE owner=? AND task=?",(p.id,task)).fetchone()[0]
        if count>=self.max_chain_steps:
            raise GatewayDenied("Chain limit reached")
        draft_id=uuid.uuid4().hex
        body=self._tag_bot({"draft_id":draft_id,"principal_id":p.id,"operation":"forward_snapshot" if source_ref else "send",
              "chat_id":chat_id,"topic_id":topic_id,"text":text,"attachments":attachments,"source":source_ref,
              "task_id":task,"reply_to_message_id":reply_id,"chain_depth":depth,"started":started,"expires_at":now+expires_in})
        payload=canonical(body)
        digest=hashlib.sha256(payload.encode()).hexdigest()
        self.store.db.execute("INSERT INTO gw_drafts(id,owner,body,digest,status,expires,created) VALUES(?,?,?,?,?,?,?)",
                              (draft_id,p.id,payload,digest,"pending",body["expires_at"],now))
        result={"draft":json.loads(payload),"digest":digest,"status":"pending-owner-approval"}
        if self.standing_send is not None:
            try:
                self.standing_send.authorize(p,bot_reference=self.bot_reference,bot_id=self.bot_id,body=body)
                result.update(status="pending-scoped-send",approval_mode="standing")
            except GatewayDenied:
                pass
        return result

    def bind_owner_challenge(self,p,draft_id,chat_id,message_id,topic_id=None):
        """Trusted operator-only hook. Not an MCP tool or automatic Telegram send."""
        row=self._draft(p,draft_id)
        scope=self._scope(chat_id,topic_id)
        integer(message_id,1,2**31-1)
        if row["status"]!="pending" or row["expires"]<=self.clock():
            raise GatewayDenied("Draft not pending")
        if self.owner_verifier is None:
            raise GatewayDenied("Owner channel unavailable")
        self.store.db.execute("INSERT INTO gw_challenges VALUES(?,?,?,?,?)",(p.id,draft_id,chat_id,self._topic(scope),message_id))
        return {"draft_id":draft_id,"digest":row["digest"],"approval_text":f"approve {draft_id} {row['digest']}","preview":json.loads(row["body"])}

    def _ingest_owner_decision(self,db,msg):
        if self.owner_verifier is None or msg.reply_to_message_id is None:
            return
        row=db.execute("SELECT d.*,c.chat approval_chat,c.topic approval_topic,c.message_id challenge_mid FROM gw_challenges c JOIN gw_drafts d ON d.id=c.draft WHERE c.chat=? AND c.topic=? AND c.message_id=? AND d.status='pending'",(msg.chat_id,msg.topic_id if msg.topic_id is not None else -1,msg.reply_to_message_id)).fetchone()
        if row is None:
            return
        try:
            self._check_bot(json.loads(row["body"]))
        except (GatewayDenied,ValueError,TypeError):
            return
        challenge=ApprovalChallenge(row["owner"],row["id"],row["digest"],row["approval_chat"],None if row["approval_topic"]==-1 else row["approval_topic"],row["challenge_mid"],row["expires"])
        try:
            decision=self.owner_verifier.verify(trusted_bot_message_from_transport(msg.raw_envelope),challenge)
        except (GatewayDenied,ValueError):
            return
        if not decision.verified:
            return
        db.execute("UPDATE gw_drafts SET status=?,approval_owner=?,approval_message=? WHERE id=? AND status='pending'",("approved" if decision.approved else "rejected",decision.owner_id,decision.source_message_id,row["id"]))

    def _draft(self,p,draft_id):
        self._identity(p)
        if not isinstance(draft_id,str) or len(draft_id)!=32:
            raise GatewayDenied("Draft unavailable")
        row=self.store.db.execute("SELECT * FROM gw_drafts WHERE id=? AND owner=?",(draft_id,p.id)).fetchone()
        if row is None:
            raise GatewayDenied("Draft unavailable")
        try:
            self._check_bot(json.loads(row["body"]))
        except (ValueError,TypeError):
            raise GatewayDenied("Draft unavailable for this bot") from None
        return row

    def get_draft_status(self, p, draft_id):
        """Read one owned draft's metadata, without a send, claim or reconciliation."""
        if type(draft_id) is not str or len(draft_id) != 32 or any(c not in "0123456789abcdef" for c in draft_id):
            raise GatewayDenied("Draft unavailable")
        row = self._draft(p, draft_id)
        body = json.loads(row["body"])
        scope = self._scope(body["chat_id"], body["topic_id"])
        for permission in ("draft", "send"):
            self.policy.require(p, permission, scope)
        if body.get("principal_id") != p.id or hashlib.sha256(row["body"].encode()).hexdigest() != row["digest"]:
            raise GatewayDenied("Draft unavailable")
        if row["status"] not in {"pending", "approved", "rejected", "sending", "sent", "failed", "unknown"}:
            raise GatewayDenied("Draft unavailable")
        result = {"draft_id": draft_id, "status": row["status"],
                  "expired": row["expires"] <= self.clock(),
                  "attempt_started": row["consumed"] is not None,
                  "failure": self._draft_failure_metadata(row["failure"]), "receipt": None}
        if row["receipt"] is not None:
            try:
                receipt = json.loads(row["receipt"])
                self._check_bot(receipt)
                integer(receipt["message_id"], 1, 2**31 - 1)
                receipt_scope = self._scope(receipt["chat_id"], receipt["topic_id"])
                if (receipt_scope != scope or receipt.get("operation_id") != self._namespace(draft_id)
                        or type(receipt.get("synthetic")) is not bool):
                    raise ValueError()
                result["receipt"] = self._tag_bot({key: receipt[key] for key in
                    ("message_id", "chat_id", "topic_id", "operation_id", "synthetic")})
            except (ValueError, TypeError, KeyError):
                raise GatewayDenied("Draft receipt unavailable") from None
        return result

    @staticmethod
    def _draft_failure_metadata(raw):
        # Old failures have no details. Never expose arbitrary persisted strings.
        try:
            failure = json.loads(raw) if raw is not None else None
        except (ValueError, TypeError):
            return None
        if type(failure) is not dict:
            return None
        kind = failure.get("kind")
        if type(kind) is not str:
            return None
        if kind in {"telegram_rejected", "rejected_without_api_code"}:
            code, retry = failure.get("api_error_code"), failure.get("retry_after_seconds")
            return {"kind": kind,
                    "api_error_code": code if type(code) is int and 400 <= code <= 599 else None,
                    "retry_after_seconds": retry if type(retry) is int and 1 <= retry <= 86400 else None}
        if (kind == "delivery_uncertain" and failure.get("stage") in ("transport", "receipt_persistence")
                and failure.get("error_category") in ("cancelled", "timeout", "connection", "sqlite",
                                                       "persistence", "adapter_uncertain", "unexpected")):
            return {key: failure[key] for key in ("kind", "stage", "error_category")}
        return None

    async def send_draft(self,p,draft_id):
        # Entire claim/send/record is serialized across processes. Crash after claim => unknown.
        with ProcessLock(self.store.path.with_suffix(".outbound.lock")):
            with self.store.transaction() as db:
                row=self._draft(p,draft_id)
                body=json.loads(row["body"])
                scope=self._scope(body["chat_id"],body["topic_id"])
                for permission in ("draft","send"):
                    self.policy.require(p,permission,scope)
                if body["source"]:
                    src=body["source"]
                    self._check_bot(src)
                    for permission in ("history","forward"):
                        self.policy.require(p,permission,self._scope(src["chat_id"],src["topic_id"]))
                    self.policy.require(p,"forward",scope)
                if row["status"]=="sent":
                    stored_receipt=json.loads(row["receipt"])
                    self._check_bot(stored_receipt)
                    return {"status":"sent","receipt":stored_receipt,"reused":True}
                standing = None
                if self.standing_send is not None and row["status"]=="pending":
                    standing = self.standing_send.authorize(p,bot_reference=self.bot_reference,
                                                            bot_id=self.bot_id,body=body)
                if (row["status"]!="approved" and not (row["status"]=="pending" and standing is not None)) or row["expires"]<=self.clock():
                    raise GatewayDenied("Draft is not approved, has expired, or was consumed")
                if hashlib.sha256(row["body"].encode()).hexdigest()!=row["digest"]:
                    raise GatewayDenied("Draft integrity mismatch")
                if self.clock()-body["started"]>self.chain_ttl or body["chain_depth"]>self.max_chain_depth:
                    raise GatewayDenied("Chain expired")
                # Ambiguous sends may have happened remotely; every consumed attempt spends budget.
                attempts=db.execute("SELECT body FROM gw_drafts WHERE owner=? AND consumed IS NOT NULL",(p.id,)).fetchall()
                steps=sum(json.loads(item[0])["task_id"]==body["task_id"] for item in attempts)
                if steps>=self.max_chain_steps:
                    raise GatewayDenied("Chain limit reached")
                recent=db.execute("SELECT COUNT(*) FROM gw_drafts WHERE owner=? AND consumed>?",(p.id,self.clock()-60)).fetchone()[0]
                if recent>=self.max_sends_per_minute:
                    raise GatewayDenied("Send rate limit")
                if standing is not None:
                    self._reserve_standing(db,p,body,standing,row["digest"])
                changed=db.execute("UPDATE gw_drafts SET status='sending',consumed=? WHERE id=? AND status IN ('pending','approved')",(self.clock(),draft_id)).rowcount
                if changed!=1:
                    raise GatewayDenied("Draft was consumed")
            try:
                receipt=await self.bot.send_message(chat_id=body["chat_id"],topic_id=body["topic_id"],text=body["text"],
                    operation_id=self._namespace(draft_id),reply_to_message_id=body["reply_to_message_id"],attachments=tuple(body["attachments"]))
            except BotRejected as error:
                code = getattr(error, "api_error_code", None)
                if type(code) is not int or not 400 <= code <= 599:
                    code = None
                retry_after = getattr(error, "retry_after", None)
                if type(retry_after) is not int or not 1 <= retry_after <= 86400:
                    retry_after = None
                # Persist only fixed categories and numbers, never API descriptions.
                failure = {"kind": "telegram_rejected" if code is not None else "rejected_without_api_code",
                           "api_error_code": code, "retry_after_seconds": retry_after}
                self.store.db.execute("UPDATE gw_drafts SET status='failed',failure=? WHERE id=?",
                                      (canonical(failure),draft_id))
                return {"status":"failed", "failure":failure,
                        "retry":"no automatic resend; inspect failure before creating another draft"}
            except BaseException as error:
                # Cancellation, timeout and unknown transport errors can follow a successful remote send.
                failure = self._record_uncertain(draft_id, error, "transport", standing)
                if isinstance(error,(KeyboardInterrupt,SystemExit,asyncio.CancelledError)):
                    raise
                return {"status":"unknown","failure":failure,
                        "retry":"manual reconciliation required; no automatic resend"}
            try:
                data=self._tag_bot(asdict(receipt))
                with self.store.transaction() as db:
                    db.execute("UPDATE gw_drafts SET status='sent',receipt=? WHERE id=?",(canonical(data),draft_id))
                    db.execute("INSERT OR IGNORE INTO gw_outbound_links VALUES(?,?,?,?,?,?,?)",(p.id,body["chat_id"],self._topic(scope),receipt.message_id,body["task_id"],body["chain_depth"],body["started"]))
            except BaseException as error:
                # The network may already have succeeded. A durable 'sending'
                # claim also blocks later standing sends if this write fails.
                failure = self._record_uncertain(draft_id, error, "receipt_persistence", standing)
                if isinstance(error,(KeyboardInterrupt,SystemExit,asyncio.CancelledError)):
                    raise
                return {"status":"unknown","failure":failure,
                        "retry":"manual reconciliation required; no automatic resend"}
            return {"status":"sent","receipt":data,"reused":False}

    def _record_uncertain(self, draft_id, error, stage, standing):
        # Fixed categories only: never serialize exception text, class names,
        # causes, URLs or stack traces. "transport" means awaiting the adapter,
        # not proof of an HTTP attempt; its erased cause remains unknown.
        if isinstance(error, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
            category = "cancelled"
        elif isinstance(error, TimeoutError):
            category = "timeout"
        elif isinstance(error, ConnectionError):
            category = "connection"
        elif isinstance(error, sqlite3.Error):
            category = "sqlite"
        elif isinstance(error, DeliveryUncertain):
            category = "adapter_uncertain"
        else:
            category = "persistence" if stage == "receipt_persistence" else "unexpected"
        failure = {"kind": "delivery_uncertain", "stage": stage, "error_category": category}
        try:
            self.store.db.execute("UPDATE gw_drafts SET status='unknown',failure=? WHERE id=?",
                                  (canonical(failure), draft_id))
        except Exception:
            # The already committed sending/consumed claim still denies retry.
            # Metadata persistence failure cannot imply rejection or success.
            pass
        if standing is not None:
            try:
                self._open_standing_circuit()
            except Exception:
                # The durable unresolved standing attempt also closes the gate.
                pass
        return failure

    def _open_standing_circuit(self):
        self.store.db.execute("INSERT INTO gw_meta(key,value) VALUES('standing_send_circuit','open') ON CONFLICT(key) DO UPDATE SET value='open'")

    def _reserve_standing(self,db,p,body,authorization,digest):
        if authorization.payload_digest!=digest:
            raise GatewayDenied("Standing payload integrity mismatch")
        if db.execute("SELECT 1 FROM gw_meta WHERE key='standing_send_circuit' AND value='open'").fetchone():
            raise GatewayDenied("Standing send circuit is open; operator reconciliation required")
        if db.execute("SELECT 1 FROM gw_standing_attempts a JOIN gw_drafts d ON d.id=a.draft WHERE d.status IN ('sending','unknown') LIMIT 1").fetchone():
            raise GatewayDenied("Uncertain standing send requires operator reconciliation")
        # A new draft, missing reply link or bot message cannot reset the
        # conversation budget. Only a captured direct human message starts a new
        # conversation. This is a loop boundary, not an approval from that human.
        conversation="initial"
        topic=body["topic_id"] if body["topic_id"] is not None else -1
        rows=db.execute("SELECT mid,body FROM gw_messages WHERE owner=? AND chat=? AND topic=? ORDER BY mid DESC",(p.id,body["chat_id"],topic))
        for item in rows:
            captured=json.loads(item["body"])
            if captured.get("provenance")=="human":
                conversation=f"human:{item['mid']}"
                break
        count=db.execute("SELECT COUNT(*) FROM gw_standing_attempts WHERE owner=? AND conversation=?",(p.id,conversation)).fetchone()[0]
        if count>=self.max_chain_steps:
            raise GatewayDenied("Standing conversation ceiling reached; wait for direct human input")
        recent=db.execute("SELECT COUNT(*) FROM gw_standing_attempts WHERE owner=? AND created>?",(p.id,self.clock()-900)).fetchone()[0]
        if recent>=8:
            raise GatewayDenied("Standing send rate limit")
        # Content/reply dedup also catches a client recreating the same draft.
        exact={k:body[k] for k in ('principal_id','bot_reference','chat_id','topic_id','text','attachments','reply_to_message_id')}
        exact['conversation']=conversation
        operation=hashlib.sha256(canonical(exact).encode()).hexdigest()
        if db.execute("SELECT 1 FROM gw_standing_attempts WHERE operation=?",(operation,)).fetchone():
            raise GatewayDenied("Equivalent standing operation was already attempted; inspect its receipt")
        db.execute("INSERT INTO gw_standing_attempts VALUES(?,?,?,?,?,?,?)",
                   (body['draft_id'],p.id,authorization.policy_fingerprint,digest,conversation,operation,self.clock()))

    def recover_uncertain(self):
        with ProcessLock(self.store.path.with_suffix(".outbound.lock")):
            changed=self.store.db.execute("UPDATE gw_drafts SET status='unknown' WHERE status='sending'").rowcount
            if self.store.db.execute("SELECT 1 FROM gw_standing_attempts a JOIN gw_drafts d ON d.id=a.draft WHERE d.status='unknown' LIMIT 1").fetchone():
                self._open_standing_circuit()
        return {"recovered_as_unknown":changed}

    def export_events(self,p,hub,limit=100):
        """Durable bridge: crash between hub enqueue and export mark is deduped by stable eventId."""
        self._identity(p)
        integer(limit,1,100)
        rows=self.store.db.execute("SELECT e.* FROM gw_event_exports x JOIN gw_events e ON e.id=x.event_id WHERE x.owner=? AND x.exported=0 ORDER BY e.id LIMIT ?",(p.id,limit)).fetchall()
        count=0
        for row in rows:
            scope=self._scope(row["chat"],None if row["topic"]==-1 else row["topic"])
            if row["expires"]<=self.clock() or not self._allowed(p,"events",scope):
                self.store.db.execute("UPDATE gw_event_exports SET exported=1 WHERE event_id=? AND owner=?",(row["id"],p.id))
                continue
            body=json.loads(row["body"])
            self._check_bot(body)
            # MCP event schema stays unchanged; its eventId and task_id carry
            # the bot namespace, while storage/history retain the explicit tag.
            body.pop("bot_reference",None)
            # Preserve capture time when export is delayed; Telegram's original
            # message creation time is not retained by this storage contract.
            hub.enqueue(p,"telegram.message.created",self._scope_dict(scope),body,
                        self._namespace(f"tg-{row['chat']}-{row['topic']}-{row['mid']}"),occurred_at=row["created"])
            self.store.db.execute("UPDATE gw_event_exports SET exported=1 WHERE event_id=? AND owner=?",(row["id"],p.id))
            count+=1
        return {"exported":count}
