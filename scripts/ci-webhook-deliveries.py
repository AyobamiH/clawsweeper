"""Create-only durable delivery claims before any local CI wake-up effect.

An interrupted claim is deliberately held, not automatically replayed. The
existing fleet poll timer reconciles missed events independently from GitHub.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

DELIVERY_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
RETENTION_SECONDS = 30 * 86400
MAX_RECORDS = 20000
MAX_STAGED_ORDINARY = 128
MAX_ORDINARY_BYTES = 65536


class DeliveryLedger:
    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise RuntimeError('unsafe_delivery_state_path')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_IMODE(self.directory.stat().st_mode) != 0o700:
            raise RuntimeError('unsafe_delivery_state_permissions')
        self.db = self.directory / 'deliveries.sqlite3'
        if self.db.is_symlink():
            raise RuntimeError('unsafe_delivery_database')
        self._connect_and_init()

    def _connect(self):
        if self.db.is_symlink():
            raise RuntimeError('unsafe_delivery_database')
        connection = sqlite3.connect(self.db, timeout=3, isolation_level=None)
        connection.execute('PRAGMA busy_timeout=3000')
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA journal_mode=DELETE')
        if stat.S_IMODE(self.db.stat().st_mode) != 0o600:
            connection.close()
            raise RuntimeError('unsafe_delivery_database_permissions')
        return connection

    def _connect_and_init(self):
        previous = os.umask(0o077)
        try:
            with self._connect() as connection:
                connection.execute('''CREATE TABLE IF NOT EXISTS deliveries (
                    id TEXT PRIMARY KEY NOT NULL,
                    fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','accepted')),
                    created_at INTEGER NOT NULL,
                    accepted_at INTEGER,
                    ordinary_event TEXT,
                    ordinary_body BLOB,
                    ordinary_signature TEXT,
                    ordinary_state TEXT NOT NULL DEFAULT 'none'
                        CHECK(ordinary_state IN ('none','staged','consumed'))
                )''')
                # Add optional ingress fields to an older owner ledger only
                # during an explicitly installed receiver release. SQLite DDL
                # is idempotent and retains existing immutable delivery rows.
                existing = {row[1] for row in connection.execute(
                    'PRAGMA table_info(deliveries)')}
                for name, definition in (
                    ('ordinary_event', 'TEXT'),
                    ('ordinary_body', 'BLOB'),
                    ('ordinary_signature', 'TEXT'),
                    ('ordinary_state', "TEXT NOT NULL DEFAULT 'none'"),
                ):
                    if name not in existing:
                        connection.execute(
                            'ALTER TABLE deliveries ADD COLUMN ' + name +
                            ' ' + definition)
        finally:
            os.umask(previous)

    @staticmethod
    def fingerprint(event, payload):
        h = hashlib.sha256()
        h.update(event.encode('ascii'))
        h.update(b'\0')
        h.update(payload)
        return h.hexdigest()

    @staticmethod
    def _checked_ordinary_signature(event, payload, signature, secret):
        # Keep the network-facing receiver limited to an authenticated,
        # bounded ingress JOURNAL; the fleet alone owns executable admission.
        if (event not in ('push', 'pull_request')
                or not isinstance(payload, bytes)
                or not 0 < len(payload) <= MAX_ORDINARY_BYTES
                or not isinstance(signature, str)
                or not isinstance(secret, bytes) or len(secret) < 32
                or len(signature) != 71 or not signature.startswith('sha256=')):
            return False
        expected = 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def claim(self, delivery_id, event, payload, now=None, *,
              ordinary_signature=None, ordinary_secret=None):
        if not isinstance(delivery_id, str) or not DELIVERY_ID.fullmatch(delivery_id.lower()):
            return 'invalid'
        ordinary = ordinary_signature is not None or ordinary_secret is not None
        if ordinary and not self._checked_ordinary_signature(
                event, payload, ordinary_signature, ordinary_secret):
            return 'invalid'
        delivery_id = delivery_id.lower()
        fingerprint = self.fingerprint(event, payload)
        when = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                connection.execute('''DELETE FROM deliveries WHERE id IN (
                    SELECT id FROM deliveries WHERE state='accepted'
                    AND accepted_at < ? AND ordinary_state!='staged'
                    ORDER BY accepted_at LIMIT 128
                )''', (when - RETENTION_SECONDS,))
                existing = connection.execute('SELECT fingerprint,state FROM deliveries WHERE id=?',
                                              (delivery_id,)).fetchone()
                if existing is not None:
                    result = ('mismatch' if existing[0] != fingerprint else
                              'duplicate' if existing[1] == 'accepted' else 'uncertain')
                else:
                    count = connection.execute('SELECT count(*) FROM deliveries').fetchone()[0]
                    if count >= MAX_RECORDS:
                        result = 'capacity_held'
                    elif ordinary and connection.execute(
                            "SELECT count(*) FROM deliveries "
                            "WHERE ordinary_state='staged'").fetchone()[0] >= MAX_STAGED_ORDINARY:
                        result = 'ordinary_capacity_held'
                    else:
                        connection.execute('''INSERT INTO deliveries
                            (id,fingerprint,state,created_at,accepted_at,
                             ordinary_event,ordinary_body,ordinary_signature,
                             ordinary_state)
                            VALUES (?,?,?,?,NULL,?,?,?,?)''',
                            (delivery_id, fingerprint, 'pending', when,
                             event if ordinary else None,
                             payload if ordinary else None,
                             ordinary_signature if ordinary else None,
                             'staged' if ordinary else 'none'))
                        result = 'claimed'
                connection.execute('COMMIT')
                return result
            except BaseException:
                connection.execute('ROLLBACK')
                raise

    def staged_ordinary(self, limit=16):
        """Read bounded, already-authenticated ingress; never execute here.

        The existing fleet's independently released controller must perform
        fresh GitHub GET and source-bound SQLite admission before consuming.
        Values include signed delivery bytes: they are private, NEVER logs.
        """
        if not isinstance(limit, int) or not 1 <= limit <= 32:
            raise RuntimeError('unsafe_ordinary_ingress_limit')
        with self._connect() as connection:
            return [
                {'delivery_id': row[0], 'fingerprint': row[1],
                 'event': row[2], 'body': bytes(row[3]),
                 'signature': row[4]}
                for row in connection.execute(
                    """SELECT id,fingerprint,ordinary_event,ordinary_body,
                              ordinary_signature FROM deliveries
                       WHERE ordinary_state='staged'
                       ORDER BY created_at,id LIMIT ?""", (limit,))
            ]

    def consume_ordinary(self, delivery_id, fingerprint):
        """CAS and purge a staged envelope ONLY after a verified queue claim."""
        if not isinstance(delivery_id, str) or not DELIVERY_ID.fullmatch(
                delivery_id.lower()) or not isinstance(fingerprint, str):
            raise RuntimeError('unsafe_ordinary_ingress_ack_identity')
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                result = connection.execute(
                    """UPDATE deliveries
                       SET ordinary_body=NULL,ordinary_signature=NULL,
                           ordinary_state='consumed'
                       WHERE id=? AND fingerprint=?
                         AND ordinary_state='staged'""",
                    (delivery_id.lower(), fingerprint))
                connection.execute('COMMIT')
                return result.rowcount == 1
            except BaseException:
                connection.execute('ROLLBACK')
                raise

    def accept(self, delivery_id, event, payload, now=None):
        when = int(time.time() if now is None else now)
        fingerprint = self.fingerprint(event, payload)
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                cursor = connection.execute('''UPDATE deliveries SET state='accepted',accepted_at=?
                    WHERE id=? AND fingerprint=? AND state='pending' ''',
                    (when, delivery_id.lower(), fingerprint))
                if cursor.rowcount != 1:
                    raise RuntimeError('delivery_claim_changed_or_not_owned')
                connection.execute('COMMIT')
            except BaseException:
                connection.execute('ROLLBACK')
                raise
