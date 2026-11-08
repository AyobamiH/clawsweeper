"""Create-only durable delivery claims before any local CI wake-up effect.

An interrupted claim is deliberately held, not automatically replayed. The
existing fleet poll timer reconciles missed events independently from GitHub.
"""
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

DELIVERY_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
RETENTION_SECONDS = 30 * 86400
MAX_RECORDS = 20000


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
                    accepted_at INTEGER
                )''')
        finally:
            os.umask(previous)

    @staticmethod
    def fingerprint(event, payload):
        h = hashlib.sha256()
        h.update(event.encode('ascii'))
        h.update(b'\0')
        h.update(payload)
        return h.hexdigest()

    def claim(self, delivery_id, event, payload, now=None):
        if not isinstance(delivery_id, str) or not DELIVERY_ID.fullmatch(delivery_id.lower()):
            return 'invalid'
        delivery_id = delivery_id.lower()
        fingerprint = self.fingerprint(event, payload)
        when = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                connection.execute('''DELETE FROM deliveries WHERE id IN (
                    SELECT id FROM deliveries WHERE state='accepted'
                    AND accepted_at < ? ORDER BY accepted_at LIMIT 128
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
                    else:
                        connection.execute('INSERT INTO deliveries VALUES (?,?,?, ?,NULL)',
                                           (delivery_id, fingerprint, 'pending', when))
                        result = 'claimed'
                connection.execute('COMMIT')
                return result
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
