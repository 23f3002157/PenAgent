import json
import sqlite3
import datetime
import logging
from typing import List, Dict, Any, Optional
from hgs.models import AttackHypothesis, HypothesisStatus
from hgs.config import settings

logger = logging.getLogger(__name__)


class PriorityQueue:
    """
    Priority Queue for AttackHypothesis objects.
    Uses Redis Sorted Sets when available, backed by persistent SQLite storage.
    """

    def __init__(self, db_path: Optional[str] = None, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.redis_url
        self._redis_client = None

        if db_path is None:
            db_url = settings.database_url
            self.db_path = db_url.replace("sqlite:///", "") if db_url.startswith("sqlite:///") else "./hgs.db"
        else:
            self.db_path = db_path

        self._init_db()
        self._init_redis()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    owasp_category TEXT NOT NULL,
                    priority REAL NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS batches (
                    batch_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def _init_redis(self):
        import os
        if os.getenv("USE_REDIS", "false").lower() not in ("1", "true"):
            self._redis_client = None
            return

        try:
            import redis
            client = redis.from_url(
                self.redis_url, decode_responses=True, socket_connect_timeout=0.2, socket_timeout=0.2
            )
            client.ping()
            self._redis_client = client
        except Exception:
            self._redis_client = None

    def push_batch(self, target_id: str, batch_id: str, mode: str, hypotheses: List[AttackHypothesis]) -> None:
        """Stores a ranked batch and enqueues pending hypotheses."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO batches (batch_id, target_id, mode, count, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (batch_id, target_id, mode, len(hypotheses), now))

            for hyp in hypotheses:
                data_json = json.dumps(hyp.model_dump())
                cursor.execute("""
                    INSERT OR REPLACE INTO hypotheses (id, target_id, owasp_category, priority, status, data_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (hyp.id, target_id, hyp.owasp_category, hyp.priority, hyp.status.value, data_json, hyp.created_at or now, now))
            conn.commit()

        # Update Redis sorted set
        if self._redis_client:
            redis_key = f"penagent:queue:{target_id}"
            for hyp in hypotheses:
                if hyp.status == HypothesisStatus.PENDING:
                    self._redis_client.zadd(redis_key, {hyp.id: hyp.priority})

    def pop_next(self, target_id: str) -> Optional[AttackHypothesis]:
        """Pops the highest-priority pending hypothesis from the queue."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM hypotheses 
                WHERE target_id = ? AND status = 'pending'
                ORDER BY priority DESC 
                LIMIT 1
            """, (target_id,))
            row = cursor.fetchone()
            if not row:
                return None

            data = json.loads(row["data_json"])
            hyp = AttackHypothesis.model_validate(data)
            hyp.status = HypothesisStatus.IN_PROGRESS
            updated_json = json.dumps(hyp.model_dump())

            cursor.execute("""
                UPDATE hypotheses 
                SET status = 'in_progress', data_json = ?, updated_at = ?
                WHERE id = ?
            """, (updated_json, now, hyp.id))
            conn.commit()

            if self._redis_client:
                self._redis_client.zrem(f"penagent:queue:{target_id}", hyp.id)

            return hyp

    def peek_queue(self, target_id: str, limit: int = 25) -> List[AttackHypothesis]:
        """Returns the pending hypotheses in the queue ordered by priority descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data_json FROM hypotheses 
                WHERE target_id = ?
                ORDER BY priority DESC 
                LIMIT ?
            """, (target_id, limit))
            rows = cursor.fetchall()
            return [AttackHypothesis.model_validate(json.loads(r["data_json"])) for r in rows]

    def get_hypothesis(self, hypothesis_id: str) -> Optional[AttackHypothesis]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM hypotheses WHERE id = ?", (hypothesis_id,))
            row = cursor.fetchone()
            if row:
                return AttackHypothesis.model_validate(json.loads(row["data_json"]))
        return None

    def update_hypothesis(self, hyp: AttackHypothesis) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE hypotheses 
                SET status = ?, priority = ?, data_json = ?, updated_at = ?
                WHERE id = ?
            """, (hyp.status.value, hyp.priority, json.dumps(hyp.model_dump()), now, hyp.id))
            conn.commit()

    def get_batch(self, batch_id: str) -> List[AttackHypothesis]:
        """Retrieves hypotheses belonging to a specific batch."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT data_json FROM hypotheses 
                WHERE data_json LIKE ?
                ORDER BY priority DESC
            """, (f'%{batch_id}%',))
            rows = cursor.fetchall()
            if rows:
                return [AttackHypothesis.model_validate(json.loads(r["data_json"])) for r in rows]
            # Fallback: get all for target if batch_id is in batches table
            cursor.execute("SELECT target_id FROM batches WHERE batch_id = ?", (batch_id,))
            b_row = cursor.fetchone()
            if b_row:
                return self.peek_queue(b_row["target_id"], limit=50)
            return []
