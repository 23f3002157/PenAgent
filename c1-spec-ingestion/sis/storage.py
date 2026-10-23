import json
import sqlite3
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from sis.models import EndpointGraph, IngestJob, JobStatus
from sis.config import settings


class GraphStorage:
    """
    Persistent repository for EndpointGraphs, Ingestion Jobs, and Spec Hashes.
    Uses SQLite (or configured relational DB) with JSON columns + hot cache.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Check settings
            db_url = settings.database_url
            if db_url.startswith("sqlite:///"):
                self.db_path = db_url.replace("sqlite:///", "")
            else:
                self.db_path = "./sis.db"
        else:
            self.db_path = db_path

        # Hot in-memory cache for fast repeated reads
        self._graph_cache: Dict[str, EndpointGraph] = {}
        self._job_cache: Dict[str, IngestJob] = {}

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables for persistent storage."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Graphs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_graphs (
                    target_id TEXT PRIMARY KEY,
                    graph_id TEXT NOT NULL,
                    spec_hash TEXT NOT NULL,
                    graph_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            # Ingestion Jobs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ingest_jobs (
                    job_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    graph_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata_json TEXT
                )
            """)
            # Spec Hashes & Raw Specs for drift detection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS spec_revisions (
                    target_id TEXT PRIMARY KEY,
                    spec_hash TEXT NOT NULL,
                    raw_spec_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_graph(self, graph: EndpointGraph) -> None:
        """Saves or updates an EndpointGraph."""
        self._graph_cache[graph.target_id] = graph

        graph_json = json.dumps(graph.model_dump())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO endpoint_graphs (target_id, graph_id, spec_hash, graph_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    graph_id=excluded.graph_id,
                    spec_hash=excluded.spec_hash,
                    graph_json=excluded.graph_json,
                    updated_at=excluded.updated_at
            """, (graph.target_id, graph.graph_id, graph.spec_hash, graph_json, graph.created_at, now))
            conn.commit()

    def get_graph(self, target_id: str) -> Optional[EndpointGraph]:
        """Retrieves EndpointGraph by target_id, checking hot cache first."""
        if target_id in self._graph_cache:
            return self._graph_cache[target_id]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT graph_json FROM endpoint_graphs WHERE target_id = ?", (target_id,))
            row = cursor.fetchone()
            if row:
                data = json.loads(row["graph_json"])
                graph = EndpointGraph.model_validate(data)
                self._graph_cache[target_id] = graph
                return graph

        return None

    def save_job(self, job: IngestJob) -> None:
        """Saves or updates an IngestJob."""
        self._job_cache[job.job_id] = job
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta_json = json.dumps(job.metadata)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ingest_jobs (job_id, target_id, status, error, graph_id, created_at, updated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    error=excluded.error,
                    graph_id=excluded.graph_id,
                    updated_at=excluded.updated_at,
                    metadata_json=excluded.metadata_json
            """, (job.job_id, job.target_id, job.status.value, job.error, job.graph_id, job.created_at, now, meta_json))
            conn.commit()

    def get_job(self, job_id: str) -> Optional[IngestJob]:
        """Retrieves an IngestJob by job_id."""
        if job_id in self._job_cache:
            return self._job_cache[job_id]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ingest_jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            if row:
                job = IngestJob(
                    job_id=row["job_id"],
                    target_id=row["target_id"],
                    status=JobStatus(row["status"]),
                    error=row["error"],
                    graph_id=row["graph_id"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    metadata=json.loads(row["metadata_json"] or "{}"),
                )
                self._job_cache[job_id] = job
                return job

        return None

    def record_spec_revision(self, target_id: str, spec_hash: str, raw_spec: Dict[str, Any]) -> None:
        """Records spec hash and content for drift detection."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        spec_json = json.dumps(raw_spec)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO spec_revisions (target_id, spec_hash, raw_spec_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    spec_hash=excluded.spec_hash,
                    raw_spec_json=excluded.raw_spec_json,
                    updated_at=excluded.updated_at
            """, (target_id, spec_hash, spec_json, now))
            conn.commit()

    def get_stored_spec_hash(self, target_id: str) -> Optional[str]:
        """Returns the last known SHA-256 hash for target_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT spec_hash FROM spec_revisions WHERE target_id = ?", (target_id,))
            row = cursor.fetchone()
            if row:
                return row["spec_hash"]
        return None
