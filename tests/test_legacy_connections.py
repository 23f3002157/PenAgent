"""Regression for real C1/C2 leaked handles observed during integration."""
import sqlite3
import pytest
from sis.storage import GraphStorage
from hgs.queue import PriorityQueue


@pytest.mark.parametrize("storage", [GraphStorage, PriorityQueue])
def test_legacy_connection_closes_after_transaction(tmp_path, storage):
    instance = storage(db_path=str(tmp_path / "legacy.db"))
    with instance._get_connection() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
