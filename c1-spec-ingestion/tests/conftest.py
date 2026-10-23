import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure sis package is on sys.path
service_dir = Path(__file__).resolve().parent.parent
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from sis.storage import GraphStorage
from sis.service import SpecIngestionService
from sis.main import app
from sis.api import service as api_service


@pytest.fixture
def repo_root() -> Path:
    """Returns the repository root directory."""
    return Path(__file__).resolve().parent.parent.parent.parent


@pytest.fixture
def temp_storage(tmp_path) -> GraphStorage:
    """Provides an isolated SQLite GraphStorage instance for unit tests."""
    db_file = tmp_path / "test_sis.db"
    return GraphStorage(db_path=str(db_file))


@pytest.fixture
def temp_service(temp_storage) -> SpecIngestionService:
    """Provides a SpecIngestionService instance backed by temp storage."""
    return SpecIngestionService(storage=temp_storage)


@pytest.fixture
def client(temp_service) -> TestClient:
    """Provides FastAPI TestClient wired with isolated storage."""
    api_service.storage = temp_service.storage
    return TestClient(app)
