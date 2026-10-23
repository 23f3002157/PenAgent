import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure hgs is on sys.path
service_dir = Path(__file__).resolve().parent.parent
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from hgs.queue import PriorityQueue
from hgs.service import HypothesisGenerationService
from hgs.main import app
from hgs.api import service as api_service


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent


@pytest.fixture
def temp_queue(tmp_path) -> PriorityQueue:
    db_file = tmp_path / "test_hgs.db"
    return PriorityQueue(db_path=str(db_file))


@pytest.fixture
def temp_service(temp_queue) -> HypothesisGenerationService:
    return HypothesisGenerationService(queue=temp_queue)


@pytest.fixture
def client(temp_service) -> TestClient:
    api_service.queue = temp_service.queue
    api_service._target_knowledge = temp_service._target_knowledge
    api_service._cached_attack_surfaces = temp_service._cached_attack_surfaces
    return TestClient(app)


@pytest.fixture
def sample_attack_surface() -> dict:
    """Fixture representing an ingested attack surface from SIS."""
    return {
        "target_id": "test_srebench",
        "nodes": [
            {
                "id": "op_auth_post_exchange_token",
                "method": "POST",
                "path": "/auth/v1/exchange-token",
                "service_prefix": "auth",
                "attack_surface_tags": ["state_mutation"],
                "parameters": [],
                "auth": {"type": "none"}
            },
            {
                "id": "op_users_get_profile",
                "method": "GET",
                "path": "/users/v1/profile/{user_id}",
                "service_prefix": "users",
                "attack_surface_tags": ["idor_candidate", "sensitive_response"],
                "parameters": [{"name": "user_id", "in": "path"}],
                "auth": {"type": "bearer"}
            },
            {
                "id": "op_vault_get_document",
                "method": "GET",
                "path": "/vault/v1/documents/{doc_id}",
                "service_prefix": "vault",
                "attack_surface_tags": ["idor_candidate", "cross_service_param:doc_id"],
                "parameters": [{"name": "doc_id", "in": "path"}],
                "auth": {"type": "bearer"}
            },
            {
                "id": "op_admin_delete_purge_cache",
                "method": "DELETE",
                "path": "/api/v1/admin/maintenance/purge-cache",
                "service_prefix": "admin",
                "attack_surface_tags": ["admin_surface", "state_mutation", "unauthenticated_sensitive_action"],
                "parameters": [],
                "auth": {"type": "none"}
            },
            {
                "id": "op_debug_get_env",
                "method": "GET",
                "path": "/api/v1/debug/env",
                "service_prefix": "debug",
                "attack_surface_tags": ["admin_surface"],
                "parameters": [],
                "auth": {"type": "none"}
            }
        ],
        "edges": [
            {
                "from_node": "op_auth_post_exchange_token",
                "to_node": "op_users_get_profile",
                "relation": "produces_param_consumed_by",
                "field": "service_token",
                "confidence": 0.85,
                "metadata": {"cross_service": True}
            },
            {
                "from_node": "op_users_get_profile",
                "to_node": "op_vault_get_document",
                "relation": "produces_param_consumed_by",
                "field": "doc_id",
                "confidence": 0.88,
                "metadata": {"cross_service": True}
            }
        ]
    }
