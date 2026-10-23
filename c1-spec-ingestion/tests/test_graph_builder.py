import pytest
from sis.graph_builder import GraphBuilder
from sis.models import EndpointNode, ParameterModel, AuthInfo


def test_operation_id_generation():
    op_id = GraphBuilder.generate_operation_id("GET", "/users/v1/profile/{id}")
    assert op_id.startswith("op_users_get_")
    assert "{" not in op_id
    assert "}" not in op_id


def test_edge_inference_parameter_matching():
    builder = GraphBuilder()

    node_auth = EndpointNode(
        id="op_auth_post_exchange_token",
        method="POST",
        path="/auth/v1/exchange-token",
        service_prefix="auth",
        response_schemas={
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "user_id": {"type": "string"},
                                "service_token": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    )

    node_user = EndpointNode(
        id="op_users_get_profile",
        method="GET",
        path="/users/v1/profile/{id}",
        service_prefix="users",
        parameters=[
            ParameterModel(name="id", location="path", required=True)
        ],
        response_schemas={
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "doc_id": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    )

    node_vault = EndpointNode(
        id="op_vault_get_document",
        method="GET",
        path="/vault/v1/documents/{doc_id}",
        service_prefix="vault",
        parameters=[
            ParameterModel(name="doc_id", location="path", required=True)
        ]
    )

    nodes = [node_auth, node_user, node_vault]
    mock_spec = {"paths": {}}
    edges = builder.infer_edges(nodes, mock_spec)

    # We expect edges:
    # 1. auth -> user (user_id -> id alias)
    # 2. user -> vault (doc_id exact match)
    auth_to_user = [e for e in edges if e.from_node == node_auth.id and e.to_node == node_user.id]
    user_to_vault = [e for e in edges if e.from_node == node_user.id and e.to_node == node_vault.id]

    assert len(auth_to_user) > 0
    assert auth_to_user[0].confidence >= 0.70
    assert auth_to_user[0].metadata["cross_service"] is True

    assert len(user_to_vault) > 0
    assert "doc_id" in user_to_vault[0].field
    assert user_to_vault[0].confidence >= 0.80
    assert user_to_vault[0].metadata["cross_service"] is True
