import pytest
from sis.tagger import AttackSurfaceTagger
from sis.models import EndpointNode, ParameterModel, AuthInfo


def test_tagger_rules():
    # Node 1: Admin endpoint with state mutation
    node_admin = EndpointNode(
        id="op_admin_post_config",
        method="POST",
        path="/api/admin/system-config",
        service_prefix="admin",
        parameters=[],
        auth=AuthInfo(type="none"),
        response_schemas={"200": {"description": "OK"}}
    )

    # Node 2: IDOR candidate with sensitive response
    node_user = EndpointNode(
        id="op_users_get_user",
        method="GET",
        path="/users/{user_id}",
        service_prefix="users",
        parameters=[
            ParameterModel(name="user_id", location="path", required=True)
        ],
        auth=AuthInfo(type="bearer"),
        response_schemas={
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "email": {"type": "string"},
                                "token": {"type": "string"},
                                "doc_id": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    )

    # Node 3: Cross service consumer of doc_id
    node_vault = EndpointNode(
        id="op_vault_get_doc",
        method="GET",
        path="/vault/v1/{doc_id}",
        service_prefix="vault",
        parameters=[
            ParameterModel(name="doc_id", location="path", required=True)
        ],
        auth=AuthInfo(type="bearer")
    )

    nodes = [node_admin, node_user, node_vault]
    tagged = AttackSurfaceTagger.tag_nodes(nodes)
    tag_map = {n.id: n.attack_surface_tags for n in tagged}

    # Verify Node 1
    assert "admin_surface" in tag_map[node_admin.id]
    assert "state_mutation" in tag_map[node_admin.id]
    assert "unauthenticated_sensitive_action" in tag_map[node_admin.id]

    # Verify Node 2
    assert "idor_candidate" in tag_map[node_user.id]
    assert "sensitive_response" in tag_map[node_user.id]

    # Verify Node 3: Cross service parameter tagged!
    assert "idor_candidate" in tag_map[node_vault.id]
    assert "cross_service_param:doc_id" in tag_map[node_vault.id]
