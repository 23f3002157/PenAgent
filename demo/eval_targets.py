"""Target policy configs for the real-benchmark evaluation (demo/run_evaluation.py).

Operation IDs below are exactly what C1 (sis) derives from each target's real
OpenAPI spec (verified live -- `node.id` must match a policy key exactly, or
C3 rejects with operation_not_authorized_or_schema_drift). Juice Shop's own
`/assets/public/specs/openapi.json` just serves its SPA's index.html, not a
spec, despite returning HTTP 200; its sample spec at
demo/benchmark-data/specs/juice_shop_sample.json (copied from the container's
/app/specs/) is used instead, and doesn't include the admin-registration
bypass endpoint -- that one op (op_js_register) exists only for guided mode,
which builds its own graph and doesn't depend on C1 discovery.

Two policy sets per target:
  - AUTONOMOUS: no header_variations for trust-bypass headers, no
    forbidden_values that require foreknowledge of a secret's exact value.
    What a human operator could reasonably configure without having already
    solved the benchmark.
  - GUIDED: full expectations derived from the ground truth, used to prove
    the execution/classification/approval/report pipeline is correct given
    a known attack path -- not a test of discovery.
"""

JUICE_SHOP = "http://127.0.0.1:18001"
SREBENCH = "http://127.0.0.1:18002"
DVWS = "http://127.0.0.1:18003"

# ---------------------------------------------------------------------------
# DVWS
# ---------------------------------------------------------------------------

def dvws_operations(mode: str) -> dict:
    guided = mode == "guided"
    return {
        "op_get_account_api_v1_accounts__account_id__get": {
            "method": "GET", "path": "/api/v1/accounts/{account_id}", "risk": "safe",
            "expectation": {
                "expected_behavior": "An account holder must not be able to read another account's balance or API key",
                "protected_fields": ["secret_api_key", "balance"],
                "forbidden_values": {"id": "2"} if guided else {},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"] if guided else [],
            },
        },
        "op_login_api_v1_auth_login_post": {
            "method": "POST", "path": "/api/v1/auth/login", "risk": "safe",
            "expectation": {
                "expected_behavior": "No credential-less request should ever receive an admin-role token",
                "protected_fields": ["token"],
                "forbidden_values": {"role": "admin"} if guided else {},
                "owasp_categories": ["API2:2023 - Broken Authentication"] if guided else [],
            },
        },
        "op_update_profile_api_v1_accounts__account_id__profile_put": {
            "method": "PUT", "path": "/api/v1/accounts/{account_id}/profile", "risk": "destructive",
            "expectation": {
                "expected_behavior": "A profile update must not be able to grant itself an elevated role",
                "protected_fields": ["account.secret_api_key"],
                "forbidden_values": {"account.role": "admin"} if guided else {},
                "owasp_categories": ["API3:2023 - Broken Object Property Level Authorization"] if guided else [],
            },
        },
        "op_purge_cache_api_v1_admin_maintenance_purge_cache_delete": {
            "method": "DELETE", "path": "/api/v1/admin/maintenance/purge-cache", "risk": "destructive",
            "allowed_headers": ["x-role"],
            "expectation": {
                "expected_behavior": "A cache purge must never execute without explicit human approval",
                "signal_fields": ["status"],
                "owasp_categories": ["API5:2023 - Broken Function Level Authorization"] if guided else [],
            },
        },
        "op_get_debug_env_api_v1_debug_env_get": {
            "method": "GET", "path": "/api/v1/debug/env", "risk": "safe",
            "expectation": {
                "expected_behavior": "Anonymous clients must not receive internal credentials or signing secrets",
                "protected_fields": ["DATABASE_URL", "JWT_SECRET"],
                # Known only to an operator who has already done reconnaissance on
                # this fixed demo value -- guided-only, never assumed autonomously.
                "forbidden_values": {"DATABASE_URL": "postgres://dvws_user:p@ssw0rd123@internal-db:5432/dvws_prod"} if guided else {},
                "owasp_categories": ["API8:2023 - Security Misconfiguration"] if guided else [],
            },
        },
    }


def dvws_target(mode: str) -> dict:
    return {"base_url": DVWS, "operations": dvws_operations(mode)}


# ---------------------------------------------------------------------------
# SREBench-API
# ---------------------------------------------------------------------------

def srebench_operations(mode: str) -> dict:
    guided = mode == "guided"
    return {
        "op_get_user_profile_users_v1_profile__user_id__get": {
            "method": "GET", "path": "/users/v1/profile/{user_id}", "risk": "safe",
            "allowed_headers": ["x-service-token"],
            "expectation": {
                "expected_behavior": "A user's profile must not be readable by an anonymous cross-service caller",
                "protected_fields": ["profile.org_id"],
                "forbidden_values": {"profile.id": "usr_102"} if guided else {},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"] if guided else [],
            },
        },
        "op_get_vault_document_vault_v1_documents__doc_id__get": {
            "method": "GET", "path": "/vault/v1/documents/{doc_id}", "risk": "safe",
            "allowed_headers": ["x-internal-service", "x-forwarded-user"],
            # The actual bypass values -- only given to the guided/"already did
            # recon" operator. Autonomous mode authorizes the header keys but
            # supplies no working value, matching a real operator who knows a
            # trust-boundary header exists (from the spec) but not its secret.
            "header_variations": {
                "x-internal-service": ["auth-service-internal"] if guided else [],
                "x-forwarded-user": ["usr_999"] if guided else [],
            },
            "expectation": {
                "expected_behavior": "A vault document must not be released to a caller without a verified internal service identity",
                "protected_fields": ["document.secret"],
                "forbidden_values": {"access_granted": True} if guided else {},
                "signal_fields": ["access_granted", "vulnerability_chain_step"],
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"] if guided else [],
            },
        },
    }


def srebench_target(mode: str) -> dict:
    return {"base_url": SREBENCH, "operations": srebench_operations(mode)}


# ---------------------------------------------------------------------------
# Juice Shop
# ---------------------------------------------------------------------------

def juice_shop_operations(mode: str) -> dict:
    guided = mode == "guided"
    ops = {
        "op_users_get_api_users_id": {
            "method": "GET", "path": "/api/Users/{id}", "risk": "safe",
            "expectation": {
                "expected_behavior": "A user must not be able to read another user's account by guessing their ID",
                "signal_fields": ["data.email"],
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"] if guided else [],
            },
        },
        "op_admin_get_rest_admin_application-configuration": {
            "method": "GET", "path": "/rest/admin/application-configuration", "risk": "safe",
            "expectation": {
                "expected_behavior": "Admin configuration must not be exposed to anonymous clients",
                "protected_fields": ["config.server"],
                "signal_fields": ["config"],
                "owasp_categories": ["API8:2023 - Security Misconfiguration"] if guided else [],
            },
        },
    }
    if guided:
        # Not part of the provided sample spec C1 ingests (it omits
        # registration entirely), so this op is never autonomously
        # discoverable with this spec -- guided-only, and built into its own
        # graph node directly by demo/run_evaluation.py's guided_run.
        ops["op_js_register"] = {
            "method": "POST", "path": "/api/Users", "risk": "destructive",
            "expectation": {
                "expected_behavior": "Self-registration must never be able to grant the admin role",
                "protected_fields": ["data.id"],
                "forbidden_values": {"data.role": "admin"},
                "owasp_categories": ["API2:2023 - Broken Authentication"],
            },
        }
    return ops


def juice_shop_target(mode: str) -> dict:
    return {"base_url": JUICE_SHOP, "operations": juice_shop_operations(mode)}


# ---------------------------------------------------------------------------

def all_targets(mode: str) -> dict:
    return {"dvws": dvws_target(mode), "srebench-api": srebench_target(mode), "juice-shop": juice_shop_target(mode)}
