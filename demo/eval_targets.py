"""Target policy configs for the real-benchmark evaluation (demo/run_evaluation.py).

Operation IDs below are exactly what C1 (sis) derives from each target's real
OpenAPI spec (verified live -- `node.id` must match a policy key exactly, or
C3 rejects with operation_not_authorized_or_schema_drift). Juice Shop's own
`/assets/public/specs/openapi.json` just serves its SPA's index.html, not a
spec, despite returning HTTP 200; its sample spec at
demo/benchmark-data/specs/juice_shop_sample.json (copied from the container's
/app/specs/) is used instead, and doesn't include most of the ops below --
they exist only for guided mode, which builds its own graph and doesn't
depend on C1 discovery.

Guided-only: these are full expectations derived from the ground truth,
used to prove the execution/classification/approval/report pipeline is
correct given a known attack path -- not a test of discovery. Fully-
autonomous zero-hint discovery was evaluated in an earlier pass (see
docs/RESULTS.md's history) and is no longer run or reported; it scored 0%
TPR on all three real targets for a specific, documented architectural
reason (HGS's candidate-surfacing heuristics and the "never invent a path/
body parameter" safety rule), which stayed true regardless of further
ground-truth expansion, so repeating it added no new information.
"""

JUICE_SHOP = "http://127.0.0.1:18001"
SREBENCH = "http://127.0.0.1:18002"
DVWS = "http://127.0.0.1:18003"

# ---------------------------------------------------------------------------
# DVWS
# ---------------------------------------------------------------------------

def dvws_operations() -> dict:
    return {
        "op_get_account_api_v1_accounts__account_id__get": {
            "method": "GET", "path": "/api/v1/accounts/{account_id}", "risk": "safe",
            "expectation": {
                "expected_behavior": "An account holder must not be able to read another account's balance or API key",
                "protected_fields": ["secret_api_key", "balance"],
                "forbidden_values": {"id": "2"},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"],
            },
        },
        "op_login_api_v1_auth_login_post": {
            "method": "POST", "path": "/api/v1/auth/login", "risk": "safe",
            "expectation": {
                "expected_behavior": "No credential-less request should ever receive an admin-role token",
                "protected_fields": ["token"],
                "forbidden_values": {"role": "admin"},
                "owasp_categories": ["API2:2023 - Broken Authentication"],
            },
        },
        "op_update_profile_api_v1_accounts__account_id__profile_put": {
            "method": "PUT", "path": "/api/v1/accounts/{account_id}/profile", "risk": "destructive",
            "expectation": {
                "expected_behavior": "A profile update must not be able to grant itself an elevated role",
                "protected_fields": ["account.secret_api_key"],
                "forbidden_values": {"account.role": "admin"},
                "owasp_categories": ["API3:2023 - Broken Object Property Level Authorization"],
            },
        },
        "op_purge_cache_api_v1_admin_maintenance_purge_cache_delete": {
            "method": "DELETE", "path": "/api/v1/admin/maintenance/purge-cache", "risk": "destructive",
            "allowed_headers": ["x-role"],
            "expectation": {
                "expected_behavior": "A cache purge must never execute without explicit human approval",
                "signal_fields": ["status"],
                "owasp_categories": ["API5:2023 - Broken Function Level Authorization"],
            },
        },
        "op_get_debug_env_api_v1_debug_env_get": {
            "method": "GET", "path": "/api/v1/debug/env", "risk": "safe",
            "expectation": {
                "expected_behavior": "Anonymous clients must not receive internal credentials or signing secrets",
                "protected_fields": ["DATABASE_URL", "JWT_SECRET"],
                "forbidden_values": {"DATABASE_URL": "postgres://dvws_user:p@ssw0rd123@internal-db:5432/dvws_prod"},
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
    }


def dvws_target() -> dict:
    return {"base_url": DVWS, "operations": dvws_operations()}


# ---------------------------------------------------------------------------
# SREBench-API
# ---------------------------------------------------------------------------

def srebench_operations() -> dict:
    return {
        "op_get_user_profile_users_v1_profile__user_id__get": {
            "method": "GET", "path": "/users/v1/profile/{user_id}", "risk": "safe",
            "allowed_headers": ["x-service-token"],
            "expectation": {
                "expected_behavior": "A user's profile must not be readable by an anonymous cross-service caller",
                "protected_fields": ["profile.org_id"],
                "forbidden_values": {"profile.id": "usr_102"},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"],
            },
        },
        "op_get_vault_document_vault_v1_documents__doc_id__get": {
            "method": "GET", "path": "/vault/v1/documents/{doc_id}", "risk": "safe",
            "allowed_headers": ["x-internal-service", "x-forwarded-user"],
            "header_variations": {"x-internal-service": ["auth-service-internal"], "x-forwarded-user": ["usr_999"]},
            "expectation": {
                "expected_behavior": "A vault document must not be released to a caller without a verified internal service identity",
                "protected_fields": ["document.secret"],
                "forbidden_values": {"access_granted": True},
                "signal_fields": ["access_granted", "vulnerability_chain_step"],
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"],
            },
        },
    }


def srebench_target() -> dict:
    return {"base_url": SREBENCH, "operations": srebench_operations()}


# ---------------------------------------------------------------------------
# Juice Shop
#
# Every op below beyond the original 3 (users_get, admin_config, register)
# was verified live with curl against the running container before being
# added -- not guessed. See demo/explore_run.py's module docstring for the
# raw verification and demo/run_evaluation.py's GUIDED_CHAINS for the exact
# session-chained steps (register -> login -> reuse the token) that exercise
# the ones requiring authentication.
# ---------------------------------------------------------------------------

def juice_shop_operations() -> dict:
    return {
        "op_users_get_api_users_id": {
            "method": "GET", "path": "/api/Users/{id}", "risk": "safe",
            "expectation": {
                "expected_behavior": "An authenticated user must not be able to read another user's account by guessing their ID",
                "protected_fields": ["data.email"],
                "signal_fields": ["data.email"],
                "forbidden_values": {"data.role": "admin"},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"],
                # Live-verified: this op now 401s anonymously (properly fixed
                # in this Juice Shop version) but still leaks another user's
                # full record -- email, role -- to any *authenticated* caller
                # who simply guesses a different numeric ID. An authenticated
                # BOLA, same as op_js_basket_view_admin.
                "requires_anonymous": False,
            },
        },
        "op_admin_get_rest_admin_application-configuration": {
            "method": "GET", "path": "/rest/admin/application-configuration", "risk": "safe",
            "expectation": {
                "expected_behavior": "Admin configuration must not be exposed to anonymous clients",
                "protected_fields": ["config.server"],
                "signal_fields": ["config"],
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
        "op_js_register": {
            "method": "POST", "path": "/api/Users", "risk": "destructive",
            "expectation": {
                "expected_behavior": "Self-registration must never be able to grant the admin role",
                "protected_fields": ["data.id"],
                "forbidden_values": {"data.role": "admin"},
                "owasp_categories": ["API2:2023 - Broken Authentication"],
            },
        },
        # Classic UNION-based SQLi via the product search filter -- dumps the
        # live SQLite schema. forbidden_values pins the injection's own
        # reflected placeholder strings ("2","3" from the UNION SELECT's
        # literal columns), not unstable real schema text, so the match stays
        # exact and deterministic regardless of what tables exist.
        "op_js_search_sqli": {
            "method": "GET", "path": "/rest/products/search", "risk": "safe",
            "expectation": {
                "expected_behavior": "The product search filter must not allow a UNION-based SQL injection to read the database schema",
                "protected_fields": ["data.0.name"],
                "forbidden_values": {"data.0.name": "2", "data.0.description": "3"},
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
        # Static file disclosures -- plain-text bodies, matched by
        # forbidden_substrings (penagent_common/config.py), not a JSON path.
        "op_js_ftp_acquisitions": {
            "method": "GET", "path": "/ftp/acquisitions.md", "risk": "safe",
            "expectation": {
                "expected_behavior": "An internal confidential document must not be served to anonymous clients",
                "forbidden_substrings": ["confidential! Do not distribute"],
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
        "op_js_metrics": {
            "method": "GET", "path": "/metrics", "risk": "safe",
            "expectation": {
                "expected_behavior": "Internal observability metrics must not be exposed without authentication",
                "forbidden_substrings": ["file_uploads_count"],
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
        # The null-byte filter bypass (demo/explore_run.py) applied to the
        # project's own backed-up package.json.
        "op_js_ftp_pkgbak": {
            "method": "GET", "path": "/ftp/package.json.bak%2500.md", "risk": "safe",
            "expectation": {
                "expected_behavior": "A static-file extension filter must not be bypassable to disclose a backup file",
                "forbidden_substrings": ["http://owasp-juice.shop"],
                "owasp_categories": ["API8:2023 - Security Misconfiguration"],
            },
        },
        # BOLA on another user's basket -- the guided binding always targets
        # basket id 1 (the seeded admin account's basket), so a stable
        # forbidden_values match on its known UserId is legitimate, not a guess.
        "op_js_basket_view_admin": {
            "method": "GET", "path": "/rest/basket/{id}", "risk": "safe",
            "expectation": {
                "expected_behavior": "A caller must not be able to view another user's shopping basket by guessing its ID",
                "protected_fields": ["data.Products"],
                "forbidden_values": {"data.UserId": 1},
                "owasp_categories": ["API1:2023 - Broken Object Level Authorization"],
                # This is an *authenticated* BOLA -- the caller has their own
                # valid session, just points it at someone else's basket id.
                # requires_anonymous defaults True (most of this project's
                # findings are unauthenticated misconfigurations); explicitly
                # False here or the real match is thrown away by the
                # anonymous-only auth-context check.
                "requires_anonymous": False,
            },
        },
        # "Payback Time": checking out a basket with a negative quantity
        # produces a negative-total order -- evidenced on the order-history
        # read afterward. The guided chain always adds 1x ProductId 1
        # (Apple Juice, $1.99) at quantity -5, so the resulting total
        # (-9.95) is fully deterministic, not an unstable guess.
        "op_js_order_history": {
            "method": "GET", "path": "/rest/order-history", "risk": "safe",
            "expectation": {
                "expected_behavior": "An order must never be allowed to complete with a negative total price",
                "protected_fields": ["data.0.totalPrice"],
                "forbidden_values": {"data.0.totalPrice": -9.95},
                "owasp_categories": ["API6:2023 - Unrestricted Access to Sensitive Business Flows"],
                "requires_anonymous": False,
            },
        },
    }


def juice_shop_target() -> dict:
    return {"base_url": JUICE_SHOP, "operations": juice_shop_operations()}


# ---------------------------------------------------------------------------

def all_targets() -> dict:
    return {"dvws": dvws_target(), "srebench-api": srebench_target(), "juice-shop": juice_shop_target()}
