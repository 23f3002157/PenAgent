import pytest
from pathlib import Path
from sis.adapters.juice_shop import JuiceShopAdapter
from sis.adapters.srebench import SREBenchAdapter
from sis.adapters.dvws import DVWSAdapter
from sis.adapters.generic import GenericOpenAPIAdapter
from sis.normalizer import SpecNormalizer


@pytest.mark.asyncio
async def test_juice_shop_adapter(repo_root):
    spec_path = str(repo_root / "specs" / "juice_shop_sample.json")
    adapter = JuiceShopAdapter()
    raw_spec, metadata = await adapter.load_spec("juice_shop", "http://localhost:18001", spec_source=spec_path)

    assert "paths" in raw_spec
    assert metadata["target_type"] == "juice_shop"
    assert "/api/Users/{id}" in raw_spec["paths"]

    normalizer = SpecNormalizer()
    normalized, spec_hash = normalizer.normalize(raw_spec)
    assert len(spec_hash) == 64
    assert normalized["openapi"].startswith("3.")


@pytest.mark.asyncio
async def test_srebench_adapter(repo_root):
    spec_path = str(repo_root / "specs" / "srebench_openapi.json")
    adapter = SREBenchAdapter()
    raw_spec, metadata = await adapter.load_spec("srebench", "http://localhost:18002", spec_source=spec_path)

    assert "paths" in raw_spec
    assert metadata["target_type"] == "srebench"
    assert "/auth/v1/exchange-token" in raw_spec["paths"]
    assert "/vault/v1/documents/{doc_id}" in raw_spec["paths"]


@pytest.mark.asyncio
async def test_dvws_adapter(repo_root):
    spec_path = str(repo_root / "specs" / "dvws_openapi.json")
    adapter = DVWSAdapter()
    raw_spec, metadata = await adapter.load_spec("dvws", "http://localhost:18003", spec_source=spec_path)

    assert "paths" in raw_spec
    assert metadata["target_type"] == "dvws"
    assert len(raw_spec["paths"]) > 5


@pytest.mark.asyncio
async def test_normalizer_dereferencing():
    raw = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "profile": {"$ref": "#/components/schemas/Profile"}
                    }
                },
                "Profile": {
                    "type": "object",
                    "properties": {
                        "bio": {"type": "string"},
                        "email": {"type": "string"}
                    }
                }
            }
        },
        "paths": {
            "/user": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    normalizer = SpecNormalizer()
    normalized, spec_hash = normalizer.normalize(raw)
    schema = normalized["paths"]["/user"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["type"] == "object"
    assert "profile" in schema["properties"]
    assert schema["properties"]["profile"]["properties"]["email"]["type"] == "string"
