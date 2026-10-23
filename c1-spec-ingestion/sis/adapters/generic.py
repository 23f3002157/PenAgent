from typing import Dict, Any, Tuple, Optional
from sis.adapters.base import BaseAdapter
from sis.normalizer import SpecNormalizer


class GenericOpenAPIAdapter(BaseAdapter):
    """
    Generic adapter for arbitrary OpenAPI 3.x / Swagger 2.0 endpoints or file paths.
    Probes common specification discovery routes.
    """

    async def load_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        candidate_sources = []
        if spec_source and spec_source != "auto":
            candidate_sources.append(spec_source)

        candidate_sources.extend([
            f"{base_url.rstrip('/')}/openapi.json",
            f"{base_url.rstrip('/')}/swagger.json",
            f"{base_url.rstrip('/')}/v3/api-docs",
            f"{base_url.rstrip('/')}/api-docs/openapi.json",
        ])

        raw_content = None
        used_source = ""
        source_type = ""

        for candidate in candidate_sources:
            content, s_type = await self.load_raw_content(candidate)
            if content:
                raw_content = content
                used_source = candidate
                source_type = s_type
                break

        if not raw_content:
            raise FileNotFoundError(
                f"GenericOpenAPIAdapter failed to locate OpenAPI spec for {target_id}. Checked: {candidate_sources}"
            )

        spec_dict = SpecNormalizer.parse_raw_spec(raw_content)
        metadata = {
            "adapter": "GenericOpenAPIAdapter",
            "target_id": target_id,
            "target_type": "generic",
            "source": used_source,
            "source_type": source_type,
        }
        return spec_dict, metadata
