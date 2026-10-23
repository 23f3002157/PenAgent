from typing import Dict, Any, Tuple, Optional
from sis.adapters.base import BaseAdapter
from sis.normalizer import SpecNormalizer
from sis.config import settings


class DVWSAdapter(BaseAdapter):
    """
    Adapter for Damn Vulnerable Web Services (DVWS-Node).
    Pulls live GET /openAPI-spec.json or falls back to local spec.
    Preserves and formats OWASP API Top-10 categories from spec tags.
    """

    async def load_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        candidate_sources = []
        if spec_source and spec_source != "auto":
            candidate_sources.append(spec_source)

        # Primary paths
        candidate_sources.extend([
            f"{base_url.rstrip('/')}/openAPI-spec.json",
            f"{base_url.rstrip('/')}/api-docs/openapi.json",
            "/app/specs/dvws_openapi.json",
            settings.dvws_spec,
            "specs/dvws_openapi.json",
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
                f"DVWSAdapter failed to locate spec. Tried sources: {candidate_sources}"
            )

        spec_dict = SpecNormalizer.parse_raw_spec(raw_content)

        metadata = {
            "adapter": "DVWSAdapter",
            "target_id": target_id,
            "target_type": "dvws",
            "source": used_source,
            "source_type": source_type,
            "owasp_top10_tagged": True,
            "notes": "DVWS-Node specification with intrinsic OWASP API Top-10 annotations",
        }
        return spec_dict, metadata
