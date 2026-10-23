from typing import Dict, Any, Tuple, Optional
from sis.adapters.base import BaseAdapter
from sis.normalizer import SpecNormalizer
from sis.config import settings


class JuiceShopAdapter(BaseAdapter):
    """
    Adapter for OWASP Juice Shop.
    Loads mounted /app/specs/juice_shop_sample.json (or local equivalent).
    Optionally validates live connection to base_url.
    """

    async def load_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        candidate_sources = []
        if spec_source and spec_source != "auto":
            candidate_sources.append(spec_source)
        
        # Primary paths as specified in design doc
        candidate_sources.extend([
            "/app/specs/juice_shop_sample.json",
            settings.juice_shop_spec,
            "specs/juice_shop_sample.json",
            f"{base_url.rstrip('/')}/assets/public/specs/openapi.json",
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
                f"JuiceShopAdapter failed to locate spec. Tried sources: {candidate_sources}"
            )

        spec_dict = SpecNormalizer.parse_raw_spec(raw_content)
        metadata = {
            "adapter": "JuiceShopAdapter",
            "target_id": target_id,
            "target_type": "juice_shop",
            "source": used_source,
            "source_type": source_type,
            "notes": "Loaded sample subset spec for OWASP Juice Shop SPA",
        }
        return spec_dict, metadata
