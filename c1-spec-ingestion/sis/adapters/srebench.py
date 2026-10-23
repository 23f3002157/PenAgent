import json
from typing import Dict, Any, Tuple, Optional
from sis.adapters.base import BaseAdapter
from sis.normalizer import SpecNormalizer
from sis.config import settings


class SREBenchAdapter(BaseAdapter):
    """
    Adapter for SREBench-API.
    Pulls live GET /openapi.json from base_url, with fallback to local mounted spec.
    Separately attaches scenario evaluation metadata strictly for offline benchmark scoring.
    """

    async def load_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        candidate_sources = []
        if spec_source and spec_source != "auto":
            candidate_sources.append(spec_source)

        # Primary path: live /openapi.json from FastAPI service
        candidate_sources.extend([
            f"{base_url.rstrip('/')}/openapi.json",
            "/app/specs/srebench_openapi.json",
            settings.srebench_spec,
            "specs/srebench_openapi.json",
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
                f"SREBenchAdapter failed to locate spec. Tried sources: {candidate_sources}"
            )

        spec_dict = SpecNormalizer.parse_raw_spec(raw_content)

        # Pull scenario metadata for benchmark evaluation (strictly kept in metadata, not planner)
        scenarios_metadata = await self._fetch_scenarios_metadata(base_url)

        metadata = {
            "adapter": "SREBenchAdapter",
            "target_id": target_id,
            "target_type": "srebench",
            "source": used_source,
            "source_type": source_type,
            "evaluation_scenarios": scenarios_metadata,
            "notes": "FastAPI auto-generated spec with cross-service evaluation metadata",
        }
        return spec_dict, metadata

    async def _fetch_scenarios_metadata(self, base_url: str) -> Dict[str, Any]:
        """Attempts live GET /scenarios/list or falls back to ground_truth_chains.json."""
        live_scenarios_url = f"{base_url.rstrip('/')}/scenarios/list"
        content, _ = await self.load_raw_content(live_scenarios_url)
        if content:
            try:
                return json.loads(content)
            except Exception:
                pass

        # Local fallback from datasets
        dataset_content, _ = await self.load_raw_content("datasets/ground_truth_chains.json")
        if dataset_content:
            try:
                data = json.loads(dataset_content)
                return data.get("targets", {}).get("srebench_api", {})
            except Exception:
                pass

        return {}
