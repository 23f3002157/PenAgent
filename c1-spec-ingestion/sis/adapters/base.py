import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import httpx
from sis.normalizer import SpecNormalizer


class BaseAdapter(ABC):
    """Abstract base adapter for loading OpenAPI/Swagger specifications."""

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    async def _fetch_url(self, url: str) -> Optional[str]:
        """Fetches spec content over HTTP/HTTPS with timeout."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
        except Exception:
            return None
        return None

    def _read_local_file(self, file_path: str) -> Optional[str]:
        """Reads spec content from filesystem, trying multiple resolution roots."""
        path = Path(file_path)
        if path.is_file():
            return path.read_text(encoding="utf-8")

        # Check current working directory
        cwd_candidate = Path.cwd() / file_path
        if cwd_candidate.is_file():
            return cwd_candidate.read_text(encoding="utf-8")

        # Check settings base directory
        from sis.config import settings
        base_candidate = settings.base_dir / file_path
        if base_candidate.is_file():
            return base_candidate.read_text(encoding="utf-8")

        # Walk up from this adapter file to discover workspace root
        curr = Path(__file__).resolve().parent
        for _ in range(6):
            target_candidate = curr / file_path
            if target_candidate.is_file():
                return target_candidate.read_text(encoding="utf-8")
            spec_candidate = curr / "specs" / Path(file_path).name
            if spec_candidate.is_file():
                return spec_candidate.read_text(encoding="utf-8")
            curr = curr.parent

        # Check inside /app container mount points
        container_candidate = Path("/app") / file_path.lstrip("/")
        if container_candidate.is_file():
            return container_candidate.read_text(encoding="utf-8")

        return None

    async def load_raw_content(self, source: str) -> Tuple[Optional[str], str]:
        """Loads spec raw string from local file first, then URL if network source."""
        # 1. Try local file resolution first
        content = self._read_local_file(source)
        if content:
            return content, "file"

        # 2. Try HTTP(S) URL
        if source.startswith("http://") or source.startswith("https://"):
            content = await self._fetch_url(source)
            if content:
                return content, "url"

        return None, "not_found"

    @abstractmethod
    async def load_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Loads spec dictionary and auxiliary metadata.
        Returns: (raw_spec_dict, adapter_metadata)
        """
        pass
