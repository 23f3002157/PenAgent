from typing import Optional
from sis.adapters.base import BaseAdapter
from sis.adapters.juice_shop import JuiceShopAdapter
from sis.adapters.srebench import SREBenchAdapter
from sis.adapters.dvws import DVWSAdapter
from sis.adapters.generic import GenericOpenAPIAdapter


def get_adapter(target_id: str, spec_source: Optional[str] = None) -> BaseAdapter:
    """
    Factory resolving target_id to specialized adapter or GenericOpenAPIAdapter.
    """
    tid = target_id.lower().replace("-", "_").replace(" ", "_")

    if "juice" in tid or "shop" in tid:
        return JuiceShopAdapter()
    elif "srebench" in tid or "sre" in tid:
        return SREBenchAdapter()
    elif "dvws" in tid or "damn_vulnerable" in tid:
        return DVWSAdapter()
    else:
        return GenericOpenAPIAdapter()


__all__ = [
    "BaseAdapter",
    "JuiceShopAdapter",
    "SREBenchAdapter",
    "DVWSAdapter",
    "GenericOpenAPIAdapter",
    "get_adapter",
]
