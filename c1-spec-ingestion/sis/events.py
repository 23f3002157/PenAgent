import json
import logging
from typing import Dict, Any, List, Callable, Optional
from sis.config import settings

logger = logging.getLogger(__name__)


class EventBus:
    """
    Event bus client supporting Redis Streams with graceful in-memory fallback.
    Emits 'graph.ready' and other pipeline events.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.redis_url
        self._redis_client = None
        self._in_memory_listeners: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._published_events: List[Dict[str, Any]] = []  # For inspection in tests

        # Attempt Redis connection
        self._init_redis()

    def _init_redis(self):
        import os
        if os.getenv("USE_REDIS", "false").lower() not in ("1", "true"):
            self._redis_client = None
            return

        try:
            import redis
            client = redis.from_url(
                self.redis_url, 
                decode_responses=True, 
                socket_connect_timeout=0.2, 
                socket_timeout=0.2
            )
            client.ping()
            self._redis_client = client
            logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.info(f"Redis not available ({e}). Using in-memory event bus.")
            self._redis_client = None

    def subscribe(self, event_type: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Registers an in-memory listener for an event type."""
        if event_type not in self._in_memory_listeners:
            self._in_memory_listeners[event_type] = []
        self._in_memory_listeners[event_type].append(callback)

    async def publish_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Publishes an event to Redis Stream and in-memory subscribers."""
        event_record = {
            "event_type": event_type,
            "payload": payload,
        }
        self._published_events.append(event_record)

        # 1. Publish to Redis Stream if available
        if self._redis_client:
            try:
                stream_key = "penagent:events"
                serialized = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in payload.items()}
                serialized["event_type"] = event_type
                self._redis_client.xadd(stream_key, serialized)
            except Exception as e:
                logger.warning(f"Failed to publish to Redis stream: {e}")

        # 2. Notify in-memory listeners
        listeners = self._in_memory_listeners.get(event_type, [])
        for listener in listeners:
            try:
                listener(payload)
            except Exception as e:
                logger.error(f"Listener error on event {event_type}: {e}")

    async def emit_graph_ready(self, target_id: str, graph_id: str, nodes_count: int, edges_count: int) -> None:
        """Publishes standard graph.ready event consumed by HGS and LangGraph Orchestrator."""
        payload = {
            "target_id": target_id,
            "graph_id": graph_id,
            "nodes_count": nodes_count,
            "edges_count": edges_count,
        }
        await self.publish_event("graph.ready", payload)

    def get_published_events(self) -> List[Dict[str, Any]]:
        """Returns log of published events (useful for tests)."""
        return list(self._published_events)


event_bus = EventBus()
