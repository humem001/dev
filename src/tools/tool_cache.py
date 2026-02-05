"""Tool definition cache with TTL-based expiration.

This module provides caching for tool definitions retrieved from the Gateway,
with configurable time-to-live (TTL) for automatic expiration.
"""

import logging
from datetime import datetime
from typing import Optional, List
from threading import Lock

from .discovery_models import ToolDefinition, CachedTools


logger = logging.getLogger(__name__)


class ToolCache:
    """Cache for tool definitions with TTL-based expiration.
    
    Provides thread-safe caching of tool definitions with automatic
    expiration based on configurable TTL.
    """
    
    def __init__(self, ttl_seconds: int = 3600):
        """Initialize tool cache.
        
        Args:
            ttl_seconds: Time-to-live for cached entries in seconds (default: 3600 = 1 hour)
        """
        self.ttl_seconds = ttl_seconds
        self._cached_tools: Optional[CachedTools] = None
        self._lock = Lock()
        
        logger.info(f"Initialized tool cache with TTL={ttl_seconds}s")
    
    def get(self) -> Optional[CachedTools]:
        """Get cached tool definitions if not expired.
        
        Returns:
            CachedTools object or None if cache is empty/expired
        """
        with self._lock:
            if self._cached_tools is None:
                logger.debug("Cache miss: no cached tools")
                return None
            
            if self._cached_tools.is_expired():
                logger.debug(
                    f"Cache expired: age={self._cached_tools.age_seconds()}s, "
                    f"TTL={self.ttl_seconds}s"
                )
                return None
            
            logger.debug(
                f"Cache hit: {len(self._cached_tools.tools)} tools, "
                f"age={self._cached_tools.age_seconds()}s"
            )
            return self._cached_tools
    
    def set(self, tools: List[ToolDefinition]) -> None:
        """Store tool definitions in cache with current timestamp.
        
        Args:
            tools: List of validated tool definitions to cache
        """
        with self._lock:
            self._cached_tools = CachedTools(
                tools=tools,
                cached_at=datetime.utcnow(),
                ttl_seconds=self.ttl_seconds
            )
            logger.info(f"Cached {len(tools)} tools")
    
    def is_expired(self) -> bool:
        """Check if cached tools have exceeded TTL.
        
        Returns:
            True if cache is expired or empty, False otherwise
        """
        with self._lock:
            if self._cached_tools is None:
                return True
            return self._cached_tools.is_expired()
    
    def clear(self) -> None:
        """Clear all cached tool definitions."""
        with self._lock:
            self._cached_tools = None
            logger.info("Cache cleared")
    
    def get_age_seconds(self) -> Optional[int]:
        """Get age of cached data in seconds.
        
        Returns:
            Age in seconds or None if cache is empty
        """
        with self._lock:
            if self._cached_tools is None:
                return None
            return self._cached_tools.age_seconds()
