"""Configuration for tool discovery service.

This module provides configuration management for the dynamic tool discovery
system, including Gateway settings, cache behavior, and error handling.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class DiscoveryConfig:
    """Configuration for tool discovery service.
    
    Provides all configuration parameters for tool discovery behavior,
    with sensible defaults that can be overridden via environment variables.
    """
    
    # Gateway configuration
    gateway_url: str
    gateway_timeout: int = 30
    
    # Cache configuration
    cache_ttl_seconds: int = 3600  # 1 hour default
    
    # Discovery behavior
    enable_gateway_discovery: bool = True
    fallback_to_local_registry: bool = True
    
    # Error handling
    max_retry_attempts: int = 3
    retry_delay_seconds: int = 5
    
    # Observability
    enable_metrics: bool = True
    log_level: str = "INFO"
    
    @classmethod
    def from_environment(cls, gateway_url: Optional[str] = None) -> "DiscoveryConfig":
        """Create configuration from environment variables.
        
        Args:
            gateway_url: Gateway URL (required if not in environment)
            
        Returns:
            DiscoveryConfig instance with values from environment
            
        Raises:
            ValueError: If required configuration is missing
        """
        # Get gateway URL from parameter or environment
        url = gateway_url or os.environ.get("GATEWAY_DISCOVERY_URL")
        if not url:
            raise ValueError(
                "Gateway URL must be provided via gateway_url parameter "
                "or GATEWAY_DISCOVERY_URL environment variable"
            )
        
        return cls(
            gateway_url=url,
            gateway_timeout=int(os.environ.get("GATEWAY_DISCOVERY_TIMEOUT", "30")),
            cache_ttl_seconds=int(os.environ.get("TOOL_CACHE_TTL_SECONDS", "3600")),
            enable_gateway_discovery=os.environ.get("ENABLE_GATEWAY_DISCOVERY", "true").lower() == "true",
            fallback_to_local_registry=os.environ.get("FALLBACK_TO_LOCAL_REGISTRY", "true").lower() == "true",
            max_retry_attempts=int(os.environ.get("GATEWAY_MAX_RETRY_ATTEMPTS", "3")),
            retry_delay_seconds=int(os.environ.get("GATEWAY_RETRY_DELAY_SECONDS", "5")),
            enable_metrics=os.environ.get("ENABLE_DISCOVERY_METRICS", "true").lower() == "true",
            log_level=os.environ.get("DISCOVERY_LOG_LEVEL", "INFO")
        )
    
    def validate(self) -> None:
        """Validate configuration values.
        
        Raises:
            ValueError: If any configuration value is invalid
        """
        if self.gateway_timeout <= 0:
            raise ValueError("gateway_timeout must be positive")
        
        if self.cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be positive")
        
        if self.max_retry_attempts < 0:
            raise ValueError("max_retry_attempts must be non-negative")
        
        if self.retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must be non-negative")
        
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            raise ValueError(f"Invalid log_level: {self.log_level}")
