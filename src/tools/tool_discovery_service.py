"""Tool discovery service for dynamic tool retrieval from Gateway.

This module provides the main orchestration service for discovering tools
from AgentCore Gateway, managing caching, validation, and error handling.
"""

import logging
import time
from typing import List, Optional

from .discovery_models import ToolDefinition
from .gateway_discovery_client import (
    GatewayDiscoveryClient,
    GatewayConnectionError,
    GatewayAuthError,
    MCPProtocolError
)
from .tool_cache import ToolCache
from .tool_validator import ToolValidator
from .discovery_config import DiscoveryConfig


logger = logging.getLogger(__name__)


class ToolDiscoveryError(Exception):
    """Exception raised when tool discovery fails with no fallback available."""
    pass


class ToolDiscoveryService:
    """Manages dynamic tool discovery from AgentCore Gateway.
    
    Orchestrates tool discovery by querying the Gateway, validating results,
    managing cache, and providing fallback mechanisms for resilience.
    """
    
    def __init__(
        self,
        gateway_client: GatewayDiscoveryClient,
        cache: ToolCache,
        validator: ToolValidator,
        config: DiscoveryConfig
    ):
        """Initialize the tool discovery service.
        
        Args:
            gateway_client: Client for communicating with Gateway
            cache: Cache for storing tool definitions
            validator: Validator for tool schemas
            config: Configuration for discovery behavior
        """
        self.gateway_client = gateway_client
        self.cache = cache
        self.validator = validator
        self.config = config
        
        logger.info("Tool discovery service initialized")
    
    def discover_tools(self, force_refresh: bool = False) -> List[ToolDefinition]:
        """Discover available tools from Gateway.
        
        Implements cache-first retrieval with fallback to Gateway query.
        Handles errors gracefully by falling back to cached tools when available.
        
        Args:
            force_refresh: If True, bypass cache and query Gateway
            
        Returns:
            List of validated tool definitions
            
        Raises:
            ToolDiscoveryError: If discovery fails and no fallback available
        """
        logger.info(f"Tool discovery initiated (force_refresh={force_refresh})")
        
        # Check cache first (unless force refresh)
        if not force_refresh:
            cached = self.cache.get()
            if cached and not cached.is_expired():
                logger.info(
                    f"Using cached tools: {len(cached.tools)} tools "
                    f"(age: {cached.age_seconds()}s)"
                )
                return cached.tools
        
        # Query Gateway with retry logic
        for attempt in range(self.config.max_retry_attempts):
            try:
                logger.debug(f"Querying Gateway for tools (attempt {attempt + 1})")
                
                # Get tools from Gateway
                raw_tools = self.gateway_client.list_all_tools()
                
                # Check for unique names
                if not self.validator.check_unique_names(raw_tools):
                    logger.warning("Duplicate tool names detected in Gateway response")
                
                # Validate and filter
                validated_tools = self.validator.validate_tools(raw_tools)
                
                if not validated_tools:
                    raise ToolDiscoveryError(
                        "No valid tools found after validation"
                    )
                
                # Cache validated tools
                self.cache.set(validated_tools)
                
                logger.info(f"Successfully discovered {len(validated_tools)} tools from Gateway")
                return validated_tools
                
            except GatewayAuthError as e:
                logger.error(f"Gateway authentication failed: {e}")
                # Try token refresh
                try:
                    self.gateway_client.token_manager.refresh_token()
                    logger.info("Token refresh attempted, retrying...")
                    continue
                except Exception as refresh_error:
                    logger.error(f"Token refresh failed: {refresh_error}")
                    break
                
            except (GatewayConnectionError, MCPProtocolError) as e:
                logger.warning(
                    f"Gateway error (attempt {attempt + 1}/{self.config.max_retry_attempts}): {e}"
                )
                
                if attempt < self.config.max_retry_attempts - 1:
                    # Wait before retry
                    time.sleep(self.config.retry_delay_seconds)
                    continue
                
                # Final attempt failed, try cache fallback
                logger.warning("All Gateway retry attempts exhausted")
                break
        
        # Gateway query failed, try cache fallback
        cached = self.cache.get()
        if cached:
            cache_age = cached.age_seconds()
            logger.warning(
                f"Using stale cached tools due to Gateway unavailability: "
                f"{len(cached.tools)} tools (age: {cache_age}s, TTL: {self.cache.ttl_seconds}s)"
            )
            return cached.tools
        
        # No cache available
        raise ToolDiscoveryError(
            "Gateway unavailable and no cached tools available"
        )
    
    def refresh_cache(self) -> None:
        """Manually refresh the tool cache from Gateway.
        
        Forces a Gateway query regardless of cache state.
        
        Raises:
            ToolDiscoveryError: If Gateway is unavailable
        """
        logger.info("Manual cache refresh triggered")
        try:
            tools = self.discover_tools(force_refresh=True)
            logger.info(f"Cache refreshed with {len(tools)} tools")
        except ToolDiscoveryError as e:
            logger.error(f"Cache refresh failed: {e}")
            raise
    
    def get_cached_tools(self) -> Optional[List[ToolDefinition]]:
        """Get tools from cache without querying Gateway.
        
        Returns:
            Cached tool definitions or None if cache is empty
        """
        cached = self.cache.get()
        if cached:
            return cached.tools
        return None
