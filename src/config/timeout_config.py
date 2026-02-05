"""Centralized timeout configuration for all external service calls.

This module defines timeout values for:
- JWT validation (JWKS retrieval)
- Bedrock inference
- AgentCore Gateway invocation
- AgentCore Memory operations
- S3 operations

All timeouts are in seconds and can be overridden via environment variables.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class TimeoutConfig:
    """Timeout configuration for external service calls.
    
    All timeout values are in seconds.
    """
    
    # JWT validation timeout (JWKS retrieval from Cognito)
    jwt_validation: int = 5
    
    # Bedrock model inference timeout
    bedrock_inference: int = 30
    
    # AgentCore Gateway invocation timeout
    gateway_invocation: int = 15
    
    # MCP Tool execution timeout (within Gateway)
    tool_execution: int = 15
    
    # AgentCore Memory operation timeout
    memory_operation: int = 5
    
    # S3 operation timeout
    s3_operation: int = 10
    
    @classmethod
    def from_environment(cls) -> 'TimeoutConfig':
        """Create TimeoutConfig from environment variables.
        
        Environment variables:
        - TIMEOUT_JWT_VALIDATION: JWT validation timeout in seconds
        - TIMEOUT_BEDROCK_INFERENCE: Bedrock inference timeout in seconds
        - TIMEOUT_GATEWAY_INVOCATION: Gateway invocation timeout in seconds
        - TIMEOUT_TOOL_EXECUTION: Tool execution timeout in seconds
        - TIMEOUT_MEMORY_OPERATION: Memory operation timeout in seconds
        - TIMEOUT_S3_OPERATION: S3 operation timeout in seconds
        
        Returns:
            TimeoutConfig with values from environment or defaults
        """
        return cls(
            jwt_validation=int(os.getenv('TIMEOUT_JWT_VALIDATION', '5')),
            bedrock_inference=int(os.getenv('TIMEOUT_BEDROCK_INFERENCE', '30')),
            gateway_invocation=int(os.getenv('TIMEOUT_GATEWAY_INVOCATION', '15')),
            tool_execution=int(os.getenv('TIMEOUT_TOOL_EXECUTION', '15')),
            memory_operation=int(os.getenv('TIMEOUT_MEMORY_OPERATION', '5')),
            s3_operation=int(os.getenv('TIMEOUT_S3_OPERATION', '10'))
        )
    
    def get_timeout(self, service: str) -> Optional[int]:
        """Get timeout for a specific service.
        
        Args:
            service: Service name (jwt_validation, bedrock_inference, etc.)
            
        Returns:
            Timeout in seconds, or None if service not found
        """
        return getattr(self, service, None)


# Global timeout configuration instance
# Can be overridden by calling TimeoutConfig.from_environment()
TIMEOUT_CONFIG = TimeoutConfig()


def get_timeout(service: str) -> int:
    """Get timeout for a specific service.
    
    Args:
        service: Service name (jwt_validation, bedrock_inference, etc.)
        
    Returns:
        Timeout in seconds
        
    Raises:
        ValueError: If service name is invalid
    """
    timeout = TIMEOUT_CONFIG.get_timeout(service)
    if timeout is None:
        raise ValueError(f"Invalid service name: {service}")
    return timeout
