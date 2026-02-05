"""Data models for dynamic tool discovery.

This module defines the core data structures used throughout the tool discovery
system, including tool definitions, cache metadata, validation results, and
Gateway responses.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional


@dataclass
class ToolDefinition:
    """Validated tool definition ready for use with Bedrock.
    
    Represents a tool that has been validated and is ready to be passed
    to the Bedrock Converse API. Includes methods for format conversion.
    """
    name: str
    description: str
    input_schema: Dict[str, Any]
    
    def to_bedrock_format(self) -> Dict[str, Any]:
        """Convert to Bedrock Converse API tool format.
        
        Returns:
            Dictionary in Bedrock tool specification format matching
            the format used by the legacy hardcoded registry.
            
        Example:
            {
                "toolSpec": {
                    "name": "list_s3_buckets",
                    "description": "Lists all S3 buckets",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {...}
                        }
                    }
                }
            }
        """
        return {
            "toolSpec": {
                "name": self.name,
                "description": self.description,
                "inputSchema": {
                    "json": self.input_schema
                }
            }
        }
    
    def __eq__(self, other: object) -> bool:
        """Check equality based on name, description, and schema."""
        if not isinstance(other, ToolDefinition):
            return NotImplemented
        return (
            self.name == other.name
            and self.description == other.description
            and self.input_schema == other.input_schema
        )
    
    def __hash__(self) -> int:
        """Hash based on tool name."""
        return hash(self.name)


@dataclass
class CachedTools:
    """Tool definitions with cache metadata.
    
    Stores tool definitions along with caching metadata including
    timestamp and TTL for expiration checking.
    """
    tools: List[ToolDefinition]
    cached_at: datetime
    ttl_seconds: int
    
    def is_expired(self) -> bool:
        """Check if cache has exceeded TTL.
        
        Returns:
            True if the cache age exceeds the configured TTL,
            False otherwise.
        """
        age = (datetime.utcnow() - self.cached_at).total_seconds()
        return age > self.ttl_seconds
    
    def age_seconds(self) -> int:
        """Get age of cached data in seconds.
        
        Returns:
            Number of seconds since the tools were cached.
        """
        return int((datetime.utcnow() - self.cached_at).total_seconds())


@dataclass
class ToolListResponse:
    """Response from Gateway tools/list request.
    
    Represents the response from an MCP tools/list request,
    including the list of tools and optional pagination cursor.
    """
    tools: List[Dict[str, Any]]
    next_cursor: Optional[str] = None
    
    def has_more(self) -> bool:
        """Check if more pages are available.
        
        Returns:
            True if next_cursor is present indicating more pages,
            False otherwise.
        """
        return self.next_cursor is not None


@dataclass
class ValidationResult:
    """Result of tool validation.
    
    Contains validation status, error messages, and warnings
    for a tool definition validation attempt.
    """
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def add_error(self, message: str) -> None:
        """Add validation error and mark result as invalid.
        
        Args:
            message: Error message describing the validation failure
        """
        self.is_valid = False
        self.errors.append(message)
    
    def add_warning(self, message: str) -> None:
        """Add validation warning without affecting validity.
        
        Args:
            message: Warning message describing a non-critical issue
        """
        self.warnings.append(message)
    
    def __bool__(self) -> bool:
        """Allow using ValidationResult in boolean context."""
        return self.is_valid
