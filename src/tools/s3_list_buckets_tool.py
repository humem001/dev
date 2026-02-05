"""S3 ListBuckets MCP Tool.

This tool implements the MCP protocol for listing S3 buckets with user attribution.
"""

import boto3
from botocore.config import Config
from typing import Any, Dict, Optional
from .mcp_tool_interface import MCPTool, MCPToolDefinition
from .tool_errors import handle_s3_error
from config.timeout_config import TIMEOUT_CONFIG


class S3ListBucketsTool(MCPTool):
    """MCP tool for listing S3 buckets.
    
    This tool executes the S3 ListBuckets operation and returns bucket information
    with creation dates, following the MCP protocol specification.
    """
    
    def __init__(self, s3_client=None, timeout: Optional[int] = None):
        """Initialize the S3 ListBuckets tool.
        
        Args:
            s3_client: Optional boto3 S3 client for testing. If None, creates default client.
            timeout: Timeout for S3 operations in seconds (defaults to TIMEOUT_CONFIG)
        """
        if s3_client is None:
            # Create S3 client with timeout configuration
            timeout_seconds = timeout or TIMEOUT_CONFIG.s3_operation
            boto_config = Config(
                connect_timeout=timeout_seconds,
                read_timeout=timeout_seconds,
                retries={'max_attempts': 0}  # We handle retries at a higher level
            )
            self.s3_client = boto3.client('s3', config=boto_config)
        else:
            self.s3_client = s3_client
    
    def get_definition(self) -> MCPToolDefinition:
        """Return the tool definition following MCP protocol.
        
        Returns:
            MCPToolDefinition with name, description, and input schema
        """
        return MCPToolDefinition(
            name='list_s3_buckets',
            description='List all S3 buckets in the account with creation dates',
            input_schema={
                'type': 'object',
                'properties': {},
                'required': []
            }
        )
    
    def execute(self, parameters: Dict[str, Any], user_context: Dict[str, str]) -> Dict[str, Any]:
        """Execute the S3 ListBuckets operation.
        
        Args:
            parameters: Tool-specific parameters (empty for ListBuckets)
            user_context: User identity information (user_id, username, client_id)
            
        Returns:
            Dictionary containing:
                - buckets: List of bucket information (name, creation_date)
                - count: Total number of buckets
                - user_id: User who executed the operation
                
        Raises:
            ToolExecutionError: If S3 operation fails
        """
        try:
            # Execute S3 ListBuckets operation
            response = self.s3_client.list_buckets()
            
            # Format bucket information
            buckets = []
            for bucket in response.get('Buckets', []):
                buckets.append({
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].isoformat()
                })
            
            # Return results with user attribution
            return {
                'buckets': buckets,
                'count': len(buckets),
                'user_id': user_context.get('user_id', 'unknown')
            }
        except Exception as e:
            # Convert S3 errors to ToolExecutionError
            tool_error = handle_s3_error(e)
            raise tool_error
