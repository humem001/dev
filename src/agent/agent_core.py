"""Strands Framework Agent core implementation.

This module implements the AI agent using Strands Framework with Claude 3 Sonnet,
integrating conversation memory retrieval and tool execution capabilities.
"""

import json
import uuid
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

from models.user_context import UserContext
from models.conversation import ConversationMessage
from models.agent_response import AgentResponse, ToolExecution
from memory.memory_client import (
    MemoryClient,
    MemoryServiceUnavailableError,
    SessionNotFoundError
)
from gateway.gateway_client import (
    GatewayClient,
    GatewayConfig,
    GatewayError
)
from tools.tool_discovery import get_discovery_service
from .exceptions import (
    AgentError,
    BedrockError,
    BedrockThrottlingError,
    BedrockModelUnavailableError,
    BedrockTimeoutError
)
from .error_handlers import handle_agent_error, format_error_response
from config.timeout_config import TIMEOUT_CONFIG


@dataclass
class AgentConfig:
    """Configuration for the Agent."""
    bedrock_model_id: str
    agentcore_gateway_url: str
    agentcore_memory_id: str
    session_timeout_minutes: int = 60
    max_context_messages: int = 10
    max_context_tokens: int = 4000
    region_name: Optional[str] = None
    bedrock_timeout: Optional[int] = None  # Defaults to TIMEOUT_CONFIG.bedrock_inference
    
    def __post_init__(self):
        """Set default timeout from TIMEOUT_CONFIG if not provided."""
        if self.bedrock_timeout is None:
            self.bedrock_timeout = TIMEOUT_CONFIG.bedrock_inference


class Agent:
    """Strands Framework-based AI agent with Claude 3 Sonnet.
    
    Handles:
    - Prompt processing using Bedrock
    - Conversation memory retrieval and storage
    - Tool selection and invocation
    - Response generation
    - Error handling with graceful degradation
    """
    
    def __init__(self, config: AgentConfig):
        """Initialize Agent.
        
        Args:
            config: Agent configuration
        """
        self.config = config
        
        # Initialize Bedrock client with timeout configuration
        try:
            boto_config = Config(
                connect_timeout=config.bedrock_timeout,
                read_timeout=config.bedrock_timeout,
                retries={'max_attempts': 0}  # We handle retries at a higher level
            )
            
            self.bedrock_client = boto3.client(
                'bedrock-runtime',
                region_name=config.region_name,
                config=boto_config
            )
        except Exception as e:
            raise AgentError(f"Failed to initialize Bedrock client: {str(e)}")
        
        # Initialize Memory client
        self.memory_client = MemoryClient(
            memory_id=config.agentcore_memory_id,
            session_timeout_minutes=config.session_timeout_minutes,
            max_context_messages=config.max_context_messages,
            max_context_tokens=config.max_context_tokens,
            region_name=config.region_name
        )
        
        # Initialize Gateway client
        gateway_config = GatewayConfig(
            gateway_url=config.agentcore_gateway_url
        )
        self.gateway_client = GatewayClient(gateway_config)
        
        # Initialize tool discovery service (for backward compatibility)
        self.tool_discovery = get_discovery_service()
        
        # Cache for Gateway tools (populated on first use)
        self._gateway_tools_cache = None
        self._gateway_tools_jwt = None
    
    def list_available_tools(self) -> List[str]:
        """List all available tools.
        
        Returns:
            List of tool names
        """
        return self.tool_discovery.list_available_tools()
    
    def get_tool_definitions(self):
        """Get definitions for all available tools.
        
        Returns:
            List of tool definitions
        """
        return self.tool_discovery.get_tool_definitions()
    
    def _get_tools_from_gateway(
        self,
        jwt_token: str,
        request_id: str
    ) -> List[Dict[str, Any]]:
        """Get tool definitions from Gateway.
        
        Uses caching to avoid repeated Gateway calls within the same request.
        
        Args:
            jwt_token: JWT token for authentication
            request_id: Request ID for tracing
            
        Returns:
            List of tool definitions in Bedrock format
        """
        # Check cache (only if same JWT token)
        if self._gateway_tools_cache is not None and self._gateway_tools_jwt == jwt_token:
            return self._gateway_tools_cache
        
        try:
            # Get tools from Gateway
            gateway_tools = self.gateway_client.list_tools(
                jwt_token=jwt_token,
                request_id=request_id
            )
            
            # Convert to Bedrock format
            bedrock_tools = []
            for tool in gateway_tools:
                bedrock_tools.append({
                    'name': tool['name'],
                    'description': tool['description'],
                    'input_schema': tool['inputSchema']
                })
            
            # Cache the result
            self._gateway_tools_cache = bedrock_tools
            self._gateway_tools_jwt = jwt_token
            
            return bedrock_tools
            
        except Exception as e:
            # Log error but don't fail - fall back to local registry
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to get tools from Gateway: {e}. Falling back to local registry.")
            
            # Fall back to local registry
            return self.tool_discovery.get_tools_for_bedrock()
    
    def process_prompt(
        self,
        prompt: str,
        user_context: UserContext,
        jwt_token: str,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> AgentResponse:
        """Process user prompt and generate response.
        
        This is the main entry point for agent processing. It:
        1. Creates or retrieves conversation session
        2. Retrieves conversation context from memory
        3. Processes prompt with Bedrock
        4. Invokes tools if needed
        5. Generates response
        6. Stores conversation in memory
        
        Args:
            prompt: User's natural language input
            user_context: User identity information
            jwt_token: JWT access token for authentication
            session_id: Optional session ID for conversation continuity
            request_id: Optional request ID for tracing
            
        Returns:
            AgentResponse with generated response and metadata
            
        Raises:
            AgentError: For agent processing errors
        """
        # Generate request ID if not provided
        if request_id is None:
            request_id = str(uuid.uuid4())
        
        try:
            # Create or retrieve session
            if session_id is None:
                session_id = self._create_session(user_context)
            
            # Retrieve conversation context
            context_messages = self._retrieve_context(session_id)
            
            # Store user message
            self._store_user_message(session_id, prompt)
            
            # Process with Bedrock
            tool_executions = []
            response_text = self._process_with_bedrock(
                prompt=prompt,
                context_messages=context_messages,
                user_context=user_context,
                jwt_token=jwt_token,
                request_id=request_id,
                tool_executions=tool_executions
            )
            
            # Store assistant response
            self._store_assistant_message(
                session_id=session_id,
                response=response_text,
                tool_calls=[te.__dict__ for te in tool_executions] if tool_executions else None
            )
            
            # Return formatted response
            return AgentResponse(
                response=response_text,
                session_id=session_id,
                user_context=user_context,
                tool_executions=tool_executions,
                request_id=request_id
            )
        
        except Exception as e:
            # Log the actual exception for debugging
            import logging
            logger = logging.getLogger()
            logger.error(f"Agent processing exception: {type(e).__name__}: {str(e)}", exc_info=True)
            
            # Handle error and return user-friendly response
            error_dict = handle_agent_error(e)
            error_response = format_error_response(error_dict, request_id)
            
            # If it's a degraded mode (memory unavailable), continue processing
            if error_dict.get('degraded_mode'):
                # Retry without memory
                try:
                    tool_executions = []
                    response_text = self._process_with_bedrock(
                        prompt=prompt,
                        context_messages=[],
                        user_context=user_context,
                        jwt_token=jwt_token,
                        request_id=request_id,
                        tool_executions=tool_executions
                    )
                    
                    return AgentResponse(
                        response=response_text,
                        session_id=session_id or str(uuid.uuid4()),
                        user_context=user_context,
                        tool_executions=tool_executions,
                        request_id=request_id
                    )
                except Exception as retry_error:
                    # Log retry failure
                    logger.error(f"Retry failed: {type(retry_error).__name__}: {str(retry_error)}", exc_info=True)
                    # If retry fails, raise original error
                    raise AgentError(error_response.get('message', 'Processing failed'))
            
            # For non-degraded errors, raise with user-friendly message
            raise AgentError(error_response.get('message', 'Processing failed'))
    
    def _create_session(self, user_context: UserContext) -> str:
        """Create new conversation session.
        
        Args:
            user_context: User identity
            
        Returns:
            Session ID
        """
        try:
            return self.memory_client.create_session(user_context.user_id)
        except MemoryServiceUnavailableError:
            # Graceful degradation - generate session ID without memory
            return str(uuid.uuid4())
        except Exception as e:
            raise AgentError(f"Failed to create session: {str(e)}")
    
    def _retrieve_context(self, session_id: str) -> List[ConversationMessage]:
        """Retrieve conversation context from memory.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of conversation messages (empty if unavailable)
        """
        try:
            return self.memory_client.retrieve_context(session_id)
        except (MemoryServiceUnavailableError, SessionNotFoundError):
            # Graceful degradation - continue without context
            return []
        except Exception:
            # Graceful degradation - continue without context
            return []
    
    def _store_user_message(self, session_id: str, prompt: str) -> None:
        """Store user message in memory.
        
        Args:
            session_id: Session identifier
            prompt: User prompt
        """
        try:
            self.memory_client.store_message(
                session_id=session_id,
                role='user',
                content=prompt
            )
        except Exception:
            # Graceful degradation - continue even if storage fails
            pass
    
    def _store_assistant_message(
        self,
        session_id: str,
        response: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Store assistant message in memory.
        
        Args:
            session_id: Session identifier
            response: Assistant response
            tool_calls: Optional tool execution details
        """
        try:
            self.memory_client.store_message(
                session_id=session_id,
                role='assistant',
                content=response,
                tool_calls=tool_calls
            )
        except Exception:
            # Graceful degradation - continue even if storage fails
            pass
    
    def _process_with_bedrock(
        self,
        prompt: str,
        context_messages: List[ConversationMessage],
        user_context: UserContext,
        jwt_token: str,
        request_id: str,
        tool_executions: List[ToolExecution]
    ) -> str:
        """Process prompt with Bedrock and handle tool execution.
        
        Args:
            prompt: User prompt
            context_messages: Conversation history
            user_context: User identity
            jwt_token: JWT token
            request_id: Request ID
            tool_executions: List to append tool executions to
            
        Returns:
            Generated response text
            
        Raises:
            BedrockError: For Bedrock API errors
        """
        # Build messages for Bedrock
        messages = self._build_bedrock_messages(prompt, context_messages)
        
        # Invoke Bedrock
        try:
            response = self._invoke_bedrock(messages, jwt_token, request_id)
            
            # Check if tool use is required
            if self._requires_tool_execution(response):
                # Extract tool information
                tool_name, tool_params = self._extract_tool_info(response)
                
                # Execute tool
                tool_result = self._execute_tool(
                    tool_name=tool_name,
                    parameters=tool_params,
                    user_context=user_context,
                    jwt_token=jwt_token,
                    request_id=request_id,
                    tool_executions=tool_executions
                )
                
                # Generate final response with tool result
                return self._generate_response_with_tool_result(
                    messages=messages,
                    tool_name=tool_name,
                    tool_result=tool_result,
                    jwt_token=jwt_token,
                    request_id=request_id
                )
            else:
                # Direct response without tools
                return self._extract_response_text(response)
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ThrottlingException':
                raise BedrockThrottlingError(
                    "Bedrock API rate limit exceeded"
                )
            elif error_code in ['ModelNotReadyException', 'ServiceUnavailableException']:
                raise BedrockModelUnavailableError(
                    "Bedrock model temporarily unavailable"
                )
            elif error_code == 'RequestTimeout':
                raise BedrockTimeoutError(
                    f"Bedrock request timed out after {self.config.bedrock_timeout}s"
                )
            else:
                raise BedrockError(f"Bedrock API error: {str(e)}")
        
        except Exception as e:
            # Check if it's a timeout error from boto3
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                raise BedrockTimeoutError(
                    f"Bedrock request timed out after {self.config.bedrock_timeout}s"
                )
            raise BedrockError(f"Failed to process with Bedrock: {str(e)}")
    
    def _build_bedrock_messages(
        self,
        prompt: str,
        context_messages: List[ConversationMessage]
    ) -> List[Dict[str, Any]]:
        """Build message list for Bedrock API.
        
        Args:
            prompt: Current user prompt
            context_messages: Conversation history
            
        Returns:
            List of messages formatted for Bedrock
        """
        messages = []
        
        # Add context messages
        for msg in context_messages:
            messages.append({
                'role': msg.role,
                'content': [{'type': 'text', 'text': msg.content}]
            })
        
        # Add current prompt
        messages.append({
            'role': 'user',
            'content': [{'type': 'text', 'text': prompt}]
        })
        
        return messages
    
    def _invoke_bedrock(
        self,
        messages: List[Dict[str, Any]],
        jwt_token: str,
        request_id: str
    ) -> Dict[str, Any]:
        """Invoke Bedrock model.
        
        Args:
            messages: Messages for the model
            jwt_token: JWT token for Gateway authentication
            request_id: Request ID for tracing
            
        Returns:
            Model response
        """
        # Get available tools from Gateway
        tools = self._get_tools_from_gateway(jwt_token, request_id)
        
        # Prepare request body for Claude 3 Sonnet
        request_body = {
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 2048,
            'messages': messages,
            'temperature': 0.7
        }
        
        # Add tools if available
        if tools:
            request_body['tools'] = tools
        
        # Invoke model
        response = self.bedrock_client.invoke_model(
            modelId=self.config.bedrock_model_id,
            body=json.dumps(request_body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        return response_body
    
    def _requires_tool_execution(self, bedrock_response: Dict[str, Any]) -> bool:
        """Check if Bedrock response indicates tool execution is needed.
        
        Args:
            bedrock_response: Response from Bedrock
            
        Returns:
            True if tool execution is required
        """
        # Check for tool_use content blocks
        content = bedrock_response.get('content', [])
        for block in content:
            if block.get('type') == 'tool_use':
                return True
        return False
    
    def _extract_tool_info(
        self,
        bedrock_response: Dict[str, Any]
    ) -> tuple[str, Dict[str, Any]]:
        """Extract tool name and parameters from Bedrock response.
        
        Args:
            bedrock_response: Response from Bedrock
            
        Returns:
            Tuple of (tool_name, parameters)
        """
        content = bedrock_response.get('content', [])
        for block in content:
            if block.get('type') == 'tool_use':
                return block.get('name', ''), block.get('input', {})
        
        return '', {}
    
    def _execute_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user_context: UserContext,
        jwt_token: str,
        request_id: str,
        tool_executions: List[ToolExecution]
    ) -> Dict[str, Any]:
        """Execute tool through Gateway.
        
        Args:
            tool_name: Name of tool to execute
            parameters: Tool parameters
            user_context: User identity
            jwt_token: JWT token
            request_id: Request ID
            tool_executions: List to append execution record to
            
        Returns:
            Tool execution result
            
        Raises:
            GatewayError: If tool execution fails
        """
        import time
        from datetime import datetime
        
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat()
        
        try:
            # Invoke tool through Gateway
            tool_response = self.gateway_client.invoke_tool(
                tool_name=tool_name,
                parameters=parameters,
                user_context=user_context,
                jwt_token=jwt_token,
                request_id=request_id
            )
            
            # Calculate execution time
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Record tool execution
            tool_execution = ToolExecution(
                tool_name=tool_name,
                timestamp=timestamp,
                status=tool_response.status,
                duration_ms=duration_ms
            )
            tool_executions.append(tool_execution)
            
            # Return tool result
            return tool_response.result
        
        except GatewayError as e:
            # Record failed execution
            duration_ms = int((time.time() - start_time) * 1000)
            tool_execution = ToolExecution(
                tool_name=tool_name,
                timestamp=timestamp,
                status='error',
                duration_ms=duration_ms
            )
            tool_executions.append(tool_execution)
            
            # Re-raise for error handling
            raise
    
    def _generate_response_with_tool_result(
        self,
        messages: List[Dict[str, Any]],
        tool_name: str,
        tool_result: Dict[str, Any],
        jwt_token: str,
        request_id: str
    ) -> str:
        """Generate final response incorporating tool result.
        
        Args:
            messages: Original messages
            tool_name: Tool that was executed
            tool_result: Tool execution result
            jwt_token: JWT token for Gateway authentication
            request_id: Request ID for tracing
            
        Returns:
            Generated response text
            
        Raises:
            BedrockError: If response generation fails
        """
        try:
            # Add tool result to messages
            tool_result_message = {
                'role': 'user',
                'content': [{
                    'type': 'tool_result',
                    'tool_use_id': tool_name,
                    'content': json.dumps(tool_result)
                }]
            }
            messages.append(tool_result_message)
            
            # Invoke Bedrock again to generate final response
            response = self._invoke_bedrock(messages, jwt_token, request_id)
            
            # Extract response text
            return self._extract_response_text(response)
        
        except Exception as e:
            # Fallback: generate simple response with tool result
            return self._format_tool_result_fallback(tool_name, tool_result)
    
    def _extract_response_text(self, bedrock_response: Dict[str, Any]) -> str:
        """Extract text response from Bedrock response.
        
        Args:
            bedrock_response: Response from Bedrock
            
        Returns:
            Response text
        """
        content = bedrock_response.get('content', [])
        for block in content:
            if block.get('type') == 'text':
                return block.get('text', '')
        
        return ''
    
    def _format_tool_result_fallback(
        self,
        tool_name: str,
        tool_result: Dict[str, Any]
    ) -> str:
        """Format tool result as fallback response.
        
        Used when Bedrock response generation fails.
        
        Args:
            tool_name: Tool that was executed
            tool_result: Tool execution result
            
        Returns:
            Formatted response text
        """
        # Format result in a user-friendly way
        if 'error' in tool_result:
            return f"I attempted to use {tool_name}, but encountered an error: {tool_result.get('error')}"
        
        # Format successful result
        result_str = json.dumps(tool_result, indent=2)
        return f"Here are the results from {tool_name}:\n\n{result_str}"
