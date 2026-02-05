"""Lambda handler for the Strands Framework Agent.

This module provides the AWS Lambda entry point for agent processing,
handling JWT validation, user context extraction, and response formatting.
"""

import json
import os
import logging
from typing import Dict, Any

from auth.jwt_validator import JWTValidator, JWTValidationError
from models.user_context import UserContext
from agent.agent_core import Agent, AgentConfig
from agent.exceptions import AgentError
from agent.error_handlers import handle_agent_error, format_error_response
from audit_logging.audit_logger import log_authentication_event, log_agent_processing
from tools.tool_registry import register_tool
from tools.s3_list_buckets_tool import S3ListBucketsTool

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Register built-in tools
register_tool(S3ListBucketsTool, metadata={
    'category': 'storage',
    'tags': ['aws', 's3', 'storage'],
    'version': '1.0.0',
    'description': 'Lists all S3 buckets accessible to the user'
})

# Initialize components from environment variables
COGNITO_JWKS_URL = os.environ.get('COGNITO_JWKS_URL')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
AGENTCORE_GATEWAY_URL = os.environ.get('AGENTCORE_GATEWAY_URL')
AGENTCORE_MEMORY_ID = os.environ.get('AGENTCORE_MEMORY_ID')
SESSION_TIMEOUT_MINUTES = int(os.environ.get('SESSION_TIMEOUT_MINUTES', '60'))
MAX_CONTEXT_MESSAGES = int(os.environ.get('MAX_CONTEXT_MESSAGES', '10'))
MAX_CONTEXT_TOKENS = int(os.environ.get('MAX_CONTEXT_TOKENS', '4000'))
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Initialize JWT validator (singleton)
jwt_validator = None
if COGNITO_JWKS_URL:
    jwt_validator = JWTValidator(COGNITO_JWKS_URL)

# Initialize Agent (singleton)
agent = None
if all([BEDROCK_MODEL_ID, AGENTCORE_GATEWAY_URL, AGENTCORE_MEMORY_ID]):
    agent_config = AgentConfig(
        bedrock_model_id=BEDROCK_MODEL_ID,
        agentcore_gateway_url=AGENTCORE_GATEWAY_URL,
        agentcore_memory_id=AGENTCORE_MEMORY_ID,
        session_timeout_minutes=SESSION_TIMEOUT_MINUTES,
        max_context_messages=MAX_CONTEXT_MESSAGES,
        max_context_tokens=MAX_CONTEXT_TOKENS,
        region_name=AWS_REGION
    )
    agent = Agent(agent_config)
    
    # Log available tools for debugging
    available_tools = agent.list_available_tools()
    logger.info(f"Agent initialized with {len(available_tools)} tools: {available_tools}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for agent processing.
    
    Expected event format:
    {
        "prompt": str,              # User's natural language input
        "jwt_token": str,           # JWT access token from Cognito
        "session_id": str | None    # Optional session ID for conversation continuity
    }
    
    Returns:
        Dictionary with agent response or error information
    
    Args:
        event: Lambda event containing prompt, jwt_token, and optional session_id
        context: Lambda context object
        
    Returns:
        Response dictionary with statusCode, body, and headers
    """
    request_id = context.aws_request_id if context else 'unknown'
    
    try:
        # Log incoming request (sanitized)
        logger.info(f"Processing agent request: {request_id}")
        
        # Validate required environment variables
        if not all([jwt_validator, agent]):
            return _error_response(
                status_code=500,
                error='configuration_error',
                message='Agent service not properly configured',
                request_id=request_id
            )
        
        # Parse event
        prompt, jwt_token, session_id = _parse_event(event)
        
        # Validate JWT and extract user context
        user_context = _validate_and_extract_user_context(jwt_token, request_id)
        
        # Log authentication success (already logged in _validate_and_extract_user_context)
        logger.info(
            f"Authentication successful for user: {user_context.user_id}",
            extra={
                'request_id': request_id,
                'user_id': user_context.user_id,
                'username': user_context.username
            }
        )
        
        # Log agent processing start
        import time
        start_time = time.time()
        
        # Process prompt with agent
        agent_response = agent.process_prompt(
            prompt=prompt,
            user_context=user_context,
            jwt_token=jwt_token,
            session_id=session_id,
            request_id=request_id
        )
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log successful agent processing
        log_agent_processing(
            operation='process_prompt',
            status='success',
            request_id=request_id,
            user_context=user_context,
            duration_ms=duration_ms,
            metadata={
                'session_id': agent_response.session_id,
                'tool_executions_count': len(agent_response.tool_executions),
                'prompt_length': len(prompt)
            }
        )
        
        # Log successful processing
        logger.info(
            f"Agent processing completed successfully",
            extra={
                'request_id': request_id,
                'user_id': user_context.user_id,
                'session_id': agent_response.session_id,
                'tool_executions': len(agent_response.tool_executions)
            }
        )
        
        # Return successful response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'X-Request-ID': request_id
            },
            'body': json.dumps(agent_response.to_dict())
        }
    
    except JWTValidationError as e:
        # Authentication error (already logged in _validate_and_extract_user_context)
        logger.warning(
            f"Authentication failed: {str(e)}",
            extra={'request_id': request_id}
        )
        return _error_response(
            status_code=401,
            error='authentication_failed',
            message='Authentication failed. Please check your credentials.',
            request_id=request_id
        )
    
    except AgentError as e:
        # Agent processing error - log with user context if available
        logger.error(
            f"Agent processing error: {str(e)}",
            extra={'request_id': request_id},
            exc_info=True  # Include full stack trace in DEBUG mode
        )
        
        # Try to get user context for logging
        try:
            user_context = _validate_and_extract_user_context(jwt_token, request_id)
            log_agent_processing(
                operation='process_prompt',
                status='failure',
                request_id=request_id,
                user_context=user_context,
                error_message=str(e),
                metadata={'error_type': type(e).__name__}
            )
        except:
            pass  # User context not available
        
        return _error_response(
            status_code=500,
            error='processing_failed',
            message=str(e),
            request_id=request_id
        )
    
    except ValueError as e:
        # Invalid input
        logger.warning(
            f"Invalid input: {str(e)}",
            extra={'request_id': request_id}
        )
        return _error_response(
            status_code=400,
            error='invalid_input',
            message=str(e),
            request_id=request_id
        )
    
    except Exception as e:
        # Unexpected error
        logger.error(
            f"Unexpected error: {str(e)}",
            extra={'request_id': request_id},
            exc_info=True
        )
        return _error_response(
            status_code=500,
            error='internal_error',
            message='An unexpected error occurred. Please try again.',
            request_id=request_id
        )


def _parse_event(event: Dict[str, Any]) -> tuple[str, str, str | None]:
    """Parse and validate Lambda event.
    
    Args:
        event: Lambda event dictionary
        
    Returns:
        Tuple of (prompt, jwt_token, session_id)
        
    Raises:
        ValueError: If required fields are missing or invalid
    """
    # Extract prompt
    prompt = event.get('prompt')
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Missing or invalid 'prompt' field")
    
    # Extract JWT token
    jwt_token = event.get('jwt_token')
    if not jwt_token or not isinstance(jwt_token, str):
        raise ValueError("Missing or invalid 'jwt_token' field")
    
    # Extract optional session_id
    session_id = event.get('session_id')
    if session_id is not None and not isinstance(session_id, str):
        raise ValueError("Invalid 'session_id' field - must be string or null")
    
    return prompt, jwt_token, session_id


def _validate_and_extract_user_context(
    jwt_token: str,
    request_id: str
) -> UserContext:
    """Validate JWT token and extract user context.
    
    Args:
        jwt_token: JWT access token
        request_id: Request ID for logging
        
    Returns:
        UserContext with user identity
        
    Raises:
        JWTValidationError: If token validation fails
    """
    try:
        # Validate token
        claims = jwt_validator.validate_token(jwt_token)
        
        # Extract user context
        user_context = UserContext.from_jwt_claims(claims)
        
        # Log successful authentication
        log_authentication_event(
            success=True,
            request_id=request_id,
            user_context=user_context,
            metadata={'claims_validated': True}
        )
        
        return user_context
    
    except JWTValidationError as e:
        # Log failed authentication
        log_authentication_event(
            success=False,
            request_id=request_id,
            error_message=str(e),
            metadata={'error_type': type(e).__name__}
        )
        raise


def _error_response(
    status_code: int,
    error: str,
    message: str,
    request_id: str
) -> Dict[str, Any]:
    """Format error response.
    
    Args:
        status_code: HTTP status code
        error: Error code
        message: Error message
        request_id: Request ID
        
    Returns:
        Lambda response dictionary
    """
    from datetime import datetime
    
    error_body = {
        'error': error,
        'message': message,
        'request_id': request_id,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'X-Request-ID': request_id
        },
        'body': json.dumps(error_body)
    }
