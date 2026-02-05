"""Gateway Request Interceptor for User Context Propagation.

This Lambda function extracts user identity from JWT tokens and adds
user context to tool parameters before forwarding to Tool Lambda.

This enables Tool Lambda to perform user-specific operations and
maintain proper audit trails with user attribution.
"""

import json
import base64
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Decode JWT payload without verification.
    
    Gateway has already validated the JWT, so we just extract claims.
    
    Args:
        token: JWT token string (without 'Bearer ' prefix)
        
    Returns:
        Dictionary of JWT claims, or empty dict if decoding fails
    """
    try:
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            logger.warning("Invalid JWT format: expected 3 parts")
            return {}
        
        # Decode payload (add padding if needed)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        
        logger.debug(f"Successfully decoded JWT with claims: {list(claims.keys())}")
        return claims
    
    except Exception as e:
        logger.error(f"Failed to decode JWT: {str(e)}")
        return {}


def extract_user_context(claims: Dict[str, Any]) -> Dict[str, str]:
    """Extract user context from JWT claims.
    
    Args:
        claims: JWT claims dictionary
        
    Returns:
        User context dictionary with user_id, username, client_id
    """
    # Extract user_id (sub claim)
    user_id = claims.get('sub', 'unknown')
    
    # Extract username (try multiple claim names)
    username = (
        claims.get('username') or 
        claims.get('cognito:username') or 
        claims.get('email') or 
        'unknown'
    )
    
    # Extract client_id
    client_id = claims.get('client_id', 'unknown')
    
    return {
        'user_id': user_id,
        'username': username,
        'client_id': client_id
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Gateway request interceptor handler.
    
    Extracts user identity from JWT and adds to tool parameters.
    
    Event Structure:
        {
            "mcp": {
                "gatewayRequest": {
                    "headers": {"Authorization": "Bearer <token>"},
                    "body": {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "name": "tool_name",
                            "arguments": {...}
                        }
                    }
                }
            }
        }
    
    Returns:
        Transformed gateway request with user_context added to arguments
    """
    request_id = context.aws_request_id
    start_time = datetime.utcnow()
    
    try:
        logger.info(f"Interceptor invoked: {request_id}")
        
        # Extract gateway request
        mcp_data = event.get('mcp', {})
        gateway_request = mcp_data.get('gatewayRequest', {})
        
        if not gateway_request:
            logger.error("Missing gatewayRequest in event")
            return _return_original_request(gateway_request)
        
        headers = gateway_request.get('headers', {})
        body = gateway_request.get('body', {})
        
        # Extract JWT token from Authorization header
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        if not auth_header:
            logger.warning("No Authorization header found")
            return _return_original_request(gateway_request)
        
        # Remove 'Bearer ' prefix
        token = auth_header.replace('Bearer ', '').replace('bearer ', '').strip()
        if not token:
            logger.warning("Empty token after removing Bearer prefix")
            return _return_original_request(gateway_request)
        
        # Decode JWT to get user claims
        claims = decode_jwt_payload(token)
        if not claims:
            logger.warning("Failed to decode JWT claims")
            return _return_original_request(gateway_request)
        
        # Extract user context
        user_context = extract_user_context(claims)
        
        logger.info(
            f"Processing request for user: {user_context['username']} "
            f"(ID: {user_context['user_id']})"
        )
        
        # Add user context to tool parameters
        if "params" in body and "arguments" in body["params"]:
            # Add user_context to arguments
            body["params"]["arguments"]["user_context"] = user_context
            
            logger.info(
                f"Added user_context to tool parameters: "
                f"user_id={user_context['user_id']}, "
                f"username={user_context['username']}"
            )
        else:
            logger.warning(
                f"Unexpected body structure, cannot add user_context. "
                f"Body keys: {list(body.keys())}"
            )
        
        # Calculate processing time
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Return transformed request
        transformed_request = {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": {
                    "headers": {
                        "Authorization": auth_header,
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    "body": body
                }
            }
        }
        
        logger.info(
            f"Request transformation complete: {request_id} "
            f"(duration: {duration_ms}ms)"
        )
        
        return transformed_request
    
    except Exception as e:
        logger.error(
            f"Interceptor error: {str(e)}", 
            exc_info=True,
            extra={'request_id': request_id}
        )
        # Return original request on error to avoid breaking the flow
        return _return_original_request(gateway_request)


def _return_original_request(gateway_request: Dict[str, Any]) -> Dict[str, Any]:
    """Return original request unchanged on error.
    
    This ensures the system continues to work even if the interceptor fails.
    
    Args:
        gateway_request: Original gateway request
        
    Returns:
        Interceptor response with original request
    """
    logger.warning("Returning original request unchanged")
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": gateway_request
        }
    }
