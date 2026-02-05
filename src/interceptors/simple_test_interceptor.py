"""Simple Test Interceptor - Minimal implementation for debugging.

This interceptor just logs the incoming event and returns it unchanged.
Use this to verify that Gateway can successfully invoke the interceptor.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Minimal interceptor that logs and returns original request."""
    
    request_id = context.aws_request_id
    
    logger.info(f"=== INTERCEPTOR INVOKED === Request ID: {request_id}")
    logger.info(f"Event structure: {json.dumps(event, indent=2)}")
    
    try:
        # Extract the gateway request
        mcp_data = event.get('mcp', {})
        gateway_request = mcp_data.get('gatewayRequest', {})
        
        logger.info(f"Gateway request keys: {list(gateway_request.keys())}")
        
        # Return the original request unchanged
        response = {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": gateway_request
            }
        }
        
        logger.info(f"Returning response: {json.dumps(response, indent=2)}")
        logger.info("=== INTERCEPTOR COMPLETE ===")
        
        return response
        
    except Exception as e:
        logger.error(f"Error in interceptor: {str(e)}", exc_info=True)
        
        # Return original request on error
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": gateway_request if 'gateway_request' in locals() else {}
            }
        }
