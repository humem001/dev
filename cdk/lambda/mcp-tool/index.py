import json
import boto3
from typing import Dict, Any, List

def handler(event, context):
    """
    MCP Tool Lambda handler implementing Model Context Protocol
    """
    try:
        print(f"Received event: {json.dumps(event)}")
        
        # Handle different event formats from AgentCore Gateway
        if not event or event == {}:
            # Gateway sends empty event for tools/call, execute the default tool
            # Since we only have one tool configured in the Gateway target, execute list_s3_buckets
            return execute_list_s3_buckets({}, 0)
        
        # Check if this is a direct MCP request
        if 'method' in event:
            method = event.get('method')
            params = event.get('params', {})
            request_id = event.get('id', 0)
        else:
            # Gateway-transformed request, execute the default tool
            return execute_list_s3_buckets({}, 0)
        
        # Extract user information from JWT claims (if available)
        user_info = extract_user_info(event)
        
        if method == 'tools/list':
            return handle_tools_list(request_id)
        elif method == 'tools/call':
            return handle_tools_call(params, user_info, request_id)
        else:
            return mcp_error("METHOD_NOT_FOUND", f"Unknown method: {method}", request_id)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return mcp_error("INTERNAL_ERROR", str(e), event.get('id', 0))

def extract_user_info(event):
    """Extract user information from JWT claims in the event"""
    user_info = {
        'user_id': None,
        'username': None,
        'email': None
    }
    
    # Check for JWT claims in various possible locations
    # AgentCore Gateway may pass JWT claims in different ways
    
    # Option 1: In requestContext (API Gateway style)
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})
    
    if 'claims' in authorizer:
        claims = authorizer['claims']
        user_info['user_id'] = claims.get('sub')
        user_info['username'] = claims.get('cognito:username')
        user_info['email'] = claims.get('email')
    
    # Option 2: Direct in event (if Gateway passes claims directly)
    if 'claims' in event:
        claims = event['claims']
        user_info['user_id'] = claims.get('sub')
        user_info['username'] = claims.get('cognito:username')
        user_info['email'] = claims.get('email')
    
    # Option 3: In headers (if passed as headers)
    headers = event.get('headers', {})
    # Check both lowercase and uppercase header names
    user_info['user_id'] = user_info['user_id'] or headers.get('x-user-sub') or headers.get('X-User-Sub')
    user_info['username'] = user_info['username'] or headers.get('x-user-id') or headers.get('X-User-ID')
    user_info['email'] = user_info['email'] or headers.get('x-user-email') or headers.get('X-User-Email')
    
    print(f"Extracted user info: {user_info}")
    print(f"Available headers: {list(headers.keys()) if headers else 'None'}")
    return user_info

def handle_tools_list(request_id):
    """Handle tools/list request - return available tools"""
    tools = [
        {
            "name": "list_s3_buckets",
            "description": "List all S3 buckets in the account",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    ]
    
    return mcp_success({"tools": tools}, request_id)

def handle_tools_call(params, user_info, request_id):
    """Handle tools/call request - execute a specific tool"""
    tool_name = params.get('name')
    arguments = params.get('arguments', {})
    
    # Extract user context from metadata if available
    meta = params.get('meta', {})
    user_context = meta.get('user_context', {})
    if user_context:
        user_info.update({
            'user_id': user_context.get('user_id', user_info.get('user_id')),
            'username': user_context.get('username', user_info.get('username')),
            'email': user_context.get('email', user_info.get('email')),
            'client_id': user_context.get('client_id', user_info.get('client_id'))
        })
        print(f"Updated user info from user_context: {user_info}")
    
    if tool_name == 'list_s3_buckets':
        return execute_list_s3_buckets(user_info, request_id)
    else:
        return mcp_error("INVALID_PARAMS", f"Unknown tool: {tool_name}", request_id)

def execute_list_s3_buckets(user_info, request_id):
    """Execute list_s3_buckets tool"""
    try:
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()
        
        buckets = []
        for bucket in response['Buckets']:
            buckets.append({
                'name': bucket['Name'],
                'creation_date': bucket['CreationDate'].isoformat()
            })
        
        # Include user context in response if available
        user_context = ""
        if user_info and user_info.get('username'):
            user_context = f" (requested by user: {user_info['username']})"
        elif user_info and user_info.get('user_id'):
            user_context = f" (requested by user ID: {user_info['user_id']})"
        
        return mcp_success({
            "content": [
                {
                    "type": "text",
                    "text": f"Found {len(buckets)} S3 buckets{user_context}:\n" + 
                           "\n".join([f"- {b['name']} (created: {b['creation_date']})" for b in buckets])
                }
            ]
        }, request_id)
        
    except Exception as e:
        return mcp_error("INTERNAL_ERROR", f"Failed to list S3 buckets: {str(e)}", request_id)

def mcp_success(result, request_id):
    """Return MCP success response"""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result
    }

def mcp_error(code, message, request_id):
    """Return MCP error response"""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message
        }
    }