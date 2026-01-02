import json
import os
import boto3
import urllib.request
import urllib.parse
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit

logger = Logger()
tracer = Tracer()
metrics = Metrics()

# Configuration from environment variables
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
AWS_REGION = os.environ.get('AWS_REGION', 'eu-west-2')
GATEWAY_URL = os.environ.get('GATEWAY_URL', 'https://strands-gateway-uwudpu9nzj.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', '1024'))
USER_POOL_ID = os.environ.get('USER_POOL_ID')
CLIENT_ID = os.environ.get('CLIENT_ID')

bedrock = boto3.client('bedrock-runtime', region_name=AWS_REGION)

@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event, context):
    """Strands Agent Lambda Handler with PowerTools"""
    
    user_prompt = event.get('prompt', 'Hello')
    username = event.get('username')  # Optional user credentials
    password = event.get('password')  # Optional user credentials
    
    logger.info("Processing user request", extra={
        "prompt": user_prompt, 
        "has_user_credentials": bool(username and password)
    })
    metrics.add_metric(name="RequestReceived", unit=MetricUnit.Count, value=1)
    
    try:
        # Get available tools
        tools = get_tools()
        
        # Call Bedrock with tools
        response = call_bedrock_with_tools(user_prompt, tools)
        
        # Process response with user context
        result = process_bedrock_response(response, username, password)
        
        metrics.add_metric(name="RequestSuccess", unit=MetricUnit.Count, value=1)
        logger.info("Request processed successfully", extra={"result_length": len(str(result))})
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': result,
                'prompt': user_prompt
            })
        }
        
    except Exception as e:
        metrics.add_metric(name="RequestError", unit=MetricUnit.Count, value=1)
        logger.error("Request processing failed", extra={"error": str(e)})
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

@tracer.capture_method
def get_tools():
    """Get available tools from Gateway"""
    logger.debug("Loading available tools from Gateway")
    return [
        {
            "name": "list_s3_buckets",
            "description": "List all S3 buckets in the account",
            "input_schema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    ]

@tracer.capture_method
def call_bedrock_with_tools(prompt, tools):
    """Call Bedrock LLM with available tools"""
    logger.debug("Calling Bedrock", extra={"model_id": BEDROCK_MODEL_ID, "tools_count": len(tools)})
    
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
        "tools": tools,
        "tool_choice": {"type": "auto"}
    }
    
    response = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=json.dumps(body)
    )
    
    return json.loads(response['body'].read())

@tracer.capture_method
def process_bedrock_response(response, username=None, password=None):
    """Process Bedrock response with user context"""
    content = response.get('content', [])
    logger.info("Full Bedrock response", extra={"response": response})
    logger.debug("Processing Bedrock response", extra={"content_items": len(content)})
    
    text_content = ""
    tool_results = []
    
    for item in content:
        logger.info("Processing content item", extra={"item": item})
        if item.get('type') == 'tool_use':
            # Execute tool via Gateway with user context
            tool_result = execute_tool_via_gateway(item['name'], item.get('input', {}), username, password)
            metrics.add_metric(name="ToolExecuted", unit=MetricUnit.Count, value=1)
            tool_results.append(f"Tool {item['name']} executed: {tool_result}")
        elif item.get('type') == 'text':
            text_content = item['text']
    
    # Return tool results if any, otherwise return text content
    if tool_results:
        return f"{text_content}\n\n" + "\n".join(tool_results)
    elif text_content:
        return text_content
    
    return "No response content"

@tracer.capture_method
def get_cognito_credentials():
    """Get Cognito credentials from Secrets Manager"""
    import boto3
    import json
    
    secret_arn = os.environ.get('COGNITO_CREDENTIALS_SECRET_ARN')
    if not secret_arn:
        raise ValueError("COGNITO_CREDENTIALS_SECRET_ARN environment variable not set")
    
    secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    try:
        response = secrets_client.get_secret_value(SecretId=secret_arn)
        secret = json.loads(response['SecretString'])
        return secret['username'], secret['password']
    except Exception as e:
        logger.error("Failed to retrieve Cognito credentials from Secrets Manager", extra={"error": str(e)})
        raise

@tracer.capture_method
def get_access_token(username=None, password=None):
    """Get Access Token for Gateway authentication using user credentials or client credentials"""
    import urllib.request
    import urllib.parse
    import json
    
    if username and password:
        # User authentication using Cognito IDP (not OAuth endpoint)
        return get_user_access_token(username, password)
    else:
        # Client credentials using OAuth endpoint
        return get_client_credentials_token()

@tracer.capture_method
def get_user_access_token(username, password):
    """Authenticate user using Cognito IDP"""
    import boto3
    import hmac
    import hashlib
    import base64
    
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    
    # Get client secret for SECRET_HASH
    secret_arn = os.environ.get('COGNITO_CREDENTIALS_SECRET_ARN')
    if not secret_arn:
        raise ValueError("COGNITO_CREDENTIALS_SECRET_ARN environment variable not set")
    
    secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    try:
        response = secrets_client.get_secret_value(SecretId=secret_arn)
        secret = json.loads(response['SecretString'])
        client_secret = secret['client_secret']
    except Exception as e:
        logger.error("Failed to retrieve client secret", extra={"error": str(e)})
        raise
    
    # Generate SECRET_HASH
    message = username + CLIENT_ID
    secret_hash = base64.b64encode(
        hmac.new(client_secret.encode(), message.encode(), hashlib.sha256).digest()
    ).decode()
    
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        
        access_token = response['AuthenticationResult']['AccessToken']
        logger.info("User authentication successful", extra={"username": username})
        return access_token
        
    except Exception as e:
        logger.error("User authentication failed", extra={"username": username, "error": str(e)})
        raise

@tracer.capture_method  
def get_client_credentials_token():
    """Get client credentials token using OAuth endpoint"""
    import urllib.request
    import urllib.parse
    import json
    
    # Get client secret from Secrets Manager
    secret_arn = os.environ.get('COGNITO_CREDENTIALS_SECRET_ARN')
    if not secret_arn:
        raise ValueError("COGNITO_CREDENTIALS_SECRET_ARN environment variable not set")
    
    secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    try:
        response = secrets_client.get_secret_value(SecretId=secret_arn)
        secret = json.loads(response['SecretString'])
        client_secret = secret['client_secret']
    except Exception as e:
        logger.error("Failed to retrieve client secret from Secrets Manager", extra={"error": str(e)})
        raise
    
    # OAuth client credentials flow
    token_url = f"https://agentcore-f5dcf6a4.auth.{AWS_REGION}.amazoncognito.com/oauth2/token"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': client_secret,
        'scope': 'strands-gateway-prod/invoke'
    }
    
    data_encoded = urllib.parse.urlencode(data).encode('utf-8')
    
    req = urllib.request.Request(
        token_url,
        data=data_encoded,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    with urllib.request.urlopen(req, timeout=10) as response:
        result = json.loads(response.read().decode('utf-8'))
    
    logger.info("Client credentials authentication successful")
    return result['access_token']

@tracer.capture_method
def get_user_info_from_token(access_token):
    """Extract user information from Access Token"""
    import base64
    import json
    
    try:
        # Decode JWT payload (without verification for user info extraction)
        parts = access_token.split('.')
        if len(parts) != 3:
            return None
            
        # Add padding if needed
        payload = parts[1]
        payload += '=' * (4 - len(payload) % 4)
        
        # Decode base64
        decoded = base64.b64decode(payload)
        claims = json.loads(decoded.decode('utf-8'))
        
        # Extract user information
        user_info = {
            'user_id': claims.get('sub'),
            'username': claims.get('username'),
            'email': claims.get('email'),
            'client_id': claims.get('client_id')
        }
        
        logger.info("Extracted user info from token", extra={"user_info": {k: v for k, v in user_info.items() if k != 'user_id'}})
        return user_info
        
    except Exception as e:
        logger.error("Failed to extract user info from token", extra={"error": str(e)})
        return None

@tracer.capture_method
def execute_tool_via_gateway(tool_name, arguments, username=None, password=None):
    """Execute tool via AgentCore Gateway with user context"""
    logger.info("Executing tool via Gateway", extra={"tool_name": tool_name, "arguments": arguments})
    
    # Map tool names to Gateway tool names
    tool_name_mapping = {
        "list_s3_buckets": "TestGatewayTarget___list_s3_buckets"
    }
    
    gateway_tool_name = tool_name_mapping.get(tool_name, tool_name)
    logger.info("Mapped tool name", extra={"original": tool_name, "gateway": gateway_tool_name})
    
    try:
        # Get access token (user or client credentials)
        access_token = get_access_token(username, password)
        
        # Extract user info from token
        user_info = get_user_info_from_token(access_token)
        
        # Prepare MCP request with user context in metadata
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": gateway_tool_name,
                "arguments": arguments
            }
        }
        
        # Add user context to metadata if available
        if user_info:
            mcp_request["meta"] = {
                "user_context": user_info
            }
        
        logger.info("Prepared MCP request with user context", extra={"tool_name": tool_name, "has_user_context": user_info is not None})
        
        # Call Gateway with user context headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Add user context headers if available
        if user_info:
            headers["X-User-ID"] = str(user_info.get('user_id') or '')
            headers["X-User-Email"] = str(user_info.get('email') or '')
            headers["X-User-Name"] = str(user_info.get('username') or '')
            logger.info("Added user context headers", extra={"user_id": user_info.get('user_id')})
        
        data = json.dumps(mcp_request).encode('utf-8')
        req = urllib.request.Request(GATEWAY_URL, data=data, headers=headers)
        
        logger.info("Sending request to Gateway", extra={
            "url": GATEWAY_URL,
            "headers": {k: v for k, v in headers.items() if k != 'Authorization'},
            "request": mcp_request
        })
        
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
        logger.info("Gateway response received", extra={"result": result})
        
        if 'error' in result:
            return f"Gateway error: {result['error']['message']}"
        
        return result.get('result', {}).get('content', [{}])[0].get('text', 'No result')
        
    except Exception as e:
        logger.error("Gateway tool execution failed", extra={"tool_name": tool_name, "error": str(e)})
        return f"Gateway execution error: {str(e)}"