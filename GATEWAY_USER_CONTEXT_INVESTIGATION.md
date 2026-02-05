# AgentCore Gateway User Context Investigation

## Investigation Date: 2026-01-27

## Question
Can AgentCore Gateway forward user context (user_id, username) from JWT tokens to Lambda Tool targets?

## Current Situation

### What Works ✅
- **Agent Lambda**: Correctly extracts user_context from Cognito JWT
- **Agent Lambda Response**: Includes user_context in final response to user
- **Agent Logs**: Show correct user attribution (`testuser@example.com`)

### What Doesn't Work ❌
- **Tool Lambda**: Receives `user_id: "unknown"` 
- **Root Cause**: AgentCore Gateway strips user_context from arguments before forwarding to Lambda

## Investigation Findings

### 1. Gateway Documentation Review

I reviewed the complete AgentCore Gateway documentation including:
- Gateway Quickstart Guide
- Gateway Integration Examples
- Lambda Target Configuration
- Authentication & Authorization
- Boto3 API Reference

### 2. Key Findings

**Gateway Does NOT Support User Context Forwarding to Lambda Targets**

The documentation shows:

1. **Lambda Target Configuration** (`create_gateway_target`):
   ```python
   {
       "gatewayIdentifier": "string",
       "name": "string",
       "targetConfiguration": {
           "mcp": {
               "lambda": {
                   "lambdaArn": "string",
                   "toolSchema": {...}
               }
           }
       },
       "credentialProviderConfigurations": [...]
   }
   ```
   - No option for custom headers
   - No option for JWT claim forwarding
   - No option for user context propagation

2. **Lambda Event Structure**:
   - Gateway invokes Lambda with tool parameters only
   - No user identity information in event
   - No custom context or headers supported

3. **Authentication Design**:
   - Gateway validates JWT at ingress (centralized auth)
   - Gateway uses its own IAM role for Lambda invocation
   - Original user identity is NOT forwarded to targets

### 3. Lambda Context Investigation

The Lambda `context` object provided by Gateway does NOT include:
- User identity from JWT
- Custom claims from JWT
- Original request headers
- User context information

The only way to identify the tool is through:
```python
tool_name = context.client_context.custom.get('bedrockAgentCoreToolName', 'unknown')
```

## Why Gateway Strips User Context

This is **by design** for security and architectural reasons:

1. **Security Boundary**: Gateway acts as a security perimeter
   - Validates authentication at the edge
   - Prevents downstream services from needing JWT validation
   - Reduces attack surface

2. **Separation of Concerns**:
   - Gateway handles authentication/authorization
   - Tools focus on business logic only
   - Cleaner architecture

3. **IAM-Based Invocation**:
   - Gateway uses its own IAM role to invoke Lambda
   - Lambda sees Gateway as the invoker, not the end user
   - Standard AWS Lambda invocation model

## 🎉 BREAKTHROUGH: Gateway Interceptors (NEW FEATURE)

### AWS Blog Post Discovery
**Source**: [Apply fine-grained access control with Bedrock AgentCore Gateway interceptors](https://aws.amazon.com/blogs/machine-learning/apply-fine-grained-access-control-with-bedrock-agentcore-gateway-interceptors/)

**Published**: Recent (2025)

### What Are Gateway Interceptors?

Gateway interceptors are Lambda functions that process requests and responses at two critical points:

1. **Request Interceptor**: Processes incoming requests BEFORE they reach target tools
2. **Response Interceptor**: Processes outgoing responses BEFORE they return to the agent

### Key Capabilities for User Context

**Request Interceptor Can**:
- ✅ Extract JWT claims (including user_id, username, custom claims)
- ✅ Add custom headers to downstream requests
- ✅ Transform request payloads with user context
- ✅ Pass authorization tokens to Lambda targets
- ✅ Implement fine-grained access control per user
- ✅ Add user identity to tool parameters

**Response Interceptor Can**:
- ✅ Filter tools based on user permissions
- ✅ Enrich responses with user context
- ✅ Implement dynamic tool discovery per user
- ✅ Add audit information

### How It Solves Your Problem

**Request Interceptor Example**:
```python
def lambda_handler(event, context):
    # Extract JWT from incoming request
    gateway_request = event['mcp']['gatewayRequest']
    headers = gateway_request.get('headers', {})
    auth_header = headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    
    # Decode JWT to get user claims
    claims = decode_jwt_payload(token)
    user_id = claims.get('sub')  # User ID from JWT
    username = claims.get('username')
    
    # Get the request body
    body = gateway_request.get('body', {})
    
    # ADD USER CONTEXT TO TOOL PARAMETERS
    if "arguments" in body["params"]:
        body["params"]["arguments"]["user_id"] = user_id
        body["params"]["arguments"]["username"] = username
        body["params"]["arguments"]["authorization"] = auth_header
    
    # Return transformed request
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "headers": {
                    "Authorization": auth_header,
                    "Content-Type": "application/json"
                },
                "body": body
            }
        }
    }
```

**What This Achieves**:
- ✅ Tool Lambda receives user_id and username in parameters
- ✅ No changes needed to Gateway configuration
- ✅ No changes needed to Tool Lambda (it already expects user_context)
- ✅ Maintains security (JWT validated at Gateway)
- ✅ Implements "act-on-behalf" pattern (recommended by AWS)

### Implementation Steps

1. **Create Request Interceptor Lambda**:
   ```python
   # Lambda that extracts JWT claims and adds to tool parameters
   def request_interceptor(event, context):
       # Extract user context from JWT
       # Add to tool parameters
       # Return transformed request
   ```

2. **Attach to Gateway**:
   ```bash
   aws bedrock-agentcore-control update-gateway \
     --gateway-identifier <gateway-id> \
     --request-interceptor-arn <lambda-arn>
   ```

3. **Tool Lambda Receives User Context**:
   ```python
   # Tool Lambda now gets user_context in parameters
   def handle_gateway_request(event, context, request_id, start_time):
       parameters = event.get('arguments', {})
       user_id = parameters.get('user_id', 'unknown')  # ✅ NOW AVAILABLE!
       username = parameters.get('username', 'unknown')  # ✅ NOW AVAILABLE!
   ```

## Possible Solutions (UPDATED)

### Option 1: Gateway Request Interceptor ✅ RECOMMENDED (NEW)
**Status**: Newly available feature

**Implementation**:
- Create Lambda function to extract JWT claims
- Add user_id and username to tool parameters
- Attach as request interceptor to Gateway

**What You Get**:
- ✅ User context in Tool Lambda
- ✅ Tool-level user-specific operations
- ✅ User attribution in tool logs
- ✅ Maintains all Gateway benefits
- ✅ Follows AWS best practices ("act-on-behalf")
- ✅ No changes to existing code structure

**Benefits**:
- Solves the original problem completely
- Recommended by AWS for identity propagation
- Maintains security boundaries
- Enables fine-grained access control
- Supports multi-tenant architectures

**Use Cases Enabled**:
- User-specific S3 bucket operations
- User-specific resource tagging
- User-based audit logging in tools
- Per-user access control in tools
- Multi-tenant tool isolation

### Option 2: Accept Current Design ✅ ALTERNATIVE
**Status**: Already implemented

**What We Have**:
- User context available at Agent Lambda level
- Full audit trail in Agent logs
- User attribution in Agent response
- Tool execution results returned to Agent

**Benefits**:
- Follows AWS best practices
- Maintains security boundaries
- Simplest implementation
- No additional complexity

**Use Cases Supported**:
- User-specific responses from Agent
- Audit logging at Agent level
- User attribution in final response
- Access control at Agent level

### Option 2: Pass User Context in Tool Parameters ❌ NOT SUPPORTED
**Status**: Attempted but Gateway strips it

**What We Tried**:
```python
arguments_with_context = {
    **parameters,
    'user_context': {
        'user_id': user_context.user_id,
        'username': user_context.username,
        'client_id': user_context.client_id
    }
}
```

**Result**: Gateway removes `user_context` before forwarding to Lambda

**Why It Doesn't Work**:
- Gateway sanitizes arguments
- Only tool-specific parameters are forwarded
- User context is not part of tool schema

### Option 3: Custom Lambda Target with User Context ❌ NOT POSSIBLE
**Status**: Not supported by Gateway API

**What Would Be Needed**:
- Custom event transformation in Gateway
- JWT claim extraction and forwarding
- Custom headers or context fields

**Why It's Not Available**:
- No API support in Gateway
- Not in Lambda target configuration schema
- Not in Gateway documentation

### Option 4: Direct Lambda Invocation (Bypass Gateway) ⚠️ LOSES MCP BENEFITS
**Status**: Possible but not recommended

**Implementation**:
```python
# Agent Lambda directly invokes Tool Lambda
lambda_client.invoke(
    FunctionName='tool-lambda',
    Payload=json.dumps({
        'tool_name': 'list_s3_buckets',
        'parameters': {...},
        'user_context': user_context.to_dict()
    })
)
```

**Drawbacks**:
- Loses MCP protocol benefits
- Loses Gateway tool discovery
- Loses Gateway authentication
- Loses Gateway semantic search
- More complex error handling
- Manual tool registration needed

### Option 5: Agent-Level User Context Enrichment ✅ ALTERNATIVE APPROACH
**Status**: Feasible if tool-level attribution is required

**Implementation**:
1. Tool Lambda returns results without user context
2. Agent Lambda enriches results with user context
3. Agent Lambda logs tool execution with user attribution
4. Final response includes user context

**Example**:
```python
# In Agent Lambda
tool_result = gateway_client.invoke_tool(
    tool_name='list_s3_buckets',
    parameters={},
    user_context=user_context,
    jwt_token=jwt_token,
    request_id=request_id
)

# Enrich result with user context
enriched_result = {
    **tool_result.result,
    'user_id': user_context.user_id,
    'username': user_context.username,
    'executed_at': datetime.utcnow().isoformat()
}

# Log with user attribution
log_tool_execution(
    tool_name='list_s3_buckets',
    user_context=user_context,
    result=enriched_result
)
```

**Benefits**:
- Maintains Gateway benefits
- Provides user attribution
- Centralized logging
- Simple implementation

## Recommendations (UPDATED)

### For Current System: Implement Gateway Request Interceptor ✅ RECOMMENDED

**Recommendation**: Add Gateway request interceptor to forward user context

**Rationale**:
1. Newly available AWS feature (2025)
2. Solves user context forwarding completely
3. Follows AWS best practices ("act-on-behalf" pattern)
4. No changes to existing code structure
5. Maintains all security boundaries
6. Enables tool-level user operations

**What You Get**:
- ✅ User authentication via Cognito
- ✅ User context in Agent Lambda
- ✅ User context in Tool Lambda (NEW!)
- ✅ User attribution in Agent response
- ✅ User attribution in tool logs (NEW!)
- ✅ Audit logging with user identity at all levels
- ✅ MCP protocol benefits
- ✅ Gateway tool discovery
- ✅ Gateway semantic search
- ✅ Tool-level user-specific operations (NEW!)
- ✅ Fine-grained access control (NEW!)

**What You Need to Do**:
1. Create request interceptor Lambda function
2. Extract JWT claims (user_id, username)
3. Add to tool parameters
4. Attach to Gateway via AWS CLI/Console

### For User-Specific Tool Operations: Alternative Approaches

If you need user-specific operations in tools (e.g., user-specific S3 buckets, user-specific tagging):

**Approach 1: Agent-Level Filtering**
```python
# Agent Lambda gets all buckets
all_buckets = tool.list_s3_buckets()

# Agent filters based on user
user_buckets = [
    b for b in all_buckets 
    if user_has_access(user_context.user_id, b)
]
```

**Approach 2: Pass User ID as Tool Parameter**
```python
# Define tool with user_id parameter
tool_schema = {
    "name": "list_user_s3_buckets",
    "parameters": {
        "user_id": {"type": "string"}
    }
}

# Agent passes user_id explicitly
result = gateway_client.invoke_tool(
    tool_name='list_user_s3_buckets',
    parameters={'user_id': user_context.user_id}
)
```

**Approach 3: Separate Tool Lambda per User Context Need**
- Create dedicated tools that require user context
- Agent Lambda handles user-specific logic
- Tool Lambda handles generic operations

## Conclusion (UPDATED)

**AgentCore Gateway DOES support forwarding user context to Lambda targets via Gateway Interceptors!**

This is a newly released feature (2025) that solves the user context propagation problem completely.

### Recommended Implementation Path

**Phase 1: Immediate (Current System Works)**
- ✅ Keep current implementation
- ✅ User context at Agent level
- ✅ System is fully operational

**Phase 2: Enhancement (Add Gateway Interceptor)**
- 🎯 Create request interceptor Lambda
- 🎯 Extract JWT claims (user_id, username)
- 🎯 Add to tool parameters
- 🎯 Attach to Gateway
- 🎯 Tool Lambda receives user context

**Benefits of Phase 2**:
- Tool-level user-specific operations
- User attribution in tool logs
- Fine-grained access control per user
- Multi-tenant support
- Follows AWS best practices

### Implementation Guide

**Step 1: Create Request Interceptor Lambda**

Create `src/interceptors/gateway_request_interceptor.py`:
```python
"""Gateway Request Interceptor for User Context Propagation.

This Lambda function extracts user identity from JWT tokens and adds
user context to tool parameters before forwarding to Tool Lambda.
"""

import json
import base64
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def decode_jwt_payload(token):
    """Decode JWT payload without verification (Gateway already validated)."""
    try:
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        
        # Decode payload (add padding if needed)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        logger.error(f"Failed to decode JWT: {str(e)}")
        return {}

def lambda_handler(event, context):
    """Gateway request interceptor handler.
    
    Extracts user identity from JWT and adds to tool parameters.
    """
    try:
        # Extract gateway request
        gateway_request = event.get('mcp', {}).get('gatewayRequest', {})
        headers = gateway_request.get('headers', {})
        body = gateway_request.get('body', {})
        
        # Extract JWT token
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        token = auth_header.replace('Bearer ', '').replace('bearer ', '')
        
        # Decode JWT to get user claims
        claims = decode_jwt_payload(token)
        user_id = claims.get('sub', 'unknown')
        username = claims.get('username', claims.get('cognito:username', 'unknown'))
        client_id = claims.get('client_id', 'unknown')
        
        logger.info(f"Interceptor processing request for user: {username}")
        
        # Add user context to tool parameters
        if "params" in body and "arguments" in body["params"]:
            body["params"]["arguments"]["user_context"] = {
                "user_id": user_id,
                "username": username,
                "client_id": client_id
            }
        
        # Return transformed request
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": {
                    "headers": {
                        "Authorization": auth_header,
                        "Content-Type": "application/json"
                    },
                    "body": body
                }
            }
        }
    
    except Exception as e:
        logger.error(f"Interceptor error: {str(e)}")
        # Return original request on error
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": gateway_request
            }
        }
```

**Step 2: Create CloudFormation Template**

Create `cloudformation/gateway-interceptor.yaml`:
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Gateway Request Interceptor for User Context Propagation'

Resources:
  InterceptorLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${AWS::StackName}-gateway-interceptor'
      RetentionInDays: 30

  InterceptorExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'

  InterceptorFunction:
    Type: AWS::Lambda::Function
    DependsOn: InterceptorLogGroup
    Properties:
      FunctionName: !Sub '${AWS::StackName}-gateway-interceptor'
      Runtime: python3.12
      Handler: gateway_request_interceptor.lambda_handler
      Role: !GetAtt InterceptorExecutionRole.Arn
      Code:
        S3Bucket: !Ref LambdaCodeBucket
        S3Key: 'gateway-interceptor.zip'
      Timeout: 10
      MemorySize: 128
      Environment:
        Variables:
          LOG_LEVEL: 'INFO'

Outputs:
  InterceptorFunctionArn:
    Description: 'Gateway Interceptor Lambda ARN'
    Value: !GetAtt InterceptorFunction.Arn
    Export:
      Name: !Sub '${AWS::StackName}-InterceptorArn'
```

**Step 3: Attach Interceptor to Gateway**

```bash
# Get Gateway ID
GATEWAY_ID="ai-agent-mcp-gateway-dev-hlgqg8fahq"
INTERCEPTOR_ARN="arn:aws:lambda:eu-west-2:581571671018:function:gateway-interceptor"

# Update Gateway with request interceptor
aws bedrock-agentcore-control update-gateway \
  --gateway-identifier ${GATEWAY_ID} \
  --request-interceptor-lambda-arn ${INTERCEPTOR_ARN} \
  --region eu-west-2
```

**Step 4: Verify Tool Lambda Receives User Context**

Tool Lambda will now receive user_context in parameters:
```python
def handle_gateway_request(event, context, request_id, start_time):
    parameters = event.get('arguments', {})
    
    # Extract user_context (now available!)
    user_context_dict = parameters.get('user_context', {})
    user_id = user_context_dict.get('user_id', 'unknown')
    username = user_context_dict.get('username', 'unknown')
    
    # Use for user-specific operations
    logger.info(f"Tool invoked by user: {username} ({user_id})")
```

### Additional Resources

- **AWS Blog Post**: [Apply fine-grained access control with Bedrock AgentCore Gateway interceptors](https://aws.amazon.com/blogs/machine-learning/apply-fine-grained-access-control-with-bedrock-agentcore-gateway-interceptors/)
- **Code Samples**: [GitHub - AgentCore Gateway Interceptors](https://github.com/aws-samples/amazon-bedrock-agentcore-samples)
- **Documentation**: [Fine-grained access control for Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html)

## Files Referenced

- `src/tools/lambda_handler.py` - Tool Lambda event handling
- `src/gateway/gateway_client.py` - Gateway MCP client
- `cloudformation/tool-lambda.yaml` - Lambda configuration
- `USER_CONTEXT_PROPAGATION_FIX.md` - Current implementation
- AgentCore Gateway Documentation (official AWS docs)

## Next Steps

**If current design is acceptable**:
- ✅ No changes needed
- ✅ System is working as designed
- ✅ User context available where it matters

**If tool-level user context is required**:
1. Implement Agent-level filtering/enrichment
2. Pass user_id as explicit tool parameter
3. Consider direct Lambda invocation (loses Gateway benefits)
4. Request feature from AWS AgentCore team

## AWS Feature Request

If tool-level user context is a critical requirement, consider submitting a feature request to AWS:

**Feature**: Support user context forwarding to Lambda targets in AgentCore Gateway

**Use Case**: Enable tools to perform user-specific operations based on authenticated user identity

**Proposed Solution**: 
- Add optional `forwardUserContext` flag in Lambda target configuration
- Include JWT claims in Lambda event or context
- Maintain backward compatibility

**Workaround**: Currently using Agent-level user context enrichment
