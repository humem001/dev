# Lambda Strands AgentCore MCP Integration

This project demonstrates a complete end-to-end integration between AWS Lambda, Amazon Bedrock, AgentCore Gateway, and MCP (Model Context Protocol) tools.

## Architecture

```
User Prompt → Strands Agent → Bedrock → Gateway → MCP Tool Lambda → S3 API → Response
```

## Components

### 1. Strands Agent Lambda
- **Function**: `AgentCoreStrandsStack-Dev-StrandsAgent4EBDB762-X8RjaFpbItq8`
- **Purpose**: Receives user prompts, calls Bedrock with available tools, executes tools via Gateway
- **Authentication**: OAuth 2.0 Client Credentials Grant
- **Key Features**:
  - Tool name mapping for Gateway compatibility
  - OAuth token management with Secrets Manager
  - Bedrock integration with tool calling

### 2. MCP Tool Lambda
- **Function**: `AgentCoreStrandsStack-Dev-MCPToolE1462ADC-1sIItGwjnJyi`
- **Purpose**: Implements MCP protocol, executes real S3 operations
- **Tools Available**:
  - `list_s3_buckets` - Lists all S3 buckets with names and creation timestamps

### 3. AgentCore Gateway
- **Gateway ID**: `strands-gateway-prod-r1e58mnw01`
- **URL**: `https://strands-gateway-prod-r1e58mnw01.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp`
- **Target ID**: `T0KMUSAHMY`
- **Authentication**: Cognito JWT with OAuth scope `strands-gateway-prod/invoke`

## Authentication Flow

1. **Client Credentials**: Strands Agent retrieves client secret from Secrets Manager
2. **OAuth Token**: Requests access token from Cognito OAuth endpoint
3. **Gateway Auth**: Uses Bearer token to authenticate with Gateway
4. **Tool Execution**: Gateway routes authenticated requests to Lambda target

## Configuration

### Environment Variables (Strands Agent)
```
GATEWAY_URL=https://strands-gateway-prod-r1e58mnw01.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp
CLIENT_ID=41ijgbsk2kgj9euvl7n7mgcdtl
USER_POOL_ID=eu-west-2_HTqLubtpj
COGNITO_CREDENTIALS_SECRET_ARN=arn:aws:secretsmanager:eu-west-2:581571671018:secret:CognitoCredentials17930F63-pEyoQAH4ipm7-GfXHcO
POWERTOOLS_METRICS_NAMESPACE=AgentCore
POWERTOOLS_SERVICE_NAME=strands-agent
```

### Secrets Manager
- **Secret Name**: `CognitoCredentials17930F63-pEyoQAH4ipm7`
- **Content**: `{"client_secret": "..."}`

## Testing

### End-to-End Test
```bash
aws lambda invoke \
  --function-name AgentCoreStrandsStack-Dev-StrandsAgent4EBDB762-X8RjaFpbItq8 \
  --region eu-west-2 \
  --payload '{"prompt": "List my S3 buckets"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'
```

### Gateway Direct Test
```bash
# Get OAuth token
NEW_TOKEN=$(curl -s -X POST https://agentcore-f5dcf6a4.auth.eu-west-2.amazoncognito.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=41ijgbsk2kgj9euvl7n7mgcdtl&client_secret=...&scope=strands-gateway-prod/invoke" | jq -r '.access_token')

# Test tools/call
curl -X POST https://strands-gateway-prod-r1e58mnw01.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "TestGatewayTarget___list_s3_buckets", "arguments": {}}}' | jq .
```

## Deployment

```bash
cd cdk
cdk deploy --require-approval never
```

## Key Features

- ✅ **OAuth 2.0 Authentication** - Secure machine-to-machine authentication
- ✅ **MCP Protocol** - Standard Model Context Protocol implementation
- ✅ **Tool Name Mapping** - Automatic mapping between Bedrock and Gateway tool names
- ✅ **Real S3 Integration** - Returns actual S3 bucket data (23 buckets found)
- ✅ **Dual Authentication** - Both client credentials and user authentication flows
- ✅ **User Context Propagation** - HTTP headers passing user information to downstream services

## Success Metrics

The integration successfully:
- **Returns actual S3 bucket data** - 23 buckets with names and creation timestamps
- Processes user prompts through Bedrock
- Routes requests through AgentCore Gateway  
- Executes real AWS API calls
- Demonstrates complete OAuth authentication flow with both client credentials and user authentication
- Supports dual authentication methods for different use cases
- Propagates user context through HTTP headers to downstream services

## Current Working Results

**End-to-end test returns real S3 data:**

**Client Credentials Authentication:**
```bash
aws lambda invoke \
  --function-name AgentCoreStrandsStack-Dev-StrandsAgent4EBDB762-X8RjaFpbItq8 \
  --region eu-west-2 \
  --payload '{"prompt": "List my S3 buckets"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'

# Output:
# Okay, let me list your S3 buckets:
# Tool list_s3_buckets executed: Found 23 S3 buckets:
# - 581571671018-mwaa (created: 2024-10-30T18:13:21+00:00)
# - bedrock-kb-data-581571671018-mjhume (created: 2025-07-02T21:02:33+00:00)
# - strands-581571671018 (created: 2025-08-26T09:47:31+00:00)
# ... and 20 more buckets
```

**User Authentication:**
```bash
aws lambda invoke \
  --function-name AgentCoreStrandsStack-Dev-StrandsAgent4EBDB762-X8RjaFpbItq8 \
  --region eu-west-2 \
  --payload '{"prompt": "List my S3 buckets", "username": "testuser", "password": "UserPass123!"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'

# Output:
# Tool list_s3_buckets executed: Found 23 S3 buckets with user context
```

## Architecture Benefits

- **Scalable**: Serverless Lambda functions auto-scale
- **Secure**: OAuth + IAM + Secrets Manager for authentication
- **Modular**: Separate concerns (agent, gateway, tools)
- **Observable**: PowerTools metrics and logging
- **Standard**: Uses MCP protocol for tool integration
