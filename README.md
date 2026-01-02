# Lambda Strands AgentCore MCP Integration

A complete implementation of Model Context Protocol (MCP) integration with Amazon Bedrock AgentCore, enabling AI agents to execute real AWS operations through secure, authenticated tool calls.

## Architecture Overview

This project demonstrates end-to-end integration from user prompts to AWS service execution:

**User Prompt** → **Strands Agent** → **Bedrock LLM** → **AgentCore Gateway** → **MCP Tool Lambda** → **AWS Services** → **Response**

## Key Features

- **Dual Authentication**: OAuth 2.0 client credentials and Cognito user authentication
- **Real AWS Integration**: Direct S3 API calls returning actual bucket data
- **MCP Protocol**: Full JSON-RPC 2.0 implementation for tool communication
- **User Context Propagation**: HTTP headers enable downstream authorization and logging
- **VPC Security**: Private subnets with VPC endpoints for secure AWS service access
- **Tool Name Mapping**: Gateway-compatible tool routing with proper naming conventions

## Components

### 1. Strands Agent Lambda
- **Function**: `<STRANDS_AGENT_FUNCTION_NAME>`
- **Purpose**: Receives user prompts, calls Bedrock with available tools, executes tools via Gateway
- **Authentication**: OAuth 2.0 Client Credentials Grant
- **Key Features**:
  - Tool name mapping for Gateway compatibility
  - OAuth token management with Secrets Manager
  - Bedrock integration with tool calling

### 2. MCP Tool Lambda
- **Function**: `<MCP_TOOL_FUNCTION_NAME>`
- **Purpose**: Implements MCP protocol, executes real S3 operations
- **Tools Available**:
  - `list_s3_buckets` - Lists all S3 buckets with names and creation timestamps

### 3. AgentCore Gateway
- **Gateway ID**: `<GATEWAY_ID>`
- **URL**: `https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com/mcp`
- **Target ID**: `<TARGET_ID>`
- **Authentication**: Cognito JWT with OAuth scope `<GATEWAY_ID>/invoke`

## Configuration

### Environment Variables (Strands Agent)
```
GATEWAY_URL=https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com/mcp
CLIENT_ID=<CLIENT_ID>
USER_POOL_ID=<REGION>_<USER_POOL_ID>
COGNITO_CREDENTIALS_SECRET_ARN=arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:<SECRET_NAME>
POWERTOOLS_METRICS_NAMESPACE=AgentCore
POWERTOOLS_SERVICE_NAME=strands-agent
```

### Secrets Manager
- **Secret Name**: `<SECRET_NAME>`
- **Content**: `{"client_secret": "<CLIENT_SECRET>"}`

### Cognito Configuration
- **User Pool**: `<REGION>_<USER_POOL_ID>`
- **Client ID**: `<CLIENT_ID>`
- **OAuth Scopes**: `<GATEWAY_ID>/invoke`
- **Grant Types**: Client credentials, Authorization code

## Deployment

### Prerequisites
- AWS CDK v2.x
- Node.js 18+
- AWS CLI configured
- AgentCore CLI installed

### Deploy Infrastructure
```bash
cd cdk
npm install
cdk deploy --require-approval never
```

### Post-Deployment Setup
1. **Update Secrets Manager** with client secret from Cognito
2. **Create Gateway** using AgentCore CLI
3. **Create Gateway Target** pointing to MCP Tool Lambda
4. **Test Integration** with provided commands

## Authentication Flows

### Client Credentials Flow
1. Strands Agent retrieves client secret from Secrets Manager
2. Requests OAuth token from Cognito using client credentials
3. Uses Bearer token to authenticate with Gateway
4. Gateway validates token and invokes MCP Tool Lambda via IAM

### User Authentication Flow
1. User provides username/password in request
2. Strands Agent authenticates user with Cognito
3. Propagates user context via HTTP headers
4. MCP Tool Lambda receives user context for authorization

## Testing

### End-to-End Test
```bash
aws lambda invoke \
  --function-name <STRANDS_AGENT_FUNCTION_NAME> \
  --region <REGION> \
  --payload '{"prompt": "List my S3 buckets"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'
```

### Gateway Direct Test
```bash
# Get OAuth token
NEW_TOKEN=$(curl -s -X POST https://<COGNITO_DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&scope=<GATEWAY_ID>/invoke" | jq -r '.access_token')

# Test tools/call
curl -X POST https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com/mcp \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "<TARGET_ID>___list_s3_buckets", "arguments": {}}}' | jq .
```

## Working Results

**Client Credentials Authentication:**
```bash
aws lambda invoke \
  --function-name <STRANDS_AGENT_FUNCTION_NAME> \
  --region <REGION> \
  --payload '{"prompt": "List my S3 buckets"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'

# Output:
# Okay, let me list your S3 buckets:
# Tool list_s3_buckets executed: Found X S3 buckets:
# - bucket-name-1 (created: YYYY-MM-DDTHH:MM:SS+00:00)
# - bucket-name-2 (created: YYYY-MM-DDTHH:MM:SS+00:00)
# ... and more buckets
```

**User Authentication:**
```bash
aws lambda invoke \
  --function-name <STRANDS_AGENT_FUNCTION_NAME> \
  --region <REGION> \
  --payload '{"prompt": "List my S3 buckets", "username": "<USERNAME>", "password": "<PASSWORD>"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/response.json && cat /tmp/response.json | jq -r '.body' | jq -r '.message'

# Output:
# Tool list_s3_buckets executed: Found X S3 buckets with user context
```

## Technical Implementation

### MCP Protocol
- **JSON-RPC 2.0**: Standard protocol for tool communication
- **Tool Discovery**: `tools/list` method returns available tools
- **Tool Execution**: `tools/call` method executes specific tools
- **Error Handling**: Proper JSON-RPC error responses

### Security
- **VPC Isolation**: Lambda functions in private subnets
- **VPC Endpoints**: Secure access to AWS services (S3, Secrets Manager)
- **IAM Roles**: Least privilege access for Lambda execution
- **OAuth 2.0**: Industry standard authentication
- **User Context**: Propagated for downstream authorization

### Tool Name Mapping
Gateway requires specific tool naming convention:
- **MCP Tool**: `list_s3_buckets`
- **Gateway Tool**: `<TARGET_ID>___list_s3_buckets`
- **Strands Agent**: Maps between formats for proper routing

## Success Metrics

✅ **End-to-End Integration**: User prompt → Real S3 bucket data  
✅ **Dual Authentication**: Both client credentials and user auth working  
✅ **MCP Protocol**: Full JSON-RPC 2.0 implementation  
✅ **User Context**: Propagated through HTTP headers  
✅ **Real AWS Services**: Direct S3 API integration  
✅ **Security**: VPC isolation with proper IAM roles  

## Architecture Diagram

See `strands-agentcore-mcp-v2.drawio` for complete architecture visualization showing:
- Authentication flows (OAuth + IAM)
- Network topology (VPC, subnets, endpoints)
- Service interactions and data flow
- Security boundaries and access patterns

## Next Steps

- **Add More Tools**: Extend MCP Tool Lambda with additional AWS service integrations
- **Enhanced Security**: Implement fine-grained IAM policies based on user context
- **Monitoring**: Add CloudWatch metrics and alarms for production readiness
- **Multi-Tenant**: Scale user context propagation for multiple tenants
- **Error Handling**: Implement comprehensive error recovery and retry logic

## Troubleshooting

### Common Issues
1. **Authentication Failures**: Check Secrets Manager client secret
2. **Gateway Errors**: Verify tool name mapping format
3. **VPC Connectivity**: Ensure VPC endpoints are properly configured
4. **Lambda Timeouts**: Check CloudWatch logs for execution details

### Debug Commands
```bash
# Check Lambda logs
aws logs tail /aws/lambda/<FUNCTION_NAME> --follow

# Test Gateway connectivity
curl -X POST https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
