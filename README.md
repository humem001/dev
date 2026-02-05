# Serverless AI Agent System with Strands Framework

A production-ready serverless AI agent system built with AWS Bedrock Strands Framework, demonstrating secure multi-tenant AI agents with dynamic tool discovery using AgentCore Gateway and Model Context Protocol (MCP).

**Status**: ✅ Production Ready  
**Last Updated**: January 27, 2026  
**Region**: eu-west-1

## Architecture

```
User Request (JWT Auth)
    ↓
Agent Lambda (Strands Framework + Bedrock Claude 3 Sonnet)
    ↓
AgentCore Gateway (MCP Protocol)
    ↓
Tool Lambda (MCP Tools)
    ↓
AWS Services (S3, etc.)
```

## Key Features

- **Strands Framework Integration**: Built on AWS Bedrock Strands Framework for robust agent orchestration
- **Dynamic Tool Discovery**: Tools discovered from Gateway at runtime (no hardcoded tool definitions)
- **MCP Protocol**: Model Context Protocol for standardized tool communication
- **JWT Authentication**: Secure authentication via Cognito with JWT token validation
- **Dual-Mode Tool Lambda**: Supports both MCP JSON-RPC (discovery) and direct invocation (execution)
- **Graceful Degradation**: Continues operation even if Gateway or Memory are unavailable
- **Comprehensive Logging**: Structured CloudWatch logs with audit trails

## Project Structure

```
.
├── src/
│   ├── agent/               # Strands Framework agent implementation
│   │   ├── agent_core.py    # Main agent with Bedrock integration
│   │   ├── lambda_handler.py
│   │   ├── exceptions.py
│   │   └── error_handlers.py
│   ├── tools/               # MCP tool implementations
│   │   ├── lambda_handler.py         # Dual-mode handler (MCP + Gateway)
│   │   ├── s3_list_buckets_tool.py   # S3 bucket listing tool
│   │   ├── tool_discovery.py         # Tool discovery service
│   │   ├── tool_registry.py          # Local tool registry
│   │   └── gateway_discovery_client.py
│   ├── gateway/             # AgentCore Gateway client
│   │   └── gateway_client.py         # MCP protocol client
│   ├── memory/              # AgentCore Memory integration
│   │   └── memory_client.py
│   ├── auth/                # JWT authentication
│   │   └── jwt_validator.py
│   ├── models/              # Core data models
│   │   ├── user_context.py
│   │   ├── conversation.py
│   │   ├── mcp_tool.py
│   │   ├── agent_response.py
│   │   └── audit_log.py
│   ├── config/              # Configuration
│   │   └── timeout_config.py
│   └── audit_logging/       # Structured audit logging
│       └── audit_logger.py
├── tests/                   # Comprehensive test suite
├── cloudformation/          # CloudFormation templates
│   ├── master.yaml          # Main stack
│   ├── vpc-networking.yaml  # VPC with S3 endpoint
│   ├── agent-lambda.yaml    # Agent Lambda
│   ├── tool-lambda.yaml     # Tool Lambda
│   └── DEPLOYMENT_GUIDE.md  # Complete deployment guide
├── docs/                    # Documentation
│   ├── DYNAMIC_TOOL_DISCOVERY.md
│   └── TOOL_EXTENSIBILITY.md
├── rebuild_agent_lambda.sh  # Agent Lambda build script
├── rebuild_tool_lambda.sh   # Tool Lambda build script
├── requirements.txt         # Python dependencies
└── pyproject.toml          # Project configuration
```

## Quick Start

### Prerequisites

- Python 3.12+
- AWS Account with appropriate permissions
- AWS CLI configured
- S3 bucket for deployment artifacts

### Deployment

Follow the complete deployment guide in `cloudformation/DEPLOYMENT_GUIDE.md`:

1. **Build Lambda packages**:
   ```bash
   ./rebuild_agent_lambda.sh
   ./rebuild_tool_lambda.sh
   ```

2. **Upload to S3**:
   ```bash
   export DEPLOYMENT_BUCKET="your-bucket-name"
   export AWS_REGION="eu-west-2"
   
   aws s3 cp agent-lambda.zip s3://${DEPLOYMENT_BUCKET}/
   aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/
   ```

3. **Deploy CloudFormation stack**:
   ```bash
   aws cloudformation create-stack \
     --stack-name serverless-ai-agent-dev \
     --template-body file://cloudformation/master.yaml \
     --parameters file://cloudformation/parameters.json \
     --capabilities CAPABILITY_NAMED_IAM \
     --region ${AWS_REGION}
   ```

4. **Create AgentCore Gateway** (via AWS Console)
   - Navigate to Bedrock Console → AgentCore → Gateways
   - Create Gateway with Cognito authentication
   - Configure Lambda target

5. **Update Agent Lambda** with Gateway URL

See `cloudformation/DEPLOYMENT_GUIDE.md` for detailed instructions.

### Testing

```bash
# Create test user
aws cognito-idp admin-create-user \
  --user-pool-id ${GATEWAY_USER_POOL_ID} \
  --username testuser@example.com \
  --password 'SecurePassword123!' \
  --permanent

# Get JWT token
python3 get_jwt_token.py > jwt_token.txt

# Test the agent
aws lambda invoke \
  --function-name ${AGENT_FUNCTION_NAME} \
  --payload file://test-event.json \
  response.json
```

## Development

### Local Development

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e ".[test]"
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run property-based tests only
pytest -m property
```

### Adding New Tools

1. Create tool class in `src/tools/` implementing `MCPTool` interface
2. Register tool in `src/tools/lambda_handler.py`
3. Rebuild and deploy Tool Lambda:
   ```bash
   ./rebuild_tool_lambda.sh
   aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/
   aws lambda update-function-code \
     --function-name ${TOOL_FUNCTION_NAME} \
     --s3-bucket ${DEPLOYMENT_BUCKET} \
     --s3-key tool-lambda.zip
   ```
4. Gateway will automatically discover the new tool

### Core Components

#### Agent Lambda (Strands Framework)
- Processes user prompts using Bedrock Claude 3 Sonnet
- Discovers tools dynamically from Gateway
- Manages conversation context (optional Memory integration)
- Handles tool execution orchestration

#### Tool Lambda (MCP Protocol)
- Dual-mode handler:
  - MCP JSON-RPC for `tools/list` (discovery)
  - Direct invocation for tool execution (from Gateway)
- Implements MCP tools (S3, etc.)
- User context propagation

#### Gateway Client
- MCP protocol implementation
- JWT authentication
- Tool discovery and execution
- Retry logic and error handling

## Documentation

### Primary Documentation
- **📘 Deployment Guide**: `cloudformation/DEPLOYMENT_GUIDE.md` - Complete step-by-step deployment instructions
- **📊 Production Summary**: `PRODUCTION_READY_SUMMARY.md` - Production deployment status and test results
- **🔍 Final Status**: `FINAL_STATUS.md` - Detailed system status and known limitations

### Technical Documentation
- **🔧 Dynamic Tool Discovery**: `docs/DYNAMIC_TOOL_DISCOVERY.md` - How tool discovery works
- **🛠️ Tool Extensibility**: `docs/TOOL_EXTENSIBILITY.md` - Adding new tools to the system

### Investigation & Troubleshooting
- **⚠️ Interceptor Troubleshooting**: `INTERCEPTOR_TROUBLESHOOTING.md` - Gateway Interceptor investigation
- **🔐 User Context Investigation**: `GATEWAY_USER_CONTEXT_INVESTIGATION.md` - User context propagation analysis
- **📝 Gateway Interceptor Implementation**: `GATEWAY_INTERCEPTOR_IMPLEMENTATION.md` - Implementation guide (not currently working)

## Known Limitations

⚠️ **User Context in Tool Lambda**: Tool Lambda receives `user_id: "unknown"` because AgentCore Gateway strips user context before forwarding (security boundary by design).

**What Works**:
- ✅ User context IS available in Agent Lambda
- ✅ User context IS available in Agent responses
- ✅ User context IS logged in Agent audit logs

**What Doesn't Work**:
- ❌ Tool Lambda doesn't see actual user ID
- ❌ Gateway Interceptor causes 500 errors when attached

**Impact**: System is fully functional for most use cases. Only affects tool-level user-specific operations.

See `INTERCEPTOR_TROUBLESHOOTING.md` for full investigation details.

## Key Design Decisions

### Why Gateway Doesn't Use MCP for Tool Execution

The Gateway uses MCP JSON-RPC for tool discovery (`tools/list`) but direct Lambda invocation for tool execution. This is by AWS design:

- **Gateway is the MCP abstraction layer** - Provides MCP interface to Agent
- **Performance optimization** - Direct invocation is faster than MCP wrapping
- **Simplified tool implementation** - Tools don't need full MCP protocol parsing

### Dynamic Tool Discovery

Tools are discovered from Gateway at runtime, eliminating duplication:
- **Single source of truth**: Gateway defines tools
- **No hardcoded definitions**: Agent queries Gateway for available tools
- **Automatic updates**: New tools available immediately after deployment

## License

MIT
