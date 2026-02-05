# Dynamic Tool Discovery from AgentCore Gateway

## Overview

The Agent Lambda now supports dynamic tool discovery from AgentCore Gateway, eliminating the need for hardcoded tool registries. The Gateway inline schema becomes the single source of truth for tool definitions.

## Features

- **Dynamic Discovery**: Query Gateway for available tools at runtime
- **Smart Caching**: TTL-based caching to minimize Gateway queries
- **Fallback Mechanism**: Uses cached tools when Gateway is unavailable
- **Backward Compatible**: Feature flag allows gradual rollout
- **Zero Code Changes**: Add new tools by only updating Gateway configuration

## Architecture

### Before (Hardcoded Registry)
```
Agent Lambda → Hardcoded Registry → Bedrock
                     ↓
              Gateway (duplicate schema)
```

### After (Dynamic Discovery)
```
Agent Lambda → Discovery Service → Cache → Gateway (single source of truth)
                                      ↓
                                  Bedrock
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENABLE_GATEWAY_DISCOVERY` | Enable Gateway-based discovery | `false` | No |
| `GATEWAY_DISCOVERY_URL` | Gateway MCP endpoint URL | - | Yes (if enabled) |
| `GATEWAY_OAUTH_TOKEN` | OAuth token for Gateway auth | - | Yes (if enabled) |
| `TOOL_CACHE_TTL_SECONDS` | Cache TTL in seconds | `3600` | No |
| `GATEWAY_DISCOVERY_TIMEOUT` | Gateway request timeout | `30` | No |
| `GATEWAY_MAX_RETRY_ATTEMPTS` | Max retry attempts | `3` | No |
| `GATEWAY_RETRY_DELAY_SECONDS` | Delay between retries | `5` | No |
| `FALLBACK_TO_LOCAL_REGISTRY` | Fallback to local registry on error | `true` | No |

### Example Configuration

```bash
# Enable Gateway discovery
export ENABLE_GATEWAY_DISCOVERY=true

# Gateway configuration
export GATEWAY_DISCOVERY_URL=https://ai-agent-mcp-gateway-dev.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp
export GATEWAY_OAUTH_TOKEN=your-oauth-token-here

# Cache configuration
export TOOL_CACHE_TTL_SECONDS=3600  # 1 hour

# Error handling
export GATEWAY_MAX_RETRY_ATTEMPTS=3
export GATEWAY_RETRY_DELAY_SECONDS=5
export FALLBACK_TO_LOCAL_REGISTRY=true
```

## Migration Path

### Phase 1: Deploy with Feature Disabled (Safe)
```bash
# Deploy code with feature flag disabled (default)
export ENABLE_GATEWAY_DISCOVERY=false

# Verify no regressions - system uses local registry as before
```

### Phase 2: Enable for Testing
```bash
# Enable Gateway discovery in test environment
export ENABLE_GATEWAY_DISCOVERY=true
export GATEWAY_DISCOVERY_URL=https://your-gateway-url/mcp
export GATEWAY_OAUTH_TOKEN=your-token

# Test tool discovery and execution
```

### Phase 3: Canary Deployment
```bash
# Enable for 10% of traffic
# Monitor metrics and logs
```

### Phase 4: Full Rollout
```bash
# Enable for 100% of traffic
# Monitor for 1-2 weeks
```

### Phase 5: Remove Local Registry (Optional)
```bash
# After stable operation, remove hardcoded registry code
# This is optional - keeping it as fallback is fine
```

## How It Works

### Tool Discovery Flow

1. **Agent Initialization**
   - Agent Lambda starts
   - Discovery service initializes based on feature flag

2. **Cache Check**
   - Check if cached tools exist and are not expired
   - If valid cache exists, use it (fast path)

3. **Gateway Query** (if cache miss or expired)
   - Send MCP `tools/list` JSON-RPC request to Gateway
   - Handle pagination if needed
   - Validate tool definitions
   - Cache validated tools

4. **Error Handling**
   - If Gateway unavailable, use stale cache (if available)
   - If no cache, fall back to local registry (if enabled)
   - Log warnings for stale cache usage

5. **Bedrock Integration**
   - Convert tools to Bedrock format
   - Pass to Bedrock Converse API
   - Tool execution continues as before

### MCP Protocol

The system uses the MCP (Model Context Protocol) `tools/list` method:

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {
    "cursor": "optional_pagination_cursor"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "list_s3_buckets",
        "description": "Lists all S3 buckets",
        "inputSchema": {
          "type": "object",
          "properties": {...}
        }
      }
    ],
    "nextCursor": "optional_cursor_for_next_page"
  }
}
```

## Adding New Tools

### Before (Manual Process)
1. Update Gateway inline schema
2. Update Agent Lambda tool registry code
3. Rebuild and redeploy Agent Lambda
4. Rebuild and redeploy Tool Lambda

### After (Automatic)
1. Update Gateway inline schema
2. Wait for cache TTL to expire (or trigger manual refresh)
3. Done! New tool automatically available

## Monitoring and Observability

### Key Metrics
- `tool_discovery.success` - Successful discoveries
- `tool_discovery.failure` - Failed discoveries
- `tool_discovery.latency` - Discovery latency
- `tool_cache.hit` - Cache hits
- `tool_cache.miss` - Cache misses
- `tool_cache.age` - Cache age in seconds

### Log Messages

**Successful Discovery:**
```
INFO: Successfully discovered 5 tools from Gateway
INFO: Cached 5 tools
```

**Cache Hit:**
```
INFO: Using cached tools: 5 tools (age: 1234s)
```

**Gateway Failure with Fallback:**
```
WARNING: Gateway error (attempt 3/3): Connection timeout
WARNING: Using stale cached tools due to Gateway unavailability: 5 tools (age: 5000s, TTL: 3600s)
```

**Validation Errors:**
```
ERROR: Tool 'invalid_tool' failed validation:
  - Missing required field: inputSchema
```

## Troubleshooting

### Gateway Discovery Not Working

**Check feature flag:**
```bash
echo $ENABLE_GATEWAY_DISCOVERY  # Should be "true"
```

**Check Gateway URL:**
```bash
echo $GATEWAY_DISCOVERY_URL  # Should be valid Gateway MCP endpoint
```

**Check OAuth token:**
```bash
echo $GATEWAY_OAUTH_TOKEN  # Should be valid token
```

**Check logs:**
```bash
# Look for initialization messages
grep "Gateway discovery" /var/log/agent-lambda.log

# Look for errors
grep "ERROR" /var/log/agent-lambda.log | grep -i gateway
```

### Tools Not Updating

**Check cache TTL:**
```bash
echo $TOOL_CACHE_TTL_SECONDS  # Default is 3600 (1 hour)
```

**Force cache refresh:**
- Restart Lambda (cold start will refresh cache)
- Or wait for TTL to expire

### Gateway Unavailable

**System will automatically:**
1. Retry 3 times with exponential backoff
2. Fall back to cached tools (if available)
3. Fall back to local registry (if enabled)
4. Log warnings about stale cache usage

**Check fallback configuration:**
```bash
echo $FALLBACK_TO_LOCAL_REGISTRY  # Should be "true" for resilience
```

## Security Considerations

1. **OAuth Token Storage**: Store tokens in AWS Secrets Manager or environment variables
2. **HTTPS Only**: Always use HTTPS for Gateway communication
3. **Token Rotation**: Implement token refresh mechanism
4. **Input Validation**: All Gateway responses are validated before use
5. **Error Messages**: Sensitive information is not exposed in logs

## Performance Impact

- **Cold Start**: +100-500ms for initial Gateway query
- **Warm Start**: <1ms (cache hit)
- **Cache Miss**: +100-500ms for Gateway query
- **Memory**: +5-10MB for caching infrastructure

## Best Practices

1. **Set appropriate TTL**: Balance freshness vs. Gateway load (default 1 hour is good)
2. **Enable fallback**: Keep `FALLBACK_TO_LOCAL_REGISTRY=true` for resilience
3. **Monitor metrics**: Watch cache hit rate and discovery latency
4. **Gradual rollout**: Use feature flag for phased deployment
5. **Keep local registry**: Maintain as fallback during transition period

## API Reference

### ToolDiscoveryService

```python
from tools.tool_discovery import get_discovery_service

# Get discovery service (automatically selects mode)
service = get_discovery_service()

# Get tools for Bedrock
tools = service.get_tools_for_bedrock()

# List tool names
names = service.list_available_tools()
```

### Manual Cache Refresh

```python
# Force cache refresh (requires Gateway access)
service._get_gateway_service().refresh_cache()
```

## Support

For issues or questions:
1. Check logs for error messages
2. Verify configuration environment variables
3. Test Gateway connectivity manually
4. Review this documentation
5. Contact the platform team
