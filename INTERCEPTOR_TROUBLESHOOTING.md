# Gateway Interceptor Troubleshooting

## Current Status

✅ **Working:**
- CloudFormation stacks deployed in eu-west-1
- Agent Lambda working correctly
- Tool Lambda working correctly
- Gateway working correctly WITHOUT interceptor
- User context extracted by Agent Lambda from JWT
- System successfully lists S3 buckets

❌ **Issue:**
- Gateway returns 500 error when interceptor is attached
- Interceptor Lambda is NOT being invoked (no logs)
- System works perfectly when interceptor is removed

## What We've Done

### 1. Deployed Infrastructure
- ✅ VPC with private subnets
- ✅ Agent Lambda (Strands Framework)
- ✅ Tool Lambda (S3 list buckets)
- ✅ Gateway created: `ai-agent-mcp-gateway-dev-f6oa4wfryg`
- ✅ Gateway Target added (Tool Lambda)
- ✅ Cognito User Pool configured
- ✅ Test user created

### 2. Deployed Interceptor
- ✅ Built interceptor package
- ✅ Uploaded to S3
- ✅ Deployed CloudFormation stack
- ✅ Granted Gateway permission to invoke interceptor
- ✅ Attached interceptor to Gateway

### 3. Testing Results

**Without Interceptor:**
```json
{
  "user_context": {
    "user_id": "6255d4b4-7091-7021-e4e4-b8f2e5c43d97",
    "username": "testuser@example.com",
    "client_id": "2co4da073qrhr0fsk07gusjauc"
  },
  "tool_executions": [{
    "tool_name": "target-quick-start-0bc241___list_s3_buckets",
    "status": "success"
  }]
}
```
Tool Lambda shows: `"user_id": "unknown"` ✅ (expected)

**With Interceptor:**
- Gateway returns 500 error
- Agent Lambda logs: `Gateway request failed with status 500`
- Interceptor logs: EMPTY (not invoked)
- System completely broken

## Possible Causes

### 1. Interceptor Response Format Issue
The interceptor might be returning an incorrect response format that the Gateway doesn't understand, causing it to fail before even invoking the interceptor.

### 2. Gateway Configuration Issue
The interceptor configuration might be incorrect:
- Interception point: `REQUEST`
- Pass headers: `True`
- Lambda ARN: Correct

### 3. Permission Issue
Although we granted permission, there might be an IAM role issue preventing the Gateway from invoking the interceptor.

### 4. Gateway Version/Feature Issue
The Gateway Interceptor feature might have specific requirements or limitations in eu-west-1 that we're not aware of.

## Next Steps to Debug

### Option 1: Check Gateway Interceptor Documentation
Search for official AWS documentation on Gateway Interceptor request/response format and requirements.

### Option 2: Simplify Interceptor
Create a minimal interceptor that just logs and returns the original request unchanged to verify the invocation works.

### Option 3: Check CloudWatch Insights
Query CloudWatch Logs Insights for any Gateway-level errors that might explain why the interceptor isn't being invoked.

### Option 4: Contact AWS Support
Since this is a newly released feature (2025), there might be undocumented requirements or known issues.

## Interceptor Code

The interceptor extracts user context from JWT and adds it to tool parameters:

```python
# Extract JWT claims
claims = decode_jwt_payload(token)
user_context = extract_user_context(claims)

# Add to tool parameters
body["params"]["arguments"]["user_context"] = user_context

# Return transformed request
return {
    "interceptorOutputVersion": "1.0",
    "mcp": {
        "transformedGatewayRequest": {
            "headers": {...},
            "body": body
        }
    }
}
```

## Resources

- Interceptor ARN: `arn:aws:lambda:eu-west-1:581571671018:function:serverless-ai-agent-dev-InterceptorStack-gateway-interceptor`
- Gateway ID: `ai-agent-mcp-gateway-dev-f6oa4wfryg`
- Gateway URL: `https://ai-agent-mcp-gateway-dev-f6oa4wfryg.gateway.bedrock-agentcore.eu-west-1.amazonaws.com/mcp`
- Region: `eu-west-1`

## Temporary Workaround

The system works perfectly without the interceptor. The only limitation is that Tool Lambda sees `user_id: "unknown"` instead of the actual user ID.

For now, user context is available in:
1. Agent Lambda (extracted from JWT)
2. Agent response to user
3. Agent audit logs

The interceptor can be added later once we resolve the 500 error issue.
