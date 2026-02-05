# Gateway Interceptor Implementation Guide

## Overview

This guide shows how to implement a Gateway Request Interceptor to forward user context (user_id, username) from JWT tokens to your Tool Lambda.

## What Problem Does This Solve?

**Current State**: Tool Lambda receives `user_id: "unknown"` because Gateway strips user_context

**After Implementation**: Tool Lambda receives actual user_id and username from JWT

## Architecture

```
User Request (JWT Token)
    ↓
Agent Lambda
    ↓
AgentCore Gateway
    ↓
Gateway Request Interceptor Lambda ← Extracts JWT claims
    ↓                                  Adds user_context to parameters
Tool Lambda ← Receives user_context!
```

## Implementation Steps

### Step 1: Create Interceptor Lambda Function

Create `src/interceptors/gateway_request_interceptor.py`:

```python
"""Gateway Request Interceptor for User Context Propagation.

This Lambda function extracts user identity from JWT tokens and adds
user context to tool parameters before forwarding to Tool Lambda.
"""

import json
import base64
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def decode_jwt_payload(token):
    """Decode JWT payload without verification.
    
    Gateway has already validated the JWT, so we just extract claims.
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary of JWT claims
    """
    try:
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            logger.warning("Invalid JWT format")
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
    
    Args:
        event: Gateway interceptor event
        context: Lambda context
        
    Returns:
        Transformed gateway request with user context
    """
    request_id = context.aws_request_id
    
    try:
        # Log incoming event structure (for debugging)
        logger.info(f"Interceptor invoked: {request_id}")
        
        # Extract gateway request
        mcp_data = event.get('mcp', {})
        gateway_request = mcp_data.get('gatewayRequest', {})
        headers = gateway_request.get('headers', {})
        body = gateway_request.get('body', {})
        
        # Extract JWT token from Authorization header
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        if not auth_header:
            logger.warning("No Authorization header found")
            return _return_original_request(gateway_request)
        
        token = auth_header.replace('Bearer ', '').replace('bearer ', '')
        
        # Decode JWT to get user claims
        claims = decode_jwt_payload(token)
        if not claims:
            logger.warning("Failed to decode JWT claims")
            return _return_original_request(gateway_request)
        
        # Extract user identity from JWT claims
        user_id = claims.get('sub', 'unknown')
        username = claims.get('username', claims.get('cognito:username', 'unknown'))
        client_id = claims.get('client_id', 'unknown')
        
        logger.info(f"Processing request for user: {username} ({user_id})")
        
        # Add user context to tool parameters
        if "params" in body and "arguments" in body["params"]:
            # Add user_context to arguments
            body["params"]["arguments"]["user_context"] = {
                "user_id": user_id,
                "username": username,
                "client_id": client_id
            }
            
            logger.info(f"Added user_context to tool parameters")
        else:
            logger.warning("Unexpected body structure, cannot add user_context")
        
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
        
        logger.info(f"Request transformation complete: {request_id}")
        return transformed_request
    
    except Exception as e:
        logger.error(f"Interceptor error: {str(e)}", exc_info=True)
        # Return original request on error to avoid breaking the flow
        return _return_original_request(gateway_request)


def _return_original_request(gateway_request):
    """Return original request unchanged on error.
    
    Args:
        gateway_request: Original gateway request
        
    Returns:
        Interceptor response with original request
    """
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": gateway_request
        }
    }
```

### Step 2: Create Build Script

Create `build_interceptor.sh`:

```bash
#!/bin/bash
set -e

echo "Building Gateway Interceptor Lambda package..."

# Create build directory
rm -rf build/interceptor
mkdir -p build/interceptor

# Copy interceptor code
cp src/interceptors/gateway_request_interceptor.py build/interceptor/

# Create deployment package
cd build/interceptor
zip -r ../../gateway-interceptor.zip .
cd ../..

echo "✓ Gateway Interceptor package created: gateway-interceptor.zip"
```

Make it executable:
```bash
chmod +x build_interceptor.sh
```

### Step 3: Create CloudFormation Template

Create `cloudformation/gateway-interceptor.yaml`:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Gateway Request Interceptor for User Context Propagation'

Parameters:
  LambdaCodeBucket:
    Type: String
    Description: 'S3 bucket containing Lambda deployment package'
  
  LambdaCodeKey:
    Type: String
    Default: 'gateway-interceptor.zip'
    Description: 'S3 key for Lambda deployment package'

Resources:
  # CloudWatch Log Group
  InterceptorLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${AWS::StackName}-gateway-interceptor'
      RetentionInDays: 30

  # IAM Execution Role
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
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - 'logs:CreateLogGroup'
                  - 'logs:CreateLogStream'
                  - 'logs:PutLogEvents'
                Resource:
                  - !GetAtt InterceptorLogGroup.Arn

  # Lambda Function
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
        S3Key: !Ref LambdaCodeKey
      Timeout: 10
      MemorySize: 128
      Environment:
        Variables:
          LOG_LEVEL: 'INFO'
      Tags:
        - Key: Application
          Value: 'serverless-ai-agent'
        - Key: Component
          Value: 'gateway-interceptor'

Outputs:
  InterceptorFunctionArn:
    Description: 'Gateway Interceptor Lambda ARN'
    Value: !GetAtt InterceptorFunction.Arn
    Export:
      Name: !Sub '${AWS::StackName}-InterceptorArn'
  
  InterceptorFunctionName:
    Description: 'Gateway Interceptor Lambda Name'
    Value: !Ref InterceptorFunction
    Export:
      Name: !Sub '${AWS::StackName}-InterceptorName'
  
  InterceptorLogGroupName:
    Description: 'Gateway Interceptor Log Group Name'
    Value: !Ref InterceptorLogGroup
    Export:
      Name: !Sub '${AWS::StackName}-InterceptorLogGroupName'
```

### Step 4: Deploy Interceptor Lambda

```bash
# Set variables
export DEPLOYMENT_BUCKET="581571671018-agentcore-eu-west-2"
export AWS_REGION="eu-west-2"
export STACK_NAME="serverless-ai-agent-dev-InterceptorStack"

# Build package
./build_interceptor.sh

# Upload to S3
aws s3 cp gateway-interceptor.zip s3://${DEPLOYMENT_BUCKET}/ --region ${AWS_REGION}

# Deploy CloudFormation stack
aws cloudformation create-stack \
  --stack-name ${STACK_NAME} \
  --template-body file://cloudformation/gateway-interceptor.yaml \
  --parameters ParameterKey=LambdaCodeBucket,ParameterValue=${DEPLOYMENT_BUCKET} \
  --capabilities CAPABILITY_IAM \
  --region ${AWS_REGION}

# Wait for stack creation
aws cloudformation wait stack-create-complete \
  --stack-name ${STACK_NAME} \
  --region ${AWS_REGION}

# Get Interceptor ARN
INTERCEPTOR_ARN=$(aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`InterceptorFunctionArn`].OutputValue' \
  --output text \
  --region ${AWS_REGION})

echo "Interceptor ARN: ${INTERCEPTOR_ARN}"
```

### Step 5: Attach Interceptor to Gateway

```bash
# Set Gateway ID
export GATEWAY_ID="ai-agent-mcp-gateway-dev-hlgqg8fahq"

# Update Gateway with request interceptor
aws bedrock-agentcore-control update-gateway \
  --gateway-identifier ${GATEWAY_ID} \
  --request-interceptor-lambda-arn ${INTERCEPTOR_ARN} \
  --region ${AWS_REGION}

echo "✓ Gateway interceptor attached successfully"
```

### Step 6: Grant Gateway Permission to Invoke Interceptor

```bash
# Get Gateway ARN
GATEWAY_ARN="arn:aws:bedrock-agentcore:${AWS_REGION}:581571671018:gateway/${GATEWAY_ID}"

# Add Lambda permission
aws lambda add-permission \
  --function-name ${INTERCEPTOR_ARN} \
  --statement-id AllowGatewayInvoke \
  --action lambda:InvokeFunction \
  --principal bedrock-agentcore.amazonaws.com \
  --source-arn ${GATEWAY_ARN} \
  --region ${AWS_REGION}

echo "✓ Gateway permission granted"
```

### Step 7: Verify Tool Lambda Receives User Context

Your Tool Lambda will now receive user_context in parameters:

```python
def handle_gateway_request(event, context, request_id, start_time):
    """Handle Gateway direct invocation requests."""
    try:
        # Extract parameters
        parameters = event.get('arguments', event.get('parameters', {}))
        
        # Extract user_context (NOW AVAILABLE!)
        user_context_dict = parameters.pop('user_context', {}) if isinstance(parameters, dict) else {}
        
        # Get user identity
        user_id = user_context_dict.get('user_id', 'unknown')
        username = user_context_dict.get('username', 'unknown')
        client_id = user_context_dict.get('client_id', 'unknown')
        
        # Log with user attribution
        log_structured(
            level='INFO',
            message='Tool invoked by user',
            user_id=user_id,
            username=username,
            client_id=client_id,
            request_id=request_id
        )
        
        # Use for user-specific operations
        # ... rest of your tool logic ...
```

## Testing

### Test 1: Verify Interceptor Logs

```bash
# Watch interceptor logs
aws logs tail /aws/lambda/${STACK_NAME}-gateway-interceptor --follow --region ${AWS_REGION}
```

### Test 2: Invoke Agent and Check Tool Logs

```bash
# Get JWT token
export JWT_TOKEN=$(python get_jwt_token.py)

# Update test event
cat test-event.json | jq --arg token "$JWT_TOKEN" '.jwt_token = $token' > test-event.json.tmp
mv test-event.json.tmp test-event.json

# Invoke Agent
aws lambda invoke \
  --function-name serverless-ai-agent-dev-AgentStack-18GVSUAMXL2T5-agent \
  --payload file://test-event.json \
  --cli-binary-format raw-in-base64-out \
  response.json \
  --region ${AWS_REGION}

# Check response
cat response.json | jq '.body' | jq -r '.' | jq '.'

# Check Tool Lambda logs
aws logs tail /aws/lambda/serverless-ai-agent-dev-ToolStack-1U7VJEK3XKGWL-tool --follow --region ${AWS_REGION}
```

You should now see actual user_id and username in Tool Lambda logs!

## Expected Results

### Before Interceptor
```json
{
  "buckets": [...],
  "count": 27,
  "user_id": "unknown"  // ❌
}
```

### After Interceptor
```json
{
  "buckets": [...],
  "count": 27,
  "user_id": "06521204-70a1-70cd-ad3b-46bdc78b3afc"  // ✅
}
```

## Troubleshooting

### Issue: Interceptor not invoked
**Solution**: Check Gateway configuration
```bash
aws bedrock-agentcore-control get-gateway \
  --gateway-identifier ${GATEWAY_ID} \
  --region ${AWS_REGION}
```

### Issue: Permission denied
**Solution**: Verify Lambda permission
```bash
aws lambda get-policy \
  --function-name ${INTERCEPTOR_ARN} \
  --region ${AWS_REGION}
```

### Issue: User context still "unknown"
**Solution**: Check interceptor logs for errors
```bash
aws logs tail /aws/lambda/${STACK_NAME}-gateway-interceptor --region ${AWS_REGION}
```

## Benefits

After implementing Gateway Interceptor:

- ✅ Tool Lambda receives actual user_id and username
- ✅ Tool-level user-specific operations enabled
- ✅ User attribution in tool logs
- ✅ Fine-grained access control per user
- ✅ Multi-tenant support
- ✅ Maintains all Gateway benefits (MCP, discovery, semantic search)
- ✅ Follows AWS best practices ("act-on-behalf" pattern)
- ✅ No changes to existing Agent or Tool Lambda code structure

## Next Steps

1. Implement user-specific operations in tools
2. Add fine-grained access control based on user_id
3. Implement multi-tenant isolation
4. Add user-based audit logging in tools
5. Consider response interceptor for dynamic tool filtering

## References

- [AWS Blog: Apply fine-grained access control with Bedrock AgentCore Gateway interceptors](https://aws.amazon.com/blogs/machine-learning/apply-fine-grained-access-control-with-bedrock-agentcore-gateway-interceptors/)
- [GitHub: AgentCore Gateway Interceptor Samples](https://github.com/aws-samples/amazon-bedrock-agentcore-samples)
- [AWS Docs: Fine-grained access control for Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html)
