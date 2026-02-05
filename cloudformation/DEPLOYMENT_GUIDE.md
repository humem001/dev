# Complete Deployment Guide - Serverless AI Agent System

## Overview

This guide provides complete step-by-step instructions for deploying the Serverless AI Agent System with Strands Framework, including both CloudFormation deployment and manual AgentCore setup.

**Last Updated**: January 27, 2026  
**Status**: Production Ready ✅

## Architecture Overview

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

## What's Working

✅ User authentication via Cognito JWT tokens  
✅ User context extraction (user_id, username, client_id)  
✅ AI agent with Bedrock Claude 3 Sonnet  
✅ Dynamic tool discovery via AgentCore Gateway  
✅ Tool execution (S3 list buckets)  
✅ Audit logging with user attribution  
✅ Error handling and retry logic

## Important: Three-Phase Deployment

⚠️ **AWS CloudFormation Limitations**: AWS::Bedrock::Gateway and AWS::Bedrock::Memory are not yet available as CloudFormation resource types.

**Deployment Phases**:
1. **Phase 1**: Deploy CloudFormation stack (VPC, Lambda functions)
2. **Phase 2**: Manually create AgentCore Gateway with Cognito via AWS Console
3. **Phase 3**: Update Agent Lambda with Gateway URL and configure authentication

**What Each Phase Deploys**:
- ✅ Phase 1: VPC networking and Lambda functions (Agent + Tool)
- ✅ Phase 2: AgentCore Gateway with Cognito authentication (via console)
- ✅ Phase 3: Connect everything together with environment variables

## Known Limitation: User Context in Tool Lambda

⚠️ **Current Behavior**: Tool Lambda receives `user_id: "unknown"` instead of actual user ID.

**Why**: AgentCore Gateway strips user context before forwarding to Tool Lambda (security boundary by design).

**What Works**:
- ✅ User context IS available in Agent Lambda
- ✅ User context IS available in Agent responses
- ✅ User context IS logged in Agent audit logs

**Workaround Attempted**: Gateway Interceptor (AWS feature to forward user context)
- Status: Not working - causes Gateway 500 errors
- Root Cause: Unknown - appears to be Gateway service issue
- Code: Kept in repository for future use when AWS resolves issue

**Alternative Solution**: Modify Agent Lambda to pass user context in tool parameters directly (bypassing Gateway Interceptor).

---

## Prerequisites Checklist

- [ ] AWS Account with Administrator access
- [ ] AWS CLI installed and configured
- [ ] Python 3.12 runtime available
- [ ] S3 bucket for deployment artifacts (must be in same region as deployment)
- [ ] Lambda deployment packages built
- [ ] jq installed for JSON processing (optional but recommended)

---

# Phase 1: CloudFormation Deployment

## Step 1: Prepare Lambda Deployment Packages

⚠️ **Critical**: Use the provided build scripts to ensure correct package structure and dependencies.

### Build Agent Lambda Package

The Agent Lambda uses Strands Framework and requires all dependencies:

```bash
# Run the build script
./rebuild_agent_lambda.sh
```

This creates `agent-lambda.zip` with:
- All source code from `src/`
- All dependencies from `requirements.txt`
- Correct handler path: `agent.lambda_handler.lambda_handler`

### Build Tool Lambda Package

The Tool Lambda requires directory structure preservation for relative imports:

```bash
# Run the build script
./rebuild_tool_lambda.sh
```

This creates `tool-lambda.zip` with:
- `tools/` directory with all tool modules
- `models/` directory with data models
- `config/` directory with configuration
- Correct handler path: `tools.lambda_handler.lambda_handler`

**Note**: The build scripts handle all dependency installation and directory structure automatically.

## Step 2: Create S3 Bucket and Upload Artifacts

**Important**: The S3 bucket must be in the **same AWS region** where you plan to deploy the CloudFormation stack.

**Critical**: You MUST upload both Lambda packages AND CloudFormation templates to S3 before deploying the stack.

```bash
# Set variables - IMPORTANT: Bucket region must match deployment region
export DEPLOYMENT_BUCKET="your-account-id-agentcore-region"
export AWS_REGION="eu-west-1"  # Change to your region

# Create S3 bucket in the deployment region (if not already created)
aws s3 mb s3://${DEPLOYMENT_BUCKET} --region ${AWS_REGION}

# Upload Lambda packages (REQUIRED)
aws s3 cp agent-lambda.zip s3://${DEPLOYMENT_BUCKET}/agent-lambda.zip --region ${AWS_REGION}
aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/tool-lambda.zip --region ${AWS_REGION}

# Upload CloudFormation templates (REQUIRED)
aws s3 cp cloudformation/vpc-networking.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/vpc-networking.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/tool-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/tool-lambda.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/agent-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/agent-lambda.yaml --region ${AWS_REGION}

# Verify all files are uploaded
aws s3 ls s3://${DEPLOYMENT_BUCKET}/ --recursive --region ${AWS_REGION}
```

**Expected output**: You should see 3 CloudFormation templates and 2 Lambda zip files listed.

## Step 3: Configure Deployment Parameters

Copy the example parameters file and customize:

Edit `parameters.json` and update:
- `LambdaCodeBucket` - Your S3 bucket name (e.g., "581571671018-agentcore-eu-west-1")
- `Environment` - dev, staging, or prod
- Other parameters as needed

```bash
cp cloudformation/parameters.json.example cloudformation/parameters.json
```


## Step 4: Deploy CloudFormation Stack

**Important**: This deploys VPC and Lambda functions only. Gateway will be created manually in Phase 2.

```bash
aws cloudformation create-stack \
  --stack-name serverless-ai-agent-dev \
  --template-body file://cloudformation/master.yaml \
  --parameters file://cloudformation/parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${AWS_REGION}
```

**Note**: Using `--template-body file://` is recommended to avoid S3 caching issues.

## Step 5: Monitor Deployment

```bash
# Watch stack creation progress
aws cloudformation wait stack-create-complete \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# View stack events
aws cloudformation describe-stack-events \
  --stack-name serverless-ai-agent-dev \
  --max-items 20 \
  --region ${AWS_REGION}
```

## Step 6: Retrieve Stack Outputs

```bash
# Get all outputs
aws cloudformation describe-stacks \
  --stack-name serverless-ai-agent-dev \
  --query 'Stacks[0].Outputs' \
  --output table \
  --region ${AWS_REGION}

# Get specific outputs and save them
export AGENT_FUNCTION_NAME=$(aws cloudformation describe-stacks --stack-name serverless-ai-agent-dev --query 'Stacks[0].Outputs[?OutputKey==`AgentFunctionName`].OutputValue' --output text --region ${AWS_REGION})

export TOOL_FUNCTION_ARN=$(aws cloudformation describe-stacks --stack-name serverless-ai-agent-dev --query 'Stacks[0].Outputs[?OutputKey==`ToolFunctionArn`].OutputValue' --output text --region ${AWS_REGION})

echo "Agent Function Name: ${AGENT_FUNCTION_NAME}"
echo "Tool Function ARN: ${TOOL_FUNCTION_ARN}"
```

**✅ Phase 1 Complete!** CloudFormation stack is deployed with VPC and Lambda functions.

---

# Phase 2: Manual AgentCore Setup

⚠️ **Critical Phase**: You must now manually create AgentCore Gateway and Memory resources since they're not available in CloudFormation.

## Step 7: Create AgentCore Gateway (Required)

⚠️ **Important**: AgentCore Gateway is **only available via AWS Console**. The AWS CLI does not yet support this resource.

The Gateway is required for the Agent to invoke MCP tools via the Tool Lambda.

### Using AWS Console

1. **Navigate to Amazon Bedrock Console**
   - Go to https://console.aws.amazon.com/bedrock/
   - Select your region (e.g., eu-west-2)

2. **Access AgentCore Gateway**
   - In the left navigation, find "AgentCore" section
   - Click on "Gateways"

3. **Create Gateway**
   - Click "Create gateway"
   - **Gateway name**: `ai-agent-mcp-gateway-dev` (use hyphens)
   - **Gateway type**: MCP Gateway
   - **Description**: "MCP Gateway for AI Agent Tool Execution"

4. **Configure Authentication** (Do this FIRST before adding target)
   - **Authentication type**: JWT
   - **JWT configuration**: Choose **"Quick create with Cognito - recommended"**
   - This will automatically create a new Cognito User Pool for the Gateway
   - **Save the User Pool ID** that gets created (e.g., `eu-west-2_BjwwPBfr9`)

5. **Configure Target**
   - **Target type**: Lambda function
   - **Lambda function ARN**: Paste your `${TOOL_FUNCTION_ARN}` from Step 6
   - **Invocation type**: Request-Response
   - **Schema**: Define an inline schema
   - **Inline schema**: Paste this MCP tool schema:
   ```json
   [
     {
       "name": "list_s3_buckets",
       "description": "Lists all S3 buckets accessible to the user",
       "inputSchema": {
         "type": "object",
         "properties": {
           "user_context": {
             "type": "object",
             "description": "User context information from JWT token"
           }
         },
         "required": []
       }
     }
   ]
   ```

6. **Create Gateway**
   - Click "Create"
   - Wait for gateway creation to complete

7. **Save Gateway Information**
   - Copy the **Gateway ID** (e.g., `ai-agent-mcp-gateway-dev-hlgqg8fahq`)
   - Copy the **Gateway URL** (e.g., `https://ai-agent-mcp-gateway-dev-hlgqg8fahq.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp`)
   - Save them as environment variables:
   ```bash
   export GATEWAY_ID="<your-gateway-id-here>"
   export GATEWAY_URL="<your-gateway-url-here>"
   echo "Gateway ID: ${GATEWAY_ID}"
   echo "Gateway URL: ${GATEWAY_URL}"
   ```

8. **Grant Gateway Permission to Invoke Lambda**
   ```bash
   # Get AWS Account ID
   export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   
   # Verify Tool Function ARN is set
   echo "Tool Function ARN: ${TOOL_FUNCTION_ARN}"
   
   # Grant permission
   aws lambda add-permission \
     --function-name "${TOOL_FUNCTION_ARN}" \
     --statement-id AllowBedrockGatewayInvoke \
     --action lambda:InvokeFunction \
     --principal bedrock.amazonaws.com \
     --source-arn "arn:aws:bedrock:${AWS_REGION}:${AWS_ACCOUNT_ID}:gateway/${GATEWAY_ID}" \
     --region ${AWS_REGION}
   ```

**✅ Phase 2 Complete!** AgentCore Gateway is created with Cognito authentication.

---

# Phase 3: Connect Everything Together

## Step 9: Update Agent Lambda Configuration

Now connect the Agent Lambda to the Gateway you just created.

```bash
# Set Gateway User Pool ID (from Step 7)
export GATEWAY_USER_POOL_ID="<paste-user-pool-id-from-gateway>"

# Calculate JWKS URL
export JWKS_URL="https://cognito-idp.${AWS_REGION}.amazonaws.com/${GATEWAY_USER_POOL_ID}/.well-known/jwks.json"

# Verify all required variables are set
echo "Verifying required variables..."
echo "AGENT_FUNCTION_NAME: ${AGENT_FUNCTION_NAME}"
echo "JWKS_URL: ${JWKS_URL}"
echo "GATEWAY_URL: ${GATEWAY_URL}"
echo "AWS_REGION: ${AWS_REGION}"

# If AGENT_FUNCTION_NAME is empty, retrieve it
if [ -z "${AGENT_FUNCTION_NAME}" ]; then
  export AGENT_FUNCTION_NAME=$(aws cloudformation describe-stacks --stack-name serverless-ai-agent-dev --query 'Stacks[0].Outputs[?OutputKey==`AgentFunctionName`].OutputValue' --output text --region ${AWS_REGION})
  echo "Agent Function Name: ${AGENT_FUNCTION_NAME}"
fi

# Create environment configuration JSON
cat > lambda-env.json <<'EOF'
{
  "Variables": {
    "COGNITO_JWKS_URL": "PLACEHOLDER_JWKS_URL",
    "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
    "AGENTCORE_GATEWAY_URL": "PLACEHOLDER_GATEWAY_URL",
    "AGENTCORE_MEMORY_ID": "DISABLED",
    "SESSION_TIMEOUT_MINUTES": "60",
    "MAX_CONTEXT_TOKENS": "4000",
    "LOG_LEVEL": "INFO"
  }
}
EOF

# Replace placeholders with actual values
sed -i.bak "s|PLACEHOLDER_JWKS_URL|${JWKS_URL}|g" lambda-env.json
sed -i.bak "s|PLACEHOLDER_GATEWAY_URL|${GATEWAY_URL}|g" lambda-env.json

# Verify the JSON file
echo "Environment configuration:"
cat lambda-env.json

# Update the Lambda function
aws lambda update-function-configuration \
  --function-name "${AGENT_FUNCTION_NAME}" \
  --environment file://lambda-env.json \
  --region ${AWS_REGION}

# Confirm success
echo "✅ Agent Lambda updated with Gateway configuration!"

# Verify the configuration was applied
aws lambda get-function-configuration \
  --function-name "${AGENT_FUNCTION_NAME}" \
  --query 'Environment.Variables' \
  --region ${AWS_REGION}
```

**Note**: Memory is disabled by default (`AGENTCORE_MEMORY_ID=DISABLED`). The system works in stateless mode.

**✅ Phase 3 Complete!** All components are connected.

---

# Testing and Verification

## Step 10: Create Test User

⚠️ **Important**: Use the User Pool that was created by the Gateway (from Step 7).

```bash
# Set the Gateway's User Pool ID (from Step 7)
export GATEWAY_USER_POOL_ID="<paste-user-pool-id-from-gateway-creation>"

# Get the User Pool Client ID
export GATEWAY_CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id ${GATEWAY_USER_POOL_ID} --region ${AWS_REGION} --query 'UserPoolClients[0].ClientId' --output text)

echo "Gateway Client ID: ${GATEWAY_CLIENT_ID}"

# Create a test user
aws cognito-idp admin-create-user \
  --user-pool-id ${GATEWAY_USER_POOL_ID} \
  --username testuser@example.com \
  --user-attributes Name=email,Value=testuser@example.com \
  --temporary-password 'TempPassword123!' \
  --message-action SUPPRESS \
  --region ${AWS_REGION}

# Set permanent password
aws cognito-idp admin-set-user-password \
  --user-pool-id ${GATEWAY_USER_POOL_ID} \
  --username testuser@example.com \
  --password 'SecurePassword123!' \
  --permanent \
  --region ${AWS_REGION}

echo "✅ Test user created: testuser@example.com"
```

## Step 11: Test Authentication

The Gateway's Cognito User Pool Client has a secret, so we need to calculate the SECRET_HASH. Here's a Python script to handle authentication:

```bash
# First, get the client secret
export GATEWAY_CLIENT_SECRET=$(aws cognito-idp describe-user-pool-client --user-pool-id ${GATEWAY_USER_POOL_ID} --client-id ${GATEWAY_CLIENT_ID} --region ${AWS_REGION} --query 'UserPoolClient.ClientSecret' --output text)

# Enable the ADMIN_NO_SRP_AUTH flow on the client (required for testing)
echo "Enabling ADMIN_NO_SRP_AUTH flow on Cognito client..."
aws cognito-idp update-user-pool-client --user-pool-id ${GATEWAY_USER_POOL_ID} --client-id ${GATEWAY_CLIENT_ID} --explicit-auth-flows ALLOW_ADMIN_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH --region ${AWS_REGION}

# Create a Python script to authenticate with SECRET_HASH
cat > get_jwt_token.py << 'EOF'
import boto3
import hmac
import hashlib
import base64
import sys
import os

def calculate_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

# Get values from environment variables
user_pool_id = os.environ.get('GATEWAY_USER_POOL_ID')
client_id = os.environ.get('GATEWAY_CLIENT_ID')
client_secret = os.environ.get('GATEWAY_CLIENT_SECRET')
region = os.environ.get('AWS_REGION')
username = 'testuser@example.com'
password = 'SecurePassword123!'

if not all([user_pool_id, client_id, client_secret, region]):
    print("Error: Missing required environment variables", file=sys.stderr)
    sys.exit(1)

# Calculate SECRET_HASH
secret_hash = calculate_secret_hash(username, client_id, client_secret)

# Authenticate
client = boto3.client('cognito-idp', region_name=region)

try:
    response = client.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        AuthFlow='ADMIN_NO_SRP_AUTH',
        AuthParameters={
            'USERNAME': username,
            'PASSWORD': password,
            'SECRET_HASH': secret_hash
        }
    )
    
    access_token = response['AuthenticationResult']['AccessToken']
    print(access_token)
    
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF

# Run the script and save the token
python3 get_jwt_token.py > jwt_token.txt

export JWT_TOKEN=$(cat jwt_token.txt)
echo "✅ JWT Token obtained successfully"
echo "Token (first 50 chars): ${JWT_TOKEN:0:50}..."
```

## Step 12: Test Agent Lambda

```bash
# Create test event
cat > test-event.json << 'EOF'
{
  "prompt": "List my S3 buckets",
  "jwt_token": "PLACEHOLDER_TOKEN",
  "session_id": null
}
EOF

# Replace the placeholder with the actual token
sed -i.bak "s|PLACEHOLDER_TOKEN|${JWT_TOKEN}|g" test-event.json

# Invoke Agent Lambda
aws lambda invoke \
  --function-name "${AGENT_FUNCTION_NAME}" \
  --payload file://test-event.json \
  --cli-binary-format raw-in-base64-out \
  --region ${AWS_REGION} \
  response.json

# View response
cat response.json | jq '.body' | jq -r '.' | jq '.'
```

**Expected Response**: You should see a JSON response with the agent's reply listing your S3 buckets.

**Note on User Context**: The Tool Lambda will show `user_id: "unknown"` because the Gateway strips user context. However, user context IS available in the Agent Lambda and Agent response. See "Known Limitation" section above for details.

## Step 13: Test Multi-Turn Conversation (If Memory Enabled)

If you enabled Memory, you can test conversation continuity:

```bash
# First turn - get session ID
cat > test-event-1.json << EOF
{
  "prompt": "My name is Alice",
  "jwt_token": "${JWT_TOKEN}",
  "session_id": null
}
EOF

aws lambda invoke \
  --function-name ${AGENT_FUNCTION_NAME} \
  --payload file://test-event-1.json \
  --cli-binary-format raw-in-base64-out \
  --region ${AWS_REGION} \
  response-1.json

# Extract session ID
export SESSION_ID=$(cat response-1.json | jq -r '.body' | jq -r '.session_id')

# Second turn - test memory
cat > test-event-2.json << EOF
{
  "prompt": "What is my name?",
  "jwt_token": "${JWT_TOKEN}",
  "session_id": "${SESSION_ID}"
}
EOF

aws lambda invoke \
  --function-name ${AGENT_FUNCTION_NAME} \
  --payload file://test-event-2.json \
  --cli-binary-format raw-in-base64-out \
  --region ${AWS_REGION} \
  response-2.json

cat response-2.json | jq '.body' | jq -r '.' | jq '.'
```

**Expected Response**: The agent should remember your name is Alice.

**✅ Deployment Complete!** Your Serverless AI Agent System with Strands Framework is fully operational.

---

# Monitoring and Debugging

## View CloudWatch Logs

```bash
# Get log group name
export AGENT_LOG_GROUP="/aws/lambda/${AGENT_FUNCTION_NAME}"

# Tail Agent Lambda logs
aws logs tail ${AGENT_LOG_GROUP} --follow --region ${AWS_REGION}
```

## Check Stack Resources

```bash
# List all resources in the stack
aws cloudformation describe-stack-resources \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# Check nested stacks
aws cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE \
  --query 'StackSummaries[?contains(StackName, `serverless-ai-agent-dev`)].StackName' \
  --region ${AWS_REGION}
```

## Verify Lambda Configuration

```bash
# Check Agent Lambda environment variables
aws lambda get-function-configuration \
  --function-name ${AGENT_FUNCTION_NAME} \
  --query 'Environment.Variables' \
  --region ${AWS_REGION}

# Check Tool Lambda resource policy
aws lambda get-policy \
  --function-name ${TOOL_FUNCTION_ARN} \
  --region ${AWS_REGION}
```

---

# Updating the System

## Update Lambda Code

```bash
# Rebuild and upload Lambda packages
aws s3 cp agent-lambda.zip s3://${DEPLOYMENT_BUCKET}/agent-lambda.zip
aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/tool-lambda.zip

# Update Lambda functions
aws lambda update-function-code \
  --function-name ${AGENT_FUNCTION_NAME} \
  --s3-bucket ${DEPLOYMENT_BUCKET} \
  --s3-key agent-lambda.zip \
  --region ${AWS_REGION}
```

## Update Stack Configuration

```bash
# Upload updated templates
aws s3 sync cloudformation/ s3://${DEPLOYMENT_BUCKET}/cloudformation/ \
  --exclude "*.md" \
  --exclude "*.example" \
  --region ${AWS_REGION}

# Create change set
aws cloudformation create-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name update-$(date +%Y%m%d-%H%M%S) \
  --template-body file://cloudformation/master.yaml \
  --parameters file://cloudformation/parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${AWS_REGION}

# Review changes
aws cloudformation describe-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name <change-set-name> \
  --region ${AWS_REGION}

# Execute change set
aws cloudformation execute-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name <change-set-name> \
  --region ${AWS_REGION}
```

---

# Troubleshooting

## Common Issues

### 1. S3 Access Denied When Creating CognitoStack

**Error**: `S3 error: Access Denied` when creating CognitoStack or other nested stacks

**Solution**: CloudFormation templates must be uploaded to S3 before stack creation:
```bash
# Upload all CloudFormation templates to S3
aws s3 cp cloudformation/cognito.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/cognito.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/vpc-networking.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/vpc-networking.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/tool-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/tool-lambda.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/agent-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/agent-lambda.yaml --region ${AWS_REGION}
```

### 2. Lambda Function Creation Fails - NoSuchKey

**Error**: `S3 Error Code: NoSuchKey. S3 Error Message: The specified key does not exist` when creating Lambda functions

**Solution**: Lambda deployment packages must be uploaded to S3:
```bash
# Upload Lambda packages
aws s3 cp agent-lambda.zip s3://${DEPLOYMENT_BUCKET}/agent-lambda.zip --region ${AWS_REGION}
aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/tool-lambda.zip --region ${AWS_REGION}
```

### 3. AWS::Bedrock::Gateway or AWS::Bedrock::Memory Not Recognized

**Error**: `Template format error: Unrecognized resource types: [AWS::Bedrock::Gateway]` or `[AWS::Bedrock::Memory]`

**Solution**: This should NOT happen with the updated templates. Both are commented out in master.yaml. If you see this:
1. Make sure you're using the latest master.yaml template
2. Upload the latest templates to S3
3. Use `--template-body file://cloudformation/master.yaml` instead of `--template-url`

### 4. S3 Bucket Region Mismatch

**Error**: `S3 error: The bucket you are attempting to access must be addressed using the specified endpoint`

**Solution**: Your S3 bucket must be in the same region as your CloudFormation deployment.
```bash
# Create a new bucket in the correct region
aws s3 mb s3://your-bucket-name-${AWS_REGION} --region ${AWS_REGION}

# Update your DEPLOYMENT_BUCKET variable
export DEPLOYMENT_BUCKET="your-bucket-name-${AWS_REGION}"

# Re-upload all artifacts to the new bucket
aws s3 cp agent-lambda.zip s3://${DEPLOYMENT_BUCKET}/agent-lambda.zip --region ${AWS_REGION}
aws s3 cp tool-lambda.zip s3://${DEPLOYMENT_BUCKET}/tool-lambda.zip --region ${AWS_REGION}
aws s3 cp cloudformation/cognito.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/cognito.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/vpc-networking.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/vpc-networking.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/tool-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/tool-lambda.yaml --region ${AWS_REGION}
aws s3 cp cloudformation/agent-lambda.yaml s3://${DEPLOYMENT_BUCKET}/cloudformation/agent-lambda.yaml --region ${AWS_REGION}
```

### 5. Stack Creation Fails - Need to Delete and Recreate

**Error**: Stack is in CREATE_FAILED state after fixing issues

**Solution**: Delete the failed stack and recreate it:
```bash
# Delete the failed stack
aws cloudformation delete-stack \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# Wait for deletion to complete (2-3 minutes)
aws cloudformation wait stack-delete-complete \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# Recreate the stack
aws cloudformation create-stack \
  --stack-name serverless-ai-agent-dev \
  --template-body file://cloudformation/master.yaml \
  --parameters file://cloudformation/parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${AWS_REGION}
```

### 6. Agent Lambda Fails with "Gateway URL not configured"

**Error**: Agent Lambda returns error about missing Gateway URL

**Solution**: Make sure you completed Step 9 to update the Agent Lambda environment variables:
```bash
aws lambda get-function-configuration \
  --function-name ${AGENT_FUNCTION_NAME} \
  --query 'Environment.Variables.AGENTCORE_GATEWAY_URL' \
  --region ${AWS_REGION}
```

If it shows "PLACEHOLDER", run Step 9 again with the correct Gateway URL.

### 7. Gateway Cannot Invoke Tool Lambda

**Error**: Gateway returns permission error when trying to invoke Tool Lambda

**Solution**: Verify the Lambda resource policy allows Bedrock Gateway:
```bash
aws lambda get-policy --function-name "${TOOL_FUNCTION_ARN}" --region ${AWS_REGION}
```

If missing, add the permission:
```bash
# First ensure TOOL_FUNCTION_ARN is set
export TOOL_FUNCTION_ARN=$(aws cloudformation describe-stacks --stack-name serverless-ai-agent-dev --query 'Stacks[0].Outputs[?OutputKey==`ToolFunctionArn`].OutputValue' --output text --region ${AWS_REGION})

# Get AWS Account ID to avoid nested command substitution
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Then add the permission
aws lambda add-permission \
  --function-name "${TOOL_FUNCTION_ARN}" \
  --statement-id AllowBedrockGatewayInvoke \
  --action lambda:InvokeFunction \
  --principal bedrock.amazonaws.com \
  --source-arn "arn:aws:bedrock:${AWS_REGION}:${AWS_ACCOUNT_ID}:gateway/${GATEWAY_ID}" \
  --region ${AWS_REGION}
```

### 8. JWT Token Validation Fails

**Error**: Gateway rejects JWT tokens

**Solution**: Verify JWKS URL is accessible and Cognito User Pool ID is correct:
```bash
curl ${JWKS_URL}
```

### 9. Memory Not Persisting Conversations

**Error**: Agent doesn't remember previous messages

**Solution**: 
1. Verify Memory ID is set in Agent Lambda environment variables
2. Check that you're passing the same `session_id` in subsequent requests
3. Verify Agent Lambda IAM role has Bedrock Memory permissions

### 10. Circular Dependency Errors

**Error**: `Circular dependency between resources`

**Solution**: This has been fixed in the updated templates. Upload the latest templates to S3.

### 11. IAM Role Already Exists

**Error**: `Role with name X already exists`

**Solution**: This has been fixed by removing explicit role names. If you still encounter this, delete the failed stack completely before redeploying.

---

# Cleanup

## Delete All Resources

```bash
# Delete CloudFormation stack
aws cloudformation delete-stack \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name serverless-ai-agent-dev \
  --region ${AWS_REGION}

# Delete AgentCore Gateway
aws bedrock delete-gateway \
  --gateway-id ${GATEWAY_ID} \
  --region ${AWS_REGION}

# Delete AgentCore Memory
aws bedrock delete-memory \
  --memory-id ${MEMORY_ID} \
  --region ${AWS_REGION}

# Clean up S3 bucket
aws s3 rm s3://${DEPLOYMENT_BUCKET} --recursive
aws s3 rb s3://${DEPLOYMENT_BUCKET}
```

---

# Summary of Deployed Resources

After completing this guide, you will have:

✅ **CloudFormation Stack** (Phase 1)
- VPC with private subnets and S3 endpoint
- Tool Lambda (VPC-attached) for MCP tool execution
- Agent Lambda (public) for AI agent orchestration

✅ **AgentCore Resources** (Phase 2)
- AgentCore Gateway for MCP tool invocation
- Cognito User Pool for JWT authentication (created by Gateway)

✅ **Integration** (Phase 3)
- Agent Lambda configured with Gateway URL and Cognito JWKS URL
- Gateway configured to invoke Tool Lambda
- JWT authentication end-to-end

✅ **Functionality**
- User authentication via Cognito JWT tokens
- User context extraction (user_id, username, client_id) in Agent Lambda
- AI agent with Bedrock Claude 3 Sonnet
- Dynamic tool discovery via AgentCore Gateway
- Tool execution (S3 list buckets)
- Audit logging with user attribution in Agent Lambda
- Error handling and retry logic

⚠️ **Known Limitation**
- Tool Lambda receives `user_id: "unknown"` (Gateway strips user context)
- User context IS available in Agent Lambda and responses
- Gateway Interceptor feature attempted but causes 500 errors
- See INTERCEPTOR_TROUBLESHOOTING.md for investigation details

---

# Cost Estimation

Approximate monthly costs for dev environment:

- **Lambda**: $5-20 (based on invocations)
- **Bedrock**: $10-50 (based on token usage)
- **Cognito**: $0-5 (first 50,000 MAUs free)
- **VPC**: $0 (Gateway endpoint is free)
- **CloudWatch**: $5-10 (logs and metrics)
- **AgentCore Gateway**: Variable (based on usage)
- **AgentCore Memory**: Variable (based on storage)

**Total**: ~$20-100/month for dev environment

Production costs will scale with usage.

---

# Best Practices

1. **Use Parameter Files** - Store configuration in version control
2. **Tag Resources** - Use consistent tagging for cost tracking
3. **Enable CloudTrail** - Audit all API calls
4. **Set Up Alarms** - Monitor Lambda errors and throttling
5. **Use Secrets Manager** - Store sensitive configuration
6. **Enable X-Ray** - Trace requests through the system
7. **Implement CI/CD** - Automate deployments
8. **Test in Dev First** - Always test changes in dev environment

---

# Next Steps

After successful deployment:

1. Configure additional users in Cognito
2. Implement additional MCP tools
3. Set up monitoring and alerting
4. Configure backup and disaster recovery
5. Implement CI/CD pipeline
6. Conduct security review
7. Perform load testing
8. Document operational procedures

---

# Support and Resources

- [AWS CloudFormation Documentation](https://docs.aws.amazon.com/cloudformation/)
- [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Strands Framework Documentation](https://docs.strands.ai/)


---

# Additional Notes

## Gateway Interceptor Status

**Feature**: Gateway Request Interceptor for user context propagation  
**Status**: ⚠️ Not working - causes Gateway 500 errors  
**Investigation**: See `INTERCEPTOR_TROUBLESHOOTING.md` for full details

**What was attempted**:
- Created interceptor Lambda to extract JWT claims
- Attached interceptor to Gateway
- Tested with both complex and minimal interceptors

**Result**: Gateway returns 500 errors when interceptor is attached, even though:
- Interceptor Lambda has correct permissions
- Interceptor code follows AWS documentation
- Gateway status shows READY
- Interceptor Lambda is NEVER invoked (no logs)

**Workaround**: System works perfectly WITHOUT interceptor. User context is available in Agent Lambda and responses, just not in Tool Lambda.

**Next Steps**: 
- Open AWS Support case to investigate Gateway Interceptor issue
- Consider alternative approaches if needed for tool-level user operations
- Monitor AWS service updates for fixes

## Production Deployment Status

**Date**: January 27, 2026  
**Region**: eu-west-1  
**Status**: ✅ Production Ready

The system is fully operational and ready for production use. The only limitation is that Tool Lambda doesn't receive user context, but this doesn't prevent the system from functioning correctly for most use cases.

## Test Results

**Test Prompt**: "List my S3 buckets"

**Result**: ✅ SUCCESS
```json
{
  "response": "Successfully listed 27 S3 buckets",
  "user_context": {
    "user_id": "6255d4b4-7091-7021-e4e4-b8f2e5c43d97",
    "username": "testuser@example.com",
    "client_id": "2co4da073qrhr0fsk07gusjauc"
  },
  "tool_executions": [{
    "tool_name": "target-quick-start-0bc241___list_s3_buckets",
    "status": "success",
    "duration_ms": 1885
  }]
}
```

---

**End of Deployment Guide**

