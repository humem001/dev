# CloudFormation Templates for Serverless AI Agent System

This directory contains AWS CloudFormation templates for deploying the Serverless AI Agent System infrastructure.

## Architecture Overview

The system consists of the following components:

1. **Cognito User Pool** - OAuth2 authentication and JWT token generation
2. **VPC and Networking** - Private subnets with S3 VPC Gateway endpoint
3. **AgentCore Memory** - Persistent conversation context storage
4. **Tool Lambda** - MCP tool implementation (VPC-attached)
5. **AgentCore Gateway** - MCP gateway for tool orchestration
6. **Agent Lambda** - Strands Framework AI agent (public)

## Template Files

### Individual Component Templates

- `cognito.yaml` - Cognito User Pool and App Client
- `vpc-networking.yaml` - VPC, subnets, and S3 VPC Gateway endpoint
- `agentcore-memory.yaml` - AgentCore Memory resource
- `tool-lambda.yaml` - MCP Tool Lambda function (VPC-attached)
- `agentcore-gateway.yaml` - AgentCore Gateway with JWT authentication
- `agent-lambda.yaml` - Agent Lambda function (Strands Framework)

### Master Template

- `master.yaml` - Orchestrates deployment of all components

## Deployment

### Prerequisites

1. **AWS Account** with appropriate permissions
2. **S3 Bucket** for Lambda deployment packages and templates
3. **Lambda Deployment Packages**:
   - `agent-lambda.zip` - Agent Lambda code
   - `tool-lambda.zip` - Tool Lambda code

### Upload Templates and Code

```bash
# Set your S3 bucket name
BUCKET_NAME="your-deployment-bucket"
REGION="us-east-1"

# Upload CloudFormation templates
aws s3 cp cognito.yaml s3://${BUCKET_NAME}/cloudformation/cognito.yaml
aws s3 cp vpc-networking.yaml s3://${BUCKET_NAME}/cloudformation/vpc-networking.yaml
aws s3 cp agentcore-memory.yaml s3://${BUCKET_NAME}/cloudformation/agentcore-memory.yaml
aws s3 cp tool-lambda.yaml s3://${BUCKET_NAME}/cloudformation/tool-lambda.yaml
aws s3 cp agentcore-gateway.yaml s3://${BUCKET_NAME}/cloudformation/agentcore-gateway.yaml
aws s3 cp agent-lambda.yaml s3://${BUCKET_NAME}/cloudformation/agent-lambda.yaml
aws s3 cp master.yaml s3://${BUCKET_NAME}/cloudformation/master.yaml

# Upload Lambda deployment packages
aws s3 cp ../agent-lambda.zip s3://${BUCKET_NAME}/agent-lambda.zip
aws s3 cp ../tool-lambda.zip s3://${BUCKET_NAME}/tool-lambda.zip
```

### Deploy Master Stack

```bash
# Deploy the master stack
aws cloudformation create-stack \
  --stack-name serverless-ai-agent-dev \
  --template-url https://${BUCKET_NAME}.s3.${REGION}.amazonaws.com/cloudformation/master.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=dev \
    ParameterKey=LambdaCodeBucket,ParameterValue=${BUCKET_NAME} \
    ParameterKey=BedrockModelId,ParameterValue=anthropic.claude-3-sonnet-20240229-v1:0 \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${REGION}

# Monitor stack creation
aws cloudformation wait stack-create-complete \
  --stack-name serverless-ai-agent-dev \
  --region ${REGION}

# Get stack outputs
aws cloudformation describe-stacks \
  --stack-name serverless-ai-agent-dev \
  --query 'Stacks[0].Outputs' \
  --region ${REGION}
```

### Deploy Individual Components

You can also deploy components individually for testing or updates:

```bash
# Deploy Cognito stack
aws cloudformation create-stack \
  --stack-name ai-agent-cognito-dev \
  --template-body file://cognito.yaml \
  --parameters \
    ParameterKey=UserPoolName,ParameterValue=ai-agent-user-pool-dev \
  --region ${REGION}

# Deploy VPC stack
aws cloudformation create-stack \
  --stack-name ai-agent-vpc-dev \
  --template-body file://vpc-networking.yaml \
  --region ${REGION}

# And so on...
```

## Configuration Parameters

### Master Template Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Environment | dev | Environment name (dev/staging/prod) |
| UserPoolName | ai-agent-user-pool | Cognito User Pool name |
| TokenExpirationMinutes | 60 | JWT token expiration time |
| VpcCidr | 10.0.0.0/16 | VPC CIDR block |
| PrivateSubnet1Cidr | 10.0.1.0/24 | Private subnet 1 CIDR |
| PrivateSubnet2Cidr | 10.0.2.0/24 | Private subnet 2 CIDR |
| LambdaCodeBucket | (required) | S3 bucket for Lambda code |
| AgentLambdaCodeKey | agent-lambda.zip | Agent Lambda S3 key |
| ToolLambdaCodeKey | tool-lambda.zip | Tool Lambda S3 key |
| BedrockModelId | anthropic.claude-3-sonnet-20240229-v1:0 | Bedrock model ID |
| MemoryName | ai-agent-memory | AgentCore Memory name |
| SessionTimeoutMinutes | 60 | Session timeout |
| MaxContextTokens | 4000 | Max context size |
| MaxMessagesPerSession | 100 | Max messages per session |
| GatewayName | ai-agent-mcp-gateway | Gateway name |

## Stack Outputs

After deployment, the master stack provides the following outputs:

### Authentication
- `UserPoolId` - Cognito User Pool ID
- `UserPoolClientId` - Cognito App Client ID
- `JWKSUrl` - JWKS URL for JWT validation

### Infrastructure
- `VpcId` - VPC ID
- `MemoryId` - AgentCore Memory ID
- `GatewayUrl` - AgentCore Gateway URL
- `GatewayId` - AgentCore Gateway ID

### Lambda Functions
- `AgentFunctionArn` - Agent Lambda ARN
- `AgentFunctionName` - Agent Lambda name
- `ToolFunctionArn` - Tool Lambda ARN
- `ToolFunctionName` - Tool Lambda name

### Deployment Info
- `Region` - AWS Region
- `Environment` - Environment name
- `StackName` - Master stack name

## Network Architecture

### Agent Lambda (No VPC)
- Deployed outside VPC for public internet access
- Requires access to Cognito JWKS endpoint (public)
- Accesses AgentCore Memory via AWS API
- Invokes AgentCore Gateway via HTTPS

### Tool Lambda (VPC-Attached)
- Deployed in private subnets
- Accesses S3 through VPC Gateway endpoint
- No public internet access
- Invoked by AgentCore Gateway via IAM

### VPC Gateway Endpoint
- Cost-effective S3 access (no data transfer charges)
- Private connectivity within AWS network
- Configured in route tables for private subnets

## IAM Permissions

### Agent Lambda Role
- `bedrock:InvokeModel` - Claude model inference
- `bedrock:*MemorySession*` - AgentCore Memory operations
- `logs:*` - CloudWatch logging

### Tool Lambda Role
- `s3:ListAllMyBuckets` - S3 bucket listing
- `s3:GetBucketLocation` - S3 bucket location
- `logs:*` - CloudWatch logging
- VPC execution permissions

### Gateway Role
- `lambda:InvokeFunction` - Invoke Tool Lambda

## Validation

### Validate Templates

```bash
# Validate master template
aws cloudformation validate-template \
  --template-body file://master.yaml

# Validate individual templates
aws cloudformation validate-template \
  --template-body file://cognito.yaml

aws cloudformation validate-template \
  --template-body file://vpc-networking.yaml

# And so on...
```

### Test Deployment

```bash
# Create change set to preview changes
aws cloudformation create-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name test-changes \
  --template-url https://${BUCKET_NAME}.s3.${REGION}.amazonaws.com/cloudformation/master.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM

# Review change set
aws cloudformation describe-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name test-changes

# Execute or delete change set
aws cloudformation execute-change-set \
  --stack-name serverless-ai-agent-dev \
  --change-set-name test-changes
```

## Cleanup

### Delete Stack

```bash
# Delete master stack (deletes all nested stacks)
aws cloudformation delete-stack \
  --stack-name serverless-ai-agent-dev \
  --region ${REGION}

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete \
  --stack-name serverless-ai-agent-dev \
  --region ${REGION}
```

### Manual Cleanup

Some resources may require manual cleanup:
- S3 buckets (if created)
- CloudWatch log groups (if retention is set)
- VPC endpoints (if not deleted automatically)

## Troubleshooting

### Common Issues

1. **Stack Creation Fails**
   - Check CloudFormation events for error details
   - Verify IAM permissions
   - Ensure S3 bucket and Lambda packages exist

2. **Lambda Function Errors**
   - Check CloudWatch logs
   - Verify environment variables
   - Test Lambda functions individually

3. **VPC Connectivity Issues**
   - Verify VPC endpoint configuration
   - Check security group rules
   - Ensure route tables are configured correctly

4. **Authentication Failures**
   - Verify Cognito configuration
   - Check JWKS URL accessibility
   - Validate JWT token format

### Debug Commands

```bash
# Get stack events
aws cloudformation describe-stack-events \
  --stack-name serverless-ai-agent-dev \
  --max-items 20

# Get stack resources
aws cloudformation describe-stack-resources \
  --stack-name serverless-ai-agent-dev

# Get nested stack details
aws cloudformation describe-stacks \
  --stack-name <nested-stack-name>
```

## Security Considerations

1. **JWT Validation** - All components validate JWT tokens
2. **Multi-Tenant Isolation** - User context propagated throughout
3. **VPC Isolation** - Tool Lambda in private subnets
4. **IAM Least Privilege** - Minimal permissions for each role
5. **Encryption** - All communications use HTTPS/TLS
6. **Audit Logging** - CloudWatch logs for all operations

## Cost Optimization

1. **VPC Gateway Endpoint** - No data transfer charges for S3
2. **Lambda Memory** - Right-sized for workload
3. **CloudWatch Logs** - 30-day retention
4. **Cognito** - Pay per active user
5. **Bedrock** - Pay per token

## Support

For issues or questions:
1. Check CloudFormation events and logs
2. Review CloudWatch logs for Lambda functions
3. Verify IAM permissions and network configuration
4. Consult AWS documentation for service-specific issues
