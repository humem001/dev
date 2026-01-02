#!/bin/bash

# AgentCore Strands Deployment Script
# Usage: ./deploy.sh [env] [region]
# Example: ./deploy.sh dev eu-west-2

set -e

# Default values
ENV=${1:-dev}
REGION=${2:-eu-west-2}

echo "🚀 Deploying AgentCore Strands Stack"
echo "Environment: $ENV"
echo "Region: $REGION"
echo ""

# Validate environment
if [[ ! "$ENV" =~ ^(dev|prod)$ ]]; then
    echo "❌ Invalid environment. Use 'dev' or 'prod'"
    exit 1
fi

# Set CDK context and deploy
echo "📦 Installing dependencies..."
npm install

echo "🏗️  Deploying CDK stack..."
cdk deploy \
    --region $REGION \
    --context env=$ENV \
    --require-approval never

echo ""
echo "✅ Stack deployed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Note the stack outputs (User Pool ID, Client ID, Lambda ARNs)"
echo "2. Create a Cognito user with the credentials from Secrets Manager"
echo "3. Create the AgentCore Gateway:"
echo ""
echo "   # Get stack outputs"
echo "   aws cloudformation describe-stacks --stack-name AgentCoreStrandsStack-${ENV^} --region $REGION --query 'Stacks[0].Outputs'"
echo ""
echo "   # Create Gateway (replace placeholders with actual values)"
echo "   agentcore gateway create-mcp-gateway \\"
echo "     --name strands-gateway-$ENV \\"
echo "     --region $REGION \\"
echo "     --authorizer-config '{\"customJWTAuthorizer\": {\"allowedClients\": [\"<CLIENT_ID>\"], \"discoveryUrl\": \"https://cognito-idp.$REGION.amazonaws.com/<USER_POOL_ID>/.well-known/openid-configuration\"}}'"
echo ""
echo "4. Create Gateway target with the MCP Tool Lambda ARN"
echo "5. Test the system"