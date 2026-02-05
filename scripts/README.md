# Deployment and Configuration Scripts

This directory contains scripts for deploying and validating the Serverless AI Agent System.

## Scripts Overview

### 1. deploy.sh

Automated deployment script that handles the complete deployment process:
- Builds Lambda deployment packages
- Uploads artifacts to S3
- Deploys CloudFormation stack
- Displays deployment outputs

**Usage:**

```bash
# Basic deployment
./scripts/deploy.sh -s my-stack-name -b my-deployment-bucket

# Full deployment with custom region and environment
./scripts/deploy.sh \
  -s serverless-ai-agent-prod \
  -b my-deployment-bucket \
  -r us-west-2 \
  -e prod \
  -p cloudformation/parameters.json

# Skip building (use existing packages)
./scripts/deploy.sh -s my-stack-name -b my-bucket --skip-build

# Deploy without waiting for completion
./scripts/deploy.sh -s my-stack-name -b my-bucket --no-wait
```

**Options:**

- `-s, --stack-name NAME` - CloudFormation stack name (required)
- `-b, --bucket NAME` - S3 bucket for deployment artifacts (required)
- `-r, --region REGION` - AWS region (default: us-east-1)
- `-e, --environment ENV` - Environment: dev, staging, prod (default: dev)
- `-p, --parameters FILE` - Parameters JSON file (default: cloudformation/parameters.json)
- `--skip-build` - Skip Lambda package building
- `--skip-upload` - Skip S3 upload
- `--no-wait` - Don't wait for stack completion
- `-h, --help` - Show help message

**Prerequisites:**

- AWS CLI installed and configured
- Python 3.12 or later
- zip command available
- Valid AWS credentials with appropriate permissions

**Output:**

The script creates:
- `agent-lambda.zip` - Agent Lambda deployment package
- `tool-lambda.zip` - Tool Lambda deployment package
- `deployment-outputs-{stack-name}.json` - Stack outputs in JSON format

### 2. validate-config.sh

Configuration validation script that performs comprehensive checks:
- CloudFormation template validation
- IAM permissions verification
- VPC and network connectivity checks
- Cognito configuration validation
- Lambda function validation

**Usage:**

```bash
# Validate deployed stack
./scripts/validate-config.sh -s my-stack-name -r us-east-1

# Validate templates only (no deployed stack)
./scripts/validate-config.sh -b my-deployment-bucket -r us-east-1

# Skip specific validation categories
./scripts/validate-config.sh -s my-stack-name --skip-vpc --skip-cognito
```

**Options:**

- `-s, --stack-name NAME` - CloudFormation stack name (optional, for deployed stack validation)
- `-b, --bucket NAME` - S3 bucket for template validation (optional)
- `-r, --region REGION` - AWS region (default: us-east-1)
- `--skip-stack` - Skip stack validation
- `--skip-iam` - Skip IAM permissions validation
- `--skip-vpc` - Skip VPC connectivity validation
- `--skip-cognito` - Skip Cognito validation
- `-h, --help` - Show help message

**Validation Categories:**

1. **Prerequisites Check**
   - AWS CLI installation
   - Python 3 installation
   - AWS credentials validity

2. **CloudFormation Template Validation**
   - Validates all template files
   - Checks deployed stack status
   - Verifies template syntax

3. **IAM Permissions Validation**
   - CloudFormation permissions
   - S3 permissions
   - Lambda permissions
   - Cognito permissions
   - EC2 permissions (for VPC)
   - IAM permissions
   - Bedrock permissions

4. **VPC and Network Validation**
   - VPC existence
   - VPC endpoints status
   - S3 Gateway endpoint availability
   - Subnet configuration

5. **Cognito Configuration Validation**
   - User Pool status
   - JWKS URL accessibility
   - User Pool Client configuration

6. **Lambda Function Validation**
   - Agent Lambda status and configuration
   - Tool Lambda status and configuration
   - VPC attachment verification
   - Runtime version check

**Exit Codes:**

- `0` - All checks passed (or passed with warnings)
- `1` - One or more checks failed

## Deployment Workflow

### Initial Deployment

1. **Prepare parameters file:**
   ```bash
   cp cloudformation/parameters.json.example cloudformation/parameters.json
   # Edit parameters.json with your configuration
   ```

2. **Validate configuration:**
   ```bash
   ./scripts/validate-config.sh -b my-deployment-bucket -r us-east-1
   ```

3. **Deploy the stack:**
   ```bash
   ./scripts/deploy.sh \
     -s serverless-ai-agent-dev \
     -b my-deployment-bucket \
     -r us-east-1 \
     -e dev
   ```

4. **Validate deployed stack:**
   ```bash
   ./scripts/validate-config.sh -s serverless-ai-agent-dev -r us-east-1
   ```

### Update Deployment

1. **Rebuild Lambda packages:**
   ```bash
   ./scripts/deploy.sh \
     -s serverless-ai-agent-dev \
     -b my-deployment-bucket \
     -r us-east-1
   ```

2. **Update without rebuilding:**
   ```bash
   ./scripts/deploy.sh \
     -s serverless-ai-agent-dev \
     -b my-deployment-bucket \
     --skip-build
   ```

### Validation Only

Run validation without deployment:

```bash
# Validate templates
./scripts/validate-config.sh -b my-deployment-bucket

# Validate deployed stack
./scripts/validate-config.sh -s my-stack-name

# Full validation
./scripts/validate-config.sh -s my-stack-name -b my-deployment-bucket
```

## Troubleshooting

### Deployment Issues

**Problem:** Stack creation fails with "Insufficient permissions"

**Solution:** Ensure your AWS credentials have the following permissions:
- CloudFormation: Full access
- IAM: Create/update roles and policies
- Lambda: Create/update functions
- S3: Create/read/write buckets
- Cognito: Create/manage user pools
- EC2: Create/manage VPC resources
- Bedrock: Access to models

**Problem:** Lambda package too large

**Solution:** 
- Remove unnecessary dependencies from requirements.txt
- Use Lambda layers for common dependencies
- Exclude test files and documentation from packages

**Problem:** Template validation fails

**Solution:**
- Check CloudFormation template syntax
- Ensure all referenced resources exist
- Verify parameter values are valid

### Validation Issues

**Problem:** JWKS endpoint not accessible

**Solution:**
- Verify Cognito User Pool is created
- Check network connectivity
- Ensure JWKS URL is correct

**Problem:** VPC endpoint not available

**Solution:**
- Wait for VPC endpoint creation to complete
- Check VPC endpoint status in AWS console
- Verify route table associations

**Problem:** Lambda function not active

**Solution:**
- Check Lambda function logs in CloudWatch
- Verify IAM role permissions
- Ensure deployment package is valid

## Best Practices

1. **Use version control for parameters:**
   - Store parameters.json in version control
   - Use different parameter files for different environments
   - Never commit sensitive values (use AWS Secrets Manager)

2. **Validate before deploying:**
   - Always run validate-config.sh before deployment
   - Fix all errors before proceeding
   - Address warnings when possible

3. **Test in dev environment first:**
   - Deploy to dev environment first
   - Run integration tests
   - Validate functionality before promoting to prod

4. **Monitor deployments:**
   - Watch CloudFormation events during deployment
   - Check CloudWatch logs for errors
   - Verify stack outputs after deployment

5. **Use consistent naming:**
   - Use environment prefixes (dev-, staging-, prod-)
   - Follow naming conventions for resources
   - Tag all resources appropriately

6. **Backup before updates:**
   - Export stack outputs before updates
   - Document current configuration
   - Have rollback plan ready

## Environment Variables

The scripts support the following environment variables:

- `AWS_REGION` - Default AWS region
- `AWS_PROFILE` - AWS CLI profile to use
- `AWS_DEFAULT_REGION` - Alternative to AWS_REGION

Example:

```bash
export AWS_REGION=us-west-2
export AWS_PROFILE=my-profile
./scripts/deploy.sh -s my-stack -b my-bucket
```

## CI/CD Integration

These scripts can be integrated into CI/CD pipelines:

### GitHub Actions Example

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Validate configuration
        run: ./scripts/validate-config.sh -b ${{ secrets.DEPLOYMENT_BUCKET }}
      
      - name: Deploy stack
        run: |
          ./scripts/deploy.sh \
            -s serverless-ai-agent-prod \
            -b ${{ secrets.DEPLOYMENT_BUCKET }} \
            -e prod
```

### AWS CodePipeline Example

```yaml
version: 0.2

phases:
  pre_build:
    commands:
      - echo "Validating configuration..."
      - ./scripts/validate-config.sh -b $DEPLOYMENT_BUCKET
  
  build:
    commands:
      - echo "Deploying stack..."
      - ./scripts/deploy.sh -s $STACK_NAME -b $DEPLOYMENT_BUCKET -e $ENVIRONMENT
  
  post_build:
    commands:
      - echo "Validating deployment..."
      - ./scripts/validate-config.sh -s $STACK_NAME
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review CloudFormation events in AWS console
3. Check CloudWatch logs for Lambda functions
4. Refer to the main DEPLOYMENT_GUIDE.md for detailed instructions

## Related Documentation

- [DEPLOYMENT_GUIDE.md](../cloudformation/DEPLOYMENT_GUIDE.md) - Detailed deployment guide
- [README.md](../cloudformation/README.md) - CloudFormation templates documentation
- [requirements.md](../requirements.md) - System requirements
