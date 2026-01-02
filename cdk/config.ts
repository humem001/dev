// Configuration for AgentCore Strands Stack
export interface AgentCoreConfig {
  // Deployment Configuration
  region: string;
  stackName: string;
  
  // Bedrock Configuration
  bedrockModelId: string;
  maxTokens: number;
  
  // Lambda Configuration
  lambdaTimeout: number; // minutes
  strandsAgentMemory: number; // MB
  mcpToolMemory: number; // MB
  
  // VPC Configuration
  maxAzs: number;
  cidrMask: number;
  
  // Cognito Configuration
  cognitoUsername: string;
  
  // PowerTools Configuration
  powerToolsLayerVersion: number;
  
  // Gateway Configuration (set after deployment)
  gatewayUrl?: string;
  gatewayName?: string;
}

// Default configuration
export const defaultConfig: AgentCoreConfig = {
  region: 'eu-west-2',
  stackName: 'AgentCoreStrandsStack',
  bedrockModelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
  maxTokens: 1024,
  lambdaTimeout: 5,
  strandsAgentMemory: 1024,
  mcpToolMemory: 512,
  maxAzs: 2,
  cidrMask: 24,
  cognitoUsername: 'agentcore-user',
  powerToolsLayerVersion: 68,
  gatewayName: 'strands-gateway'
};

// Environment-specific overrides
export const environments = {
  dev: {
    ...defaultConfig,
    stackName: 'AgentCoreStrandsStack-Dev',
    gatewayName: 'strands-gateway-dev'
  },
  prod: {
    ...defaultConfig,
    stackName: 'AgentCoreStrandsStack-Prod',
    gatewayName: 'strands-gateway-prod'
  }
};