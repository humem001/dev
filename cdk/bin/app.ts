#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AgentCoreStrandsStack } from '../lib/agentcore-strands-stack';
import { defaultConfig, environments } from '../config';

const app = new cdk.App();

// Get environment from context or default to 'dev'
const env = app.node.tryGetContext('env') || 'dev';
const config = environments[env as keyof typeof environments] || defaultConfig;

new AgentCoreStrandsStack(app, config.stackName, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || config.region,
  },
  description: 'AgentCore Strands Agent with Lambda MCP Tool',
  config: config,
});

app.synth();
