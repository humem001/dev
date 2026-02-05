"""Agent module for Strands Framework-based AI agent."""

from .agent_core import Agent, AgentConfig
from .lambda_handler import lambda_handler

__all__ = ['Agent', 'AgentConfig', 'lambda_handler']
