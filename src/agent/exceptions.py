"""Exception classes for the Agent module."""


class AgentError(Exception):
    """Base exception for agent-related errors."""
    pass


class BedrockError(AgentError):
    """Exception for Bedrock API errors."""
    pass


class BedrockThrottlingError(BedrockError):
    """Exception for Bedrock throttling errors."""
    pass


class BedrockModelUnavailableError(BedrockError):
    """Exception when Bedrock model is unavailable."""
    pass


class BedrockTimeoutError(BedrockError):
    """Exception when Bedrock operation times out."""
    pass
