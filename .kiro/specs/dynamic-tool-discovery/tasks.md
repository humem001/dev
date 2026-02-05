# Implementation Plan: Dynamic Tool Discovery from AgentCore Gateway

## Overview

This implementation plan breaks down the dynamic tool discovery feature into discrete coding tasks. The approach follows an incremental pattern: build core components first, add caching and validation, implement error handling, then integrate with the agent. Each task builds on previous work and includes testing to validate functionality early.

## Tasks

- [x] 1. Set up project structure and data models
  - Create directory structure for new modules
  - Define core data models: `ToolDefinition`, `CachedTools`, `ToolListResponse`, `ValidationResult`
  - Implement `ToolDefinition.to_bedrock_format()` method
  - Add type hints and docstrings
  - _Requirements: 5.1_

- [ ]* 1.1 Write property test for Bedrock format conversion
  - **Property 12: Bedrock format compatibility**
  - **Validates: Requirements 5.1**
  - Generate random tool definitions and verify conversion produces correct structure
  - _Requirements: 5.1_

- [ ] 2. Implement Gateway client for MCP protocol
  - [x] 2.1 Create `GatewayClient` class with initialization
    - Implement `__init__` with gateway_url, token_manager, timeout parameters
    - Set up HTTP client (aiohttp or httpx)
    - _Requirements: 1.1, 1.2_
  
  - [x] 2.2 Implement `list_tools()` method for single page
    - Build MCP tools/list JSON-RPC request
    - Send POST request with OAuth token
    - Parse JSON-RPC response
    - Handle pagination cursor
    - _Requirements: 1.1, 1.2_
  
  - [x] 2.3 Implement `list_all_tools()` method with pagination
    - Loop through pages using cursor
    - Aggregate all tools from multiple pages
    - _Requirements: 1.1_
  
  - [ ]* 2.4 Write property test for Gateway response structure
    - **Property 1: Gateway returns complete tool definitions**
    - **Validates: Requirements 1.1, 1.2**
    - Generate random Gateway responses and verify all tools have required fields
    - _Requirements: 1.1, 1.2_
  
  - [ ]* 2.5 Write unit tests for error scenarios
    - Test network timeout handling
    - Test auth failure handling
    - Test malformed JSON response
    - _Requirements: 1.4_

- [ ] 3. Checkpoint - Ensure Gateway client tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement tool validation
  - [x] 4.1 Create `ToolValidator` class
    - Implement `validate_tool()` for single tool
    - Check required fields: name, description, inputSchema
    - Validate inputSchema structure (type: object)
    - Return `ValidationResult` with errors/warnings
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [x] 4.2 Implement `validate_tools()` for batch validation
    - Validate multiple tools
    - Filter out invalid tools
    - Log errors for invalid tools
    - Return list of valid `ToolDefinition` objects
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [x] 4.3 Implement `check_unique_names()` method
    - Verify all tool names are unique
    - Return boolean result
    - _Requirements: 6.4_
  
  - [ ]* 4.4 Write property test for validation filtering
    - **Property 14: Validation filters invalid tools**
    - **Validates: Requirements 6.1, 6.2, 6.3**
    - Generate random tool sets with some invalid tools
    - Verify invalid tools are filtered out
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [ ]* 4.5 Write property test for unique names
    - **Property 15: Unique tool names**
    - **Validates: Requirements 6.4**
    - Generate random tool sets and verify uniqueness validation
    - _Requirements: 6.4_

- [ ] 5. Implement tool cache with TTL
  - [x] 5.1 Create `ToolCache` class
    - Implement `__init__` with ttl_seconds parameter
    - Initialize internal storage (dict or similar)
    - _Requirements: 2.1, 2.4_
  
  - [x] 5.2 Implement cache operations
    - Implement `get()` method to retrieve cached tools
    - Implement `set()` method to store tools with timestamp
    - Implement `is_expired()` method to check TTL
    - Implement `clear()` method
    - Implement `get_age_seconds()` method
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  
  - [ ]* 5.3 Write property test for TTL expiration
    - **Property 5: TTL-based cache expiration**
    - **Validates: Requirements 2.3, 2.4**
    - Generate random TTL values and cache ages
    - Verify expiration logic is correct
    - _Requirements: 2.3, 2.4_
  
  - [ ]* 5.4 Write property test for cache-first retrieval
    - **Property 4: Cache-first retrieval**
    - **Validates: Requirements 2.2**
    - Verify cache is checked before Gateway query
    - _Requirements: 2.2_

- [ ] 6. Checkpoint - Ensure validation and cache tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement configuration management
  - [x] 7.1 Create `DiscoveryConfig` dataclass
    - Define all configuration fields with defaults
    - Add validation for config values
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
  
  - [ ]* 7.2 Write property test for default configuration
    - **Property 16: Default configuration values**
    - **Validates: Requirements 7.5**
    - Verify defaults are used when config not provided
    - _Requirements: 7.5_
  
  - [ ]* 7.3 Write unit tests for configuration scenarios
    - Test all configuration parameters
    - Test invalid configuration values
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 8. Implement tool discovery service
  - [x] 8.1 Create `ToolDiscoveryService` class
    - Implement `__init__` with dependencies (gateway_client, cache, validator, config)
    - Initialize internal state
    - _Requirements: 1.1, 2.1_
  
  - [x] 8.2 Implement `discover_tools()` method
    - Check cache first (unless force_refresh)
    - Query Gateway if cache expired or force refresh
    - Validate tools from Gateway
    - Store validated tools in cache
    - Handle errors with fallback to cache
    - Implement retry logic with exponential backoff
    - _Requirements: 1.1, 2.1, 2.2, 2.3, 4.1_
  
  - [x] 8.3 Implement `refresh_cache()` method
    - Query Gateway for updated tools
    - Validate and store in cache
    - _Requirements: 3.2_
  
  - [x] 8.4 Implement `get_cached_tools()` method
    - Return cached tools without Gateway query
    - _Requirements: 2.2_
  
  - [ ]* 8.5 Write property test for cache storage
    - **Property 3: Retrieved tools are cached**
    - **Validates: Requirements 2.1**
    - Verify tools from Gateway are stored in cache
    - _Requirements: 2.1_
  
  - [ ]* 8.6 Write property test for manual refresh
    - **Property 6: Manual refresh queries Gateway**
    - **Validates: Requirements 3.2**
    - Verify refresh triggers Gateway query
    - _Requirements: 3.2_

- [ ] 9. Implement error handling and fallback logic
  - [ ] 9.1 Add error handling to `discover_tools()`
    - Catch `GatewayConnectionError` and fallback to cache
    - Catch `GatewayAuthError` and retry with token refresh
    - Catch `MCPProtocolError` and fallback to cache
    - Raise `ToolDiscoveryError` when no fallback available
    - _Requirements: 1.4, 4.1, 4.2_
  
  - [ ] 9.2 Implement logging for all error scenarios
    - Log tool discovery success with count
    - Log tool discovery failure with error details
    - Log cache refresh events
    - Log stale cache usage warnings
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
  
  - [ ]* 9.3 Write property test for Gateway failure fallback
    - **Property 9: Fallback to cache on Gateway failure**
    - **Validates: Requirements 4.1**
    - Simulate Gateway failures and verify cache fallback
    - _Requirements: 4.1_
  
  - [ ]* 9.4 Write property test for stale cache warning
    - **Property 11: Stale cache warning**
    - **Validates: Requirements 4.4, 8.4**
    - Verify warning is logged when using stale cache
    - _Requirements: 4.4, 8.4_
  
  - [ ]* 9.5 Write property test for error descriptiveness
    - **Property 2: Tool discovery errors are descriptive**
    - **Validates: Requirements 1.4**
    - Generate random error scenarios and verify error messages
    - _Requirements: 1.4_

- [ ] 10. Checkpoint - Ensure error handling tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Implement concurrency safety
  - [ ] 11.1 Add asyncio locks to prevent concurrent Gateway queries
    - Add lock to `discover_tools()` method
    - Add lock to `refresh_cache()` method
    - _Requirements: 3.4_
  
  - [ ] 11.2 Implement atomic cache updates
    - Use lock or atomic swap for cache updates
    - Ensure no partial state visible during updates
    - _Requirements: 3.3_
  
  - [ ]* 11.3 Write property test for atomic updates
    - **Property 7: Atomic cache updates**
    - **Validates: Requirements 3.3**
    - Verify no partial state during concurrent access
    - _Requirements: 3.3_
  
  - [ ]* 11.4 Write property test for non-blocking refresh
    - **Property 8: Non-blocking refresh**
    - **Validates: Requirements 3.4**
    - Verify concurrent reads don't block during refresh
    - _Requirements: 3.4_

- [ ] 12. Implement backward compatibility and configuration
  - [x] 12.1 Add feature flag support
    - Read `ENABLE_GATEWAY_DISCOVERY` environment variable
    - Implement fallback to local registry when disabled
    - _Requirements: 5.3, 5.4_
  
  - [x] 12.2 Implement local registry fallback
    - Keep existing hardcoded tool registry
    - Use local registry when Gateway discovery disabled
    - _Requirements: 5.3, 5.4_
  
  - [ ]* 12.3 Write property test for configuration-based fallback
    - **Property 13: Configuration-based fallback to local registry**
    - **Validates: Requirements 5.4**
    - Verify local registry used when Gateway discovery disabled
    - _Requirements: 5.4_
  
  - [ ]* 12.4 Write unit tests for feature flag scenarios
    - Test with feature enabled
    - Test with feature disabled
    - Test with missing configuration
    - _Requirements: 5.3, 5.4_

- [ ] 13. Integrate with agent initialization
  - [ ] 13.1 Modify agent initialization code
    - Create `ToolDiscoveryService` instance
    - Call `discover_tools()` during agent startup
    - Pass discovered tools to Bedrock API
    - _Requirements: 2.5, 5.1_
  
  - [ ] 13.2 Add environment variable configuration
    - Read Gateway URL, credentials, TTL from environment
    - Create `DiscoveryConfig` from environment variables
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
  
  - [ ]* 13.3 Write integration test for end-to-end discovery
    - Test complete flow from agent init to Bedrock API
    - Mock Gateway responses
    - Verify tools passed to Bedrock correctly
    - _Requirements: 1.1, 2.5, 5.1_

- [ ] 14. Implement observability
  - [ ] 14.1 Add comprehensive logging
    - Log tool discovery initiated
    - Log tools discovered with count
    - Log cache hits/misses
    - Log validation errors
    - _Requirements: 8.1, 8.2, 8.3_
  
  - [ ]* 14.2 Write property test for comprehensive logging
    - **Property 17: Comprehensive logging**
    - **Validates: Requirements 8.1, 8.2, 8.3**
    - Verify appropriate logs for all operations
    - _Requirements: 8.1, 8.2, 8.3_
  
  - [ ]* 14.3 Write unit tests for logging scenarios
    - Test log messages for success
    - Test log messages for failures
    - Test log messages for cache operations
    - _Requirements: 8.1, 8.2, 8.3_

- [ ] 15. Implement Gateway recovery behavior
  - [ ] 15.1 Add scheduled cache refresh logic
    - Implement background task for periodic refresh
    - Trigger refresh after Gateway recovery
    - _Requirements: 4.3_
  
  - [ ]* 15.2 Write property test for Gateway recovery
    - **Property 10: Cache refresh after Gateway recovery**
    - **Validates: Requirements 4.3**
    - Verify cache refreshes after Gateway becomes available
    - _Requirements: 4.3_

- [ ] 16. Final checkpoint - Ensure all tests pass
  - Run complete test suite
  - Verify all property tests pass (minimum 100 iterations each)
  - Verify all unit tests pass
  - Verify integration tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 17. Documentation and deployment preparation
  - [x] 17.1 Update README with configuration instructions
    - Document environment variables
    - Document feature flag usage
    - Document migration path
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
  
  - [ ] 17.2 Add inline code documentation
    - Ensure all public methods have docstrings
    - Add type hints to all functions
    - Document error handling behavior
    - _Requirements: All_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using `hypothesis` library
- Unit tests validate specific examples and edge cases
- All property tests should run minimum 100 iterations
- Integration tests verify end-to-end flows with mocked Gateway
