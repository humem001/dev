"""Tool definition validator.

This module provides validation for tool definitions retrieved from the Gateway,
ensuring they are well-formed and contain all required fields before use.
"""

import logging
from typing import Dict, Any, List

from .discovery_models import ToolDefinition, ValidationResult


logger = logging.getLogger(__name__)


class ToolValidator:
    """Validates tool definitions for correctness and completeness.
    
    Ensures tool definitions from the Gateway contain all required fields
    and have valid schemas before they are used with Bedrock.
    """
    
    def validate_tool(self, tool: Dict[str, Any]) -> ValidationResult:
        """Validate a single tool definition.
        
        Checks that the tool has all required fields (name, description, inputSchema)
        and that the inputSchema is a valid JSON Schema object.
        
        Args:
            tool: Tool definition dictionary from Gateway
            
        Returns:
            ValidationResult indicating success or failure with details
        """
        result = ValidationResult(is_valid=True)
        
        # Validate required field: name
        if "name" not in tool:
            result.add_error("Missing required field: name")
        elif not isinstance(tool["name"], str):
            result.add_error("Field 'name' must be a string")
        elif not tool["name"].strip():
            result.add_error("Field 'name' cannot be empty")
        
        # Validate required field: description
        if "description" not in tool:
            result.add_error("Missing required field: description")
        elif not isinstance(tool["description"], str):
            result.add_error("Field 'description' must be a string")
        elif not tool["description"].strip():
            result.add_error("Field 'description' cannot be empty")
        
        # Validate required field: inputSchema
        if "inputSchema" not in tool:
            result.add_error("Missing required field: inputSchema")
        else:
            input_schema = tool["inputSchema"]
            
            # inputSchema must be a dictionary
            if not isinstance(input_schema, dict):
                result.add_error("Field 'inputSchema' must be an object")
            else:
                # inputSchema must have type: object
                if "type" not in input_schema:
                    result.add_error("Field 'inputSchema' must have 'type' field")
                elif input_schema["type"] != "object":
                    result.add_error("Field 'inputSchema.type' must be 'object'")
                
                # Validate properties if present
                if "properties" in input_schema:
                    if not isinstance(input_schema["properties"], dict):
                        result.add_error("Field 'inputSchema.properties' must be an object")
                
                # Validate required if present
                if "required" in input_schema:
                    if not isinstance(input_schema["required"], list):
                        result.add_error("Field 'inputSchema.required' must be an array")
        
        return result
    
    def validate_tools(self, tools: List[Dict[str, Any]]) -> List[ToolDefinition]:
        """Validate multiple tool definitions, filtering out invalid ones.
        
        Validates each tool definition and returns only the valid ones.
        Invalid tools are logged but don't cause the entire operation to fail.
        
        Args:
            tools: List of tool definition dictionaries
            
        Returns:
            List of validated ToolDefinition objects (invalid tools excluded)
            
        Note:
            Logs errors for invalid tools but doesn't raise exceptions
        """
        valid_tools: List[ToolDefinition] = []
        
        for i, tool in enumerate(tools):
            # Get tool name for logging (may not exist if validation fails)
            tool_name = tool.get("name", f"<unnamed tool at index {i}>")
            
            # Validate tool
            validation_result = self.validate_tool(tool)
            
            if validation_result.is_valid:
                # Create ToolDefinition from validated tool
                tool_def = ToolDefinition(
                    name=tool["name"],
                    description=tool["description"],
                    input_schema=tool["inputSchema"]
                )
                valid_tools.append(tool_def)
                
                # Log warnings if any
                if validation_result.warnings:
                    for warning in validation_result.warnings:
                        logger.warning(f"Tool '{tool_name}': {warning}")
            else:
                # Log all validation errors
                logger.error(f"Tool '{tool_name}' failed validation:")
                for error in validation_result.errors:
                    logger.error(f"  - {error}")
        
        logger.info(f"Validated {len(valid_tools)} out of {len(tools)} tools")
        
        return valid_tools
    
    def check_unique_names(self, tools: List[Dict[str, Any]]) -> bool:
        """Verify that all tool names are unique.
        
        Args:
            tools: List of tool definitions
            
        Returns:
            True if all names are unique, False otherwise
        """
        seen_names = set()
        duplicates = set()
        
        for tool in tools:
            name = tool.get("name")
            if name:
                if name in seen_names:
                    duplicates.add(name)
                seen_names.add(name)
        
        if duplicates:
            logger.error(f"Duplicate tool names found: {', '.join(sorted(duplicates))}")
            return False
        
        return True
