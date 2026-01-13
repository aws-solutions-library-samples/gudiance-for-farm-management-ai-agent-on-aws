"""
Centralized Nova Omni Configuration
All LLM parameters in one place for easy management
"""
import os
from typing import Dict, Any, Literal
from dataclasses import dataclass

@dataclass
class NovaModelConfig:
    """Configuration for Nova Omni models"""
    model_id: str
    temperature: float
    max_tokens: int
    reasoning_effort: Literal["low", "medium", "high"]
    
    def to_inference_config(self) -> Dict[str, Any]:
        """Convert to Bedrock inferenceConfig format"""
        return {
            "temperature": self.temperature,
            "maxTokens": self.max_tokens
        }
    
    def to_additional_fields(self) -> Dict[str, Any]:
        """Convert to additionalModelRequestFields format for Nova Omni"""
        # Reasoning disabled - return empty dict
        return {}

# Environment-based configuration with defaults
REGION = os.environ.get('BEDROCK_REGION', os.environ.get('AWS_REGION', 'us-west-2'))

# Model configurations by use case - All use 5000 tokens and medium reasoning
CONFIGS = {
    "plant_detection": NovaModelConfig(
        model_id=os.environ.get('NOVA_MODEL_ID', 'us.amazon.nova-2-lite-v1:0'),
        temperature=float(os.environ.get('NOVA_TEMP', '0.1')),
        max_tokens=int(os.environ.get('NOVA_MAX_TOKENS', '5000')),
        reasoning_effort=os.environ.get('NOVA_REASONING', 'medium')
    ),
    "plant_care": NovaModelConfig(
        model_id=os.environ.get('NOVA_MODEL_ID', 'us.amazon.nova-2-lite-v1:0'),
        temperature=float(os.environ.get('NOVA_TEMP', '0.1')),
        max_tokens=int(os.environ.get('NOVA_MAX_TOKENS', '5000')),
        reasoning_effort=os.environ.get('NOVA_REASONING', 'medium')
    ),
    "web_search": NovaModelConfig(
        model_id=os.environ.get('NOVA_MODEL_ID', 'us.amazon.nova-2-lite-v1:0'),
        temperature=float(os.environ.get('NOVA_TEMP', '0.1')),
        max_tokens=int(os.environ.get('NOVA_MAX_TOKENS', '5000')),
        reasoning_effort=os.environ.get('NOVA_REASONING', 'medium')
    )
}

def get_config(use_case: str) -> NovaModelConfig:
    """
    Get configuration for specific use case
    
    Args:
        use_case: One of 'plant_detection', 'plant_care', 'web_search'
    
    Returns:
        NovaModelConfig for the specified use case
    """
    return CONFIGS.get(use_case, CONFIGS["plant_care"])

def parse_nova_omni_response(response: Dict[str, Any]) -> str:
    """
    Extract text from Nova Omni response
    
    Args:
        response: Bedrock converse() response
    
    Returns:
        Extracted text content
    """
    content = response['output']['message']['content']
    return content[0]['text'] if content else ""

# Configuration summary for logging
def get_config_summary() -> Dict[str, Any]:
    """Get summary of current configuration for logging"""
    return {
        "region": REGION,
        "configs": {
            name: {
                "model_id": config.model_id,
                "temperature": config.temperature,
                "max_tokens": config.max_tokens,
                "reasoning_effort": config.reasoning_effort
            }
            for name, config in CONFIGS.items()
        }
    }
