# Lambda function code (Web search - bedrock model as fallback)
import json
import requests
import boto3
import os
from functools import lru_cache
from nova_config import get_config, parse_nova_omni_response, REGION

@lru_cache(maxsize=10)
def get_model_id(model_pattern='nova-2-lite-omni', region_param=None):
    """
    Dynamically discover correct model ID for any AWS region.
    Uses ListFoundationModels API to find the right format.
    
    Args:
        model_pattern: Model name to search for (e.g., 'nova-2-lite-omni', 'nova-pro')
        region_param: AWS region (defaults to module-level REGION variable)
    
    Returns:
        Correct model ID for the region (e.g., 'amazon.nova-2-lite-omni-v1:0')
    """
    target_region = region_param or REGION
    
    try:
        bedrock = boto3.client('bedrock', region_name=target_region)
        
        # List all available foundation models
        response = bedrock.list_foundation_models()
        
        # Find model matching the pattern
        for model in response.get('modelSummaries', []):
            model_id = model['modelId']
            model_lower = model_id.lower()
            pattern_lower = model_pattern.lower()
            
            # Match pattern with exact model name check
            if pattern_lower in model_lower:
                # Ensure we match the right model
                if 'premier' in pattern_lower and 'premier' in model_lower:
                    print(f"✅ Discovered model ID: {model_id}")
                    return model_id
                elif 'pro' in pattern_lower and 'pro' in model_lower and 'premier' not in model_lower:
                    print(f"✅ Discovered model ID: {model_id}")
                    return model_id
                elif 'lite' in pattern_lower and 'lite' in model_lower:
                    print(f"✅ Discovered model ID: {model_id}")
                    return model_id
                elif 'micro' in pattern_lower and 'micro' in model_lower:
                    print(f"✅ Discovered model ID: {model_id}")
                    return model_id
        
        # Fallback: use standard format without region prefix
        fallback_id = f"amazon.{model_pattern}-v1:0"
        print(f"⚠️ Model not found via API, using fallback: {fallback_id}")
        return fallback_id
        
    except Exception as e:
        # Fallback if API call fails
        fallback_id = f"amazon.{model_pattern}-v1:0"
        print(f"⚠️ Error discovering model ({e}), using fallback: {fallback_id}")
        return fallback_id

def get_tavily_api_key():
    """
    Retrieve Tavily API key from Secrets Manager with fallback to environment variable.
    This provides backward compatibility during migration.
    """
    # Try Secrets Manager first (new approach)
    secret_name = os.environ.get('TAVILY_SECRET_NAME')
    if secret_name:
        try:
            secrets_client = boto3.client('secretsmanager', region_name=REGION)
            response = secrets_client.get_secret_value(SecretId=secret_name)
            secret = json.loads(response['SecretString'])
            api_key = secret.get('tavily_api_key')
            if api_key:
                return api_key
        except Exception as e:
            print(f"Warning: Failed to retrieve Tavily API key from Secrets Manager: {e}")
            print("Falling back to environment variable...")
    
    # Fallback to environment variable (legacy approach)
    return os.environ.get('TAVILY_API_KEY')

def fallback_to_bedrock(query):
    """Fallback to Bedrock when Tavily is unavailable"""
    try:
        # Get configuration for web search
        config = get_config("web_search")
        print(f"🔗 Using model: {config.model_id} in region: {REGION}")
        
        bedrock = boto3.client('bedrock-runtime', region_name=REGION)
        
        system_prompt = """You are a web search assistant. Provide comprehensive information based on your knowledge.
                    
            Focus on:
            - Accurate, up-to-date information
            - Multiple perspectives when relevant
            - Practical, actionable advice
            - Clear, well-structured responses
            
            Query: Provide detailed information about the user's query."""
    
        payload = {
            "schemaVersion": "messages-v1",
            "inferenceConfig": config.to_inference_config(),
            "additionalModelRequestFields": config.to_additional_fields(),
            "system": [{"text": system_prompt}],
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": query}]
                }
            ]
        }
        
        response = bedrock.invoke_model(
            modelId=config.model_id,
            body=json.dumps(payload)
        )
        
        response_body = json.loads(response['body'].read())
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'source': 'bedrock',
                'results': {
                    'answer': parse_nova_omni_response(response_body),
                    'model': config.model_id
                }
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Bedrock fallback error: {str(e)}'
            })
        }

def lambda_handler(event, context):
    """Lambda function for web search with Tavily/Bedrock fallback"""
    
    # Get query from event
    query = event.get('query', '')
    if not query:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Query parameter required'})
        }
    
    # Get Tavily API key (tries Secrets Manager first, then env var)
    tavily_api_key = get_tavily_api_key()
    
    if tavily_api_key:
        # Use Tavily API
        try:
            response = requests.post(
                'https://api.tavily.com/search',
                headers={'Content-Type': 'application/json'},
                json={
                    'api_key': tavily_api_key,
                    'query': query,
                    'search_depth': 'advanced',
                    'include_answer': True,
                    'max_results': 5
                },
                timeout=30
            )
            
            if response.status_code == 200:
                search_results = response.json()
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'source': 'tavily',
                        'results': search_results
                    })
                }
            else:
                # Fallback to Bedrock if Tavily fails
                return fallback_to_bedrock(query)
                
        except Exception as e:
            # Fallback to Bedrock if Tavily errors
            return fallback_to_bedrock(query)
    
    else:
        # No Tavily API key - use Bedrock directly
        return fallback_to_bedrock(query)
