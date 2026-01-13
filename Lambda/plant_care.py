# Plant care Lambda code - uses Nova Omni to provide care recommendations

import json
import boto3
import os
from nova_config import get_config, parse_nova_omni_response, REGION


def lambda_handler(event, context):
    try:
        plant_name = event.get('plant_name', 'unknown')
        health_status = event.get('health_status', 'healthy')
        
        # Get configuration for plant care
        config = get_config("plant_care")
        print(f"🔗 Using model: {config.model_id} in region: {REGION}")
        
        bedrock = boto3.client("bedrock-runtime", region_name=REGION)
        prompt = f"Provide care advice for {plant_name} with status: {health_status}"
        
        response = bedrock.converse(
            modelId=config.model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig=config.to_inference_config(),
            additionalModelRequestFields=config.to_additional_fields()
        )
        
        return {'statusCode': 200, 'body': json.dumps({
            'expert_advice': parse_nova_omni_response(response)
        })}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
