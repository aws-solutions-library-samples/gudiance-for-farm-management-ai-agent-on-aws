# Plant detection Lambda code - uses Nova Omni to analyze plant images

import json
import boto3
import base64
import os
from nova_config import get_config, parse_nova_omni_response, REGION

def lambda_handler(event, context):
    try:
        print(f"Received event keys: {list(event.keys())}")
        
        # Extract inputs
        image_path = event.get('image_path')
        image_data = event.get('image_data')
        
        print(f"image_path present: {bool(image_path)}")
        print(f"image_data present: {bool(image_data)}")
        
        if not image_path and not image_data:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Either image_path or image_data required'})
            }
        
        # Process image input - FIXED LOGIC
        image_bytes = None
        
        if image_data:
            # Handle base64 image data
            print("Processing image_data...")
            try:
                image_bytes = base64.b64decode(image_data)
                print(f"✅ Decoded base64 image: {len(image_bytes)} bytes")
            except Exception as e:
                return {'statusCode': 400, 'body': json.dumps({'error': f'Invalid base64: {e}'})}
                
        elif image_path:
            # Handle image path (S3 or URL only)
            print(f"Processing image_path: {image_path}")
            if image_path.startswith('s3://'):
                try:
                    s3_client = boto3.client('s3')
                    bucket = image_path.split('/')[2]
                    key = '/'.join(image_path.split('/')[3:])
                    response = s3_client.get_object(Bucket=bucket, Key=key)
                    image_bytes = response['Body'].read()
                    print(f"✅ Loaded from S3: {len(image_bytes)} bytes")
                except Exception as e:
                    return {'statusCode': 500, 'body': json.dumps({'error': f'S3 error: {e}'})}
            else:
                return {'statusCode': 404, 'body': json.dumps({'error': f'Only S3 paths supported: {image_path}'})}
        
        if not image_bytes:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No image data processed'})}

        # Detect format - CORRECTED
        if image_bytes.startswith(b'\xff\xd8\xff'):
            image_format = 'jpeg'
        elif image_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
            image_format = 'png'
        else:
            image_format = 'jpeg'  # Default

        
        print(f"✅ Detected format: {image_format}")
        
        # Get configuration for plant detection
        config = get_config("plant_detection")
        print(f"🔗 Using model: {config.model_id} in region: {REGION}")
        
        # Tool configuration for structured output
        tool_config = {
            "tools": [{
                "toolSpec": {
                    "name": "submit_plant_analysis",
                    "description": "Submit the final plant analysis results",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "plant_type": {
                                    "type": "string",
                                    "description": "The identified plant name/type"
                                },
                                "health_analysis": {
                                    "type": "string", 
                                    "description": "Detailed health analysis of the plant"
                                }
                            },
                            "required": ["plant_type", "health_analysis"]
                        }
                    }
                }
            }],
            "toolChoice": {"tool": {"name": "submit_plant_analysis"}}
        }
        
        # Call Nova Omni using converse API
        bedrock_client = boto3.client("bedrock-runtime", region_name=REGION)
        
        response = bedrock_client.converse(
            modelId=config.model_id,
            messages=[{
                "role": "user",
                "content": [
                    {"image": {"format": image_format, "source": {"bytes": image_bytes}}},
                    {"text": "Analyze this plant image and identify the plant type and health condition. Use specific plant names such as: sweet_potato_leaf, tomato, bean, lettuce, pepper, cucumber, spinach, okra, sweet potato, carrot, onion, garlic, herbs. For health_analysis, describe in detail: leaf color (green, yellow, brown, purple), spots (black spots, brown spots, white spots), wilting, malnutrition signs, holes or other symptoms of pest damage, disease symptoms, nutrient deficiency, overall plant condition."}
                ]
            }],
            toolConfig=tool_config,
            inferenceConfig=config.to_inference_config(),
            additionalModelRequestFields=config.to_additional_fields()
        )
        
        # Extract tool use response
        content_items = response['output']['message']['content']
        for item in content_items:
            if 'toolUse' in item:
                tool_input = item['toolUse']['input']
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        "plant_name": tool_input['plant_type'],
                        "health_issues": tool_input['health_analysis']
                    })
                }
        
        # Fallback if no tool use found
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'No tool use response received'})
        }
        
    except Exception as e:
        print(f"Lambda error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
