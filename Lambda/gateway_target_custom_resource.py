import json
import urllib3
import boto3
import time

def lambda_handler(event, context):
    try:
        if event['RequestType'] == 'Delete':
            send_response(event, context, 'SUCCESS', {})
            return
        
        region = context.invoked_function_arn.split(':')[3]
        bedrock_agentcore_client = boto3.client('bedrock-agentcore-control',
                                               region_name=region,
                                               endpoint_url=f"https://bedrock-agentcore-control.{region}.amazonaws.com")
        
        gateway_id = event['ResourceProperties']['GatewayId']
        
        # Register Lambda targets using bedrock-agentcore-control client
        targets = [
            {
                'name': 'plant-detection-target',
                'arn': event['ResourceProperties']['PlantDetectionArn'],
                'tool_name': 'plant_detection_tool',
                'description': 'Detect plant and health',
                'properties': {"image_data": {"type": "string"}}
            },
            {
                'name': 'plant-care-target', 
                'arn': event['ResourceProperties']['PlantCareArn'],
                'tool_name': 'plant_care_tool',
                'description': 'Get plant care advice',
                'properties': {"plant_name": {"type": "string"}, "health_status": {"type": "string"}}
            },
            {
                'name': 'weather-forecast-target',
                'arn': event['ResourceProperties']['WeatherForecastArn'],
                'tool_name': 'weather_forecast_tool',
                'description': 'Get weather forecast for a specific location',
                'properties': {"location": {"type": "string"}}
            },
            {
                'name': 'web-search-target',
                'arn': event['ResourceProperties']['WebSearchArn'],
                'tool_name': 'websearch_tool',
                'description': 'Generic web search',
                'properties': {"query": {"type": "string"}}
            },
            {
                'name': 'plant-web-search-target',
                'arn': event['ResourceProperties']['PlantWebSearchArn'],
                'tool_name': 'plant_web_search_tool',
                'description': 'Search plant information',
                'properties': {"plant_name": {"type": "string"}, "health_status": {"type": "string"}}
            }
        ]
        
        registered_targets = []
        for i, target in enumerate(targets):
            try:
                # Add delay between requests to avoid throttling
                if i > 0:
                    time.sleep(10)  # Wait 10 seconds between each target registration
                
                config = {
                    "mcp": {
                        "lambda": {
                            "lambdaArn": target['arn'],
                            "toolSchema": {
                                "inlinePayload": [{
                                    "name": target['tool_name'],
                                    "description": target['description'],
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": target['properties']
                                    }
                                }]
                            }
                        }
                    }
                }
                
                response = bedrock_agentcore_client.create_gateway_target(
                    gatewayIdentifier=gateway_id,
                    name=target['name'],
                    targetConfiguration=config,
                    credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE"}]
                )
                
                registered_targets.append(target['name'])
                print(f"Registered target: {target['name']}")
            except Exception as e:
                print(f"Failed to register target {target['name']}: {str(e)}")
                # Continue with next target even if one fails
                continue

        send_response(event, context, 'SUCCESS', {
            'RegisteredTargets': ','.join(registered_targets),
            'TargetCount': len(registered_targets)
        })
        
    except Exception as e:
        print(f"Error: {str(e)}")
        send_response(event, context, 'FAILED', {'Error': str(e)})

def send_response(event, context, status, data):
    # Set appropriate reason based on status
    reason = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    if status == 'SUCCESS':
        reason = 'Gateway targets registered successfully'
    elif data.get('Error'):
        reason = str(data.get('Error'))[:256]  # CloudFormation limits reason to 256 chars
    
    response_body = {
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': data.get('RegisteredTargets', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }
    
    json_response_body = json.dumps(response_body)
    print(f"Response body: {json_response_body}")
    
    try:
        http = urllib3.PoolManager()
        response = http.request(
            'PUT',
            event['ResponseURL'],
            body=json_response_body,
            headers={
                'Content-Type': '',
                'Content-Length': str(len(json_response_body))
            },
            timeout=urllib3.Timeout(connect=5.0, read=30.0)
        )
        print(f"CloudFormation response status: {response.status}")
        if response.status != 200:
            print(f"CloudFormation response body: {response.data}")
    except Exception as e:
        print(f"Failed to send response to CloudFormation: {str(e)}")
        # Don't raise - we've done our best to notify CloudFormation
