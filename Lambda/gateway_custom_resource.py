import json
import urllib3
import boto3

def lambda_handler(event, context):
    try:
        if event['RequestType'] in ['Delete', 'Update']:
            # Delete Gateway and Cognito resources for rollback
            region = context.invoked_function_arn.split(':')[3]
            
            gateway_id = event.get('PhysicalResourceId')
            if gateway_id and gateway_id != context.log_stream_name:
                print(f"Attempting to delete gateway: {gateway_id}")
                try:
                    bedrock_client = boto3.client('bedrock-agentcore-control', region_name=region)
                    
                    # Delete all gateway targets with retry
                    import time
                    for attempt in range(5):
                        try:
                            targets_response = bedrock_client.list_gateway_targets(gatewayIdentifier=gateway_id)
                            targets = targets_response.get('targets', [])
                            
                            if not targets:
                                print("No targets found, proceeding to delete gateway")
                                break
                            
                            for target in targets:
                                target_name = target.get('name')
                                if target_name:
                                    print(f"Deleting gateway target: {target_name}")
                                    bedrock_client.delete_gateway_target(
                                        gatewayIdentifier=gateway_id,
                                        targetName=target_name
                                    )
                            
                            # Wait for targets to be deleted
                            time.sleep(10)
                            
                            # Check if all targets are deleted
                            check_response = bedrock_client.list_gateway_targets(gatewayIdentifier=gateway_id)
                            if not check_response.get('targets', []):
                                print("All targets deleted successfully")
                                break
                                
                        except Exception as target_error:
                            print(f"Target deletion attempt {attempt + 1} error: {str(target_error)}")
                            if attempt < 4:
                                time.sleep(5)
                    
                    # Then delete the gateway
                    bedrock_client.delete_gateway(gatewayIdentifier=gateway_id)
                    print(f"Successfully deleted gateway: {gateway_id}")
                except Exception as e:
                    print(f"Gateway deletion failed: {str(e)}")
                    # Don't fail the stack deletion if gateway deletion fails
            
            # Delete SSM parameter
            try:
                stack_name = event['StackId'].split('/')[-2]
                ssm = boto3.client('ssm')
                ssm.delete_parameter(Name=f'/plant-advisor/{stack_name}/gateway-info')
                print("Deleted SSM parameter")
            except Exception as e:
                print(f"SSM parameter deletion error: {str(e)}")
            
            if event['RequestType'] == 'Delete':
                send_response(event, context, 'SUCCESS', {})
                return
        
        from bedrock_agentcore_starter_toolkit.operations.gateway.client import GatewayClient
        
        region = context.invoked_function_arn.split(':')[3]
        client = GatewayClient(region_name=region)
        
        # Create cognito authorizer with unique name
        stack_name = event['StackId'].split('/')[-2]
        auth_name = f"PlantGatewayAuth-{stack_name[:8]}"
        
        # Create OAuth authorizer for Gateway authentication
        try:
            cognito_response = client.create_oauth_authorizer_with_cognito(auth_name)
        except Exception as auth_error:
            print(f"Failed to create OAuth authorizer: {str(auth_error)}")
            raise auth_error
        
        # Create the gateway (toolkit will create its own execution role)
        gateway = client.create_mcp_gateway(
            name='PlantAdvisorGateway',
            authorizer_config=cognito_response["authorizer_config"]
            )
        
        gateway_id = gateway.get('gatewayId') or gateway.get('gatewayArn').split('/')[-1]
        gateway_url = gateway.get('gatewayUrl')
        
        cognito_info_json = json.dumps(cognito_response)

        # Store gateway info in SSM
        gateway_info = {
            'gateway_id': gateway_id,
            'gateway_url': gateway_url,
            'cognito_info': cognito_info_json
        }
        
        ssm = boto3.client('ssm')
        ssm.put_parameter(
            Name=f'/plant-advisor/{stack_name}/gateway-info',
            Value=json.dumps(gateway_info),
            Type='String',
            Overwrite=True
        )
        
        send_response(event, context, 'SUCCESS', {
            'GatewayId': gateway_id,
            'GatewayUrl': gateway_url,
            'CognitoInfo': cognito_info_json
        })
        
    except Exception as e:
        import traceback
        error_message = str(e)
        print(f"Error: {error_message}")
        print(f"Traceback: {traceback.format_exc()}")
        send_response(event, context, 'FAILED', {'Error': error_message})

def send_response(event, context, status, data):
    # Set appropriate reason based on status
    reason = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    if status == 'SUCCESS':
        reason = 'Gateway creation completed successfully'
    elif data.get('Error'):
        reason = str(data.get('Error'))[:256]  # CloudFormation limits reason to 256 chars
    
    response_body = {
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': data.get('GatewayId', context.log_stream_name),
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
