"""
Cognito Secret Store Custom Resource
Stores Cognito client secret in Secrets Manager for runtime access
"""

import json
import urllib3
import boto3


def send_response(event, context, status, data):
    """Send CloudFormation response"""
    response_body = {
        'Status': status,
        'Reason': f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': data.get('SecretArn', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }
    
    http = urllib3.PoolManager()
    response = http.request('PUT', event['ResponseURL'], 
                          body=json.dumps(response_body),
                          headers={'Content-Type': 'application/json'})
    print(f"CloudFormation response status: {response.status}")


def lambda_handler(event, context):
    """
    Custom Resource to store Cognito client secret in Secrets Manager
    This allows the Runtime to load the secret at runtime instead of having it embedded
    """
    try:
        print(f"Event: {json.dumps(event)}")
        
        request_type = event['RequestType']
        props = event['ResourceProperties']
        
        # Extract required properties
        stack_name = props['StackName']
        cognito_info = json.loads(props['CognitoInfo'])
        client_info = cognito_info['client_info']
        
        secrets_client = boto3.client('secretsmanager')
        secret_name = f'plant-advisor-cognito-secrets-{stack_name}'
        
        if request_type == 'Delete':
            try:
                secrets_client.delete_secret(
                    SecretId=secret_name,
                    ForceDeleteWithoutRecovery=True
                )
                print(f"Deleted secret: {secret_name}")
            except secrets_client.exceptions.ResourceNotFoundException:
                print(f"Secret {secret_name} not found, skipping deletion")
            
            send_response(event, context, 'SUCCESS', {})
            return
        
        # Create or Update - Store all Gateway-provided OAuth2 configuration
        secret_string = json.dumps({
            'COGNITO_CLIENT_ID': client_info['client_id'],
            'COGNITO_CLIENT_SECRET': client_info['client_secret'],
            'COGNITO_SCOPES': client_info['scope'],
            'COGNITO_TOKEN_ENDPOINT': client_info['token_endpoint']
        })
        
        try:
            # Try to create the secret
            response = secrets_client.create_secret(
                Name=secret_name,
                Description=f'Cognito client secret for {stack_name} runtime',
                SecretString=secret_string,
                Tags=[
                    {'Key': 'Application', 'Value': 'PlantAdvisor'},
                    {'Key': 'StackName', 'Value': stack_name},
                    {'Key': 'ManagedBy', 'Value': 'CustomResource'}
                ]
            )
            print(f"Created secret: {secret_name}")
            secret_arn = response['ARN']
            
        except secrets_client.exceptions.ResourceExistsException:
            # Secret already exists, update it
            response = secrets_client.update_secret(
                SecretId=secret_name,
                SecretString=secret_string
            )
            print(f"Updated existing secret: {secret_name}")
            secret_arn = response['ARN']
        
        send_response(event, context, 'SUCCESS', {
            'SecretName': secret_name,
            'SecretArn': secret_arn,
            'Status': 'created'
        })
        
    except Exception as e:
        print(f"Error storing Cognito secret: {str(e)}")
        import traceback
        traceback.print_exc()
        send_response(event, context, 'FAILED', {'Error': str(e)})
