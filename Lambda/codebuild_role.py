import json
import boto3
import urllib3
import time

def lambda_handler(event, context):
    try:
        if event['RequestType'] in ['Delete', 'Update']:
            if event['RequestType'] == 'Delete':
                send_response(event, context, 'SUCCESS', {})
                return
        
        iam = boto3.client('iam')
        
        for attempt in range(30):  # Wait up to 5 minutes
            try:
                roles = iam.list_roles(PathPrefix='/')['Roles']
                codebuild_role = None
                
                for role in roles:
                    if role['RoleName'].startswith('AmazonBedrockAgentCoreSDKCodeBuild-'):
                        codebuild_role = role['RoleName']
                        break
                
                if codebuild_role:
                    # Attach CloudWatch Logs policy
                    iam.attach_role_policy(
                        RoleName=codebuild_role,
                        PolicyArn='arn:aws:iam::aws:policy/CloudWatchLogsFullAccess'
                    )
                    
                    # Attach ECR policy
                    iam.attach_role_policy(
                        RoleName=codebuild_role,
                        PolicyArn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly'
                    )
                    
                    send_response(event, context, 'SUCCESS', {'RoleName': codebuild_role})
                    return
            except Exception as e:
                print(f"Attempt {attempt}: {str(e)}")
            
            time.sleep(10)  # Wait 10 seconds between attempts
        
        send_response(event, context, 'FAILED', {'Error': 'CodeBuild role not found'})
        
    except Exception as e:
        print(f"Error: {str(e)}")
        send_response(event, context, 'FAILED', {})

def send_response(event, context, status, data):
    response_body = {
        'Status': status,
        'Reason': 'OK',
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }
    
    http = urllib3.PoolManager()
    http.request('PUT', event['ResponseURL'], 
                body=json.dumps(response_body),
                headers={'Content-Type': 'application/json'})