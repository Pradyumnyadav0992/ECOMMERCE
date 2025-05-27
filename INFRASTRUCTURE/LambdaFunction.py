import hmac
import hashlib
import json
import urllib3
import os
import base64
import boto3
import json


def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = response['SecretString']
        return json.loads(secret)  # Parse JSON string to dict
    except Exception as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        raise e



def trigger(jenkins_url,jenkins_token)

    # Trigger Jenkins build
    http = urllib3.PoolManager()

    # Encode basic auth
    credentials = f"{jenkins_user}:{jenkins_token}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode('utf-8')

    headers = {
        'Authorization': f'Basic {encoded_credentials}',
        'Content-Type': 'application/json'
    }

    response = http.request(
        'POST',
        f"{jenkins_url}/job/ECOMMERCE_OPENTELEMETRY_BUILD/build?token={jenkins_token}",
        headers=headers
    )

    return {
        'statusCode': response.status,
        'body': 'Build triggered' if response.status == 201 else f'Failed to trigger build: {response.status}'
    }

def lambda_handler(event, context):

    jenkins_url = "http://ecommerce-alb-868586226.us-west-2.elb.amazonaws.com"
    secret_name = 'ECOMMERC_SECRETS'
    secrets = get_secret(secret_name)

    # Fetching Value from AWS secret
    secret = secrets.get('secret')
    jenkins_token = secrets.get('jenkins_token')
    jenkins_user = secrets.get('jenkins_user')

    print(f"secret: {secret}")
    print(f"Jenkins URL: {jenkins_url}")
    print(f"Jenkins Token: {jenkins_token}")
    print(f"Jenkins User: {jenkins_user}")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Secrets fetched successfully',
            'jenkins_url': jenkins_url
        })
    }




    # Validate GitHub signature
    signature = event.get('headers', {}).get('x-hub-signature-256')
    body = event.get('body', '')
    if not signature:
        return {'statusCode': 400, 'body': 'Missing signature header'}

    mac = hmac.new(secret.encode(), msg=body.encode(), digestmod=hashlib.sha256)
    expected_signature = 'sha256=' + mac.hexdigest()
    print("SDASD",signature,expected_signature)
    if not hmac.compare_digest(signature, expected_signature):
        return {'statusCode': 401, 'body': 'Invalid signature'}
        
        
    #Checking Git commit
    try:
        body = json.loads(event['body'])
    except (KeyError, json.JSONDecodeError):
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Invalid payload'})
        }

    # Get GitHub event type
    github_event = event['headers'].get('X-GitHub-Event') or event['headers'].get('x-github-event')

    if github_event == 'issue_comment':
        comment = body.get('comment', {}).get('body', '').lower()

        # Keywords to trigger on
        trigger_keywords = ['breaking:', 'feat:', 'fix:']

        if any(keyword in comment for keyword in trigger_keywords):
            print("✅ Triggered due to keyword match in comment:", comment)
             trigger(jenkins_url,jenkins_token)

            return {
                'statusCode': 200,
                'body': json.dumps({'message': "Build Triggered"})
            }
        else:
            print("No matching keyword found in comment: Please add breaking: , feat: , fix: ", comment)
            return {
                'statusCode': 200,
                'body': json.dumps({'message': "No matching keyword found in comment: Please add breaking: , feat: , fix: ."})
            }

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Ignored: Not an issue_comment event.'})
    }








   