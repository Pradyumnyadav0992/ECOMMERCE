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


def lambda_handler(event, context):

    jenkins_url = "http://ecommerce-alb-868586226.us-west-2.elb.amazonaws.com"
    secret_name = 'ECOMMERC_SECRETS'
    secrets = get_secret(secret_name)


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
            'jenkins_url': jenkins_url,
            # Avoid returning sensitive tokens in real responses
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

   