import json
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):

    # 'queryStringParameters' passed via HTTP API gw on GET method
    # 'keyword' is the name of the input field in the html form sec.html
    data = event['queryStringParameters']['keyword']
    secret_name = data.lower()
    region_name = "us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    secret = json.loads(secret)
    # Your code goes here.
    for x, y in secret.items():
        user = "Username: " + x
        passw = "Password: " + y
        return (user + '\n' + passw)

    # return secret
