import json
import logging
import os

import boto3
import botocore
from chalice import Chalice, Response, CognitoUserPoolAuthorizer, UnauthorizedError, BadRequestError
from pydantic import ValidationError

from chalicelib.models.registration import RegistrationDetail

##################
# Chalice app
##################
app = Chalice(app_name='telepoop-backend')
app.log.setLevel(logging.INFO)

##################
# Environment
##################
SECURITY_TOKEN_SECRET = os.getenv('security_token_secret')
TELEPOOP_APP_CLIENT = os.getenv('telepoop_app_client')

##################
# boto3
##################
cognito = boto3.client('cognito-idp')
sm = boto3.client('secretsmanager')

##################
# helper functions
##################
def retrieve_security_token(secret: str):
    secret_response = sm.get_secret_value(SecretId=secret)
    secret_string = json.loads(secret_response['SecretString'])
    return secret_string['security_token']


##################
# API routes
##################
@app.route('/user/register', methods=['POST'])
def register_user():
    try:
        registration_detail = RegistrationDetail(**app.current_request.json_body)
    except ValidationError as e:
        raise BadRequestError(e.errors())

    user_name = registration_detail.username
    user_password = registration_detail.password
    incoming_security_token = registration_detail.security_token
    expected_security_token = retrieve_security_token(SECURITY_TOKEN_SECRET)

    if incoming_security_token != expected_security_token:
        raise UnauthorizedError('Invalid security token.')
    
    try:
        cognito.sign_up(
            ClientId=TELEPOOP_APP_CLIENT,
            Username=user_name,
            Password=user_password
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPasswordException':
            msg = 'Password must be at least 8 characters long and contain a lowercase, uppercase, and special character.'
            app.log.error(msg)
            raise BadRequestError(msg)
        elif e.response['Error']['Code'] == 'UsernameExistsException':
            msg = 'Username already exists.'
            app.log.error('Username already exists.')
            raise BadRequestError(msg)
        else:
            raise e

    return Response(
        body='success',
        status_code=200,
        headers={'Content-Type': 'text/plain'}
    )


@app.route('/upload_file', methods=['POST'])
def upload_file():
    pass
