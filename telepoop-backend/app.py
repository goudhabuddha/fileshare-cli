import json
import logging
import os

import boto3
from chalice import Chalice, UnauthorizedError, BadRequestError
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
    
    cognito.sign_up(
        ClientId=TELEPOOP_APP_CLIENT,
        Username=user_name,
        Password=user_password
    )

    return {'hello': 'world'}
