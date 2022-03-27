import json
import logging
import os

import boto3
from chalice import Chalice, UnauthorizedError


##################
# Chalice app
##################
app = Chalice(app_name='telepoop-backend')
app.debug = True
app.log.setLevel(logging.DEBUG)

##################
# Environment
##################
SECURITY_TOKEN_SECRET = os.getenv('security_token_secret')

##################
# boto3
##################
cognito = boto3.client('cognito-idp')
sm = boto3.client('secretsmanager')

##################
# helper functions
##################
def retrieve_security_token(secret: str):
    response = sm.get_secret_value(SecretId=secret)
    secret_string = json.loads(response['SecretString'])
    return secret_string['security_token']


##################
# API routes
##################
@app.route('/user/register', methods=['POST'])
def register_user():
    registration_detail = app.current_request.json_body

    user_name = registration_detail['username']
    user_password = registration_detail['password']
    incoming_security_token = registration_detail['security_token']
    expected_security_token = retrieve_security_token(SECURITY_TOKEN_SECRET)

    app.log.debug(f'incoming security token: {incoming_security_token}')
    app.log.debug(f'expected security token: {expected_security_token}')

    if incoming_security_token != expected_security_token:
        raise UnauthorizedError('Invalid security token.')

    return {'hello': 'world'}
