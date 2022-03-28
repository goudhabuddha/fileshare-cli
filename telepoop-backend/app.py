import hashlib
import json
import logging
import os

import boto3
import botocore
from chalice import Chalice, Response, AuthResponse, UnauthorizedError, BadRequestError
from pydantic import ValidationError
from pynamodb.models import Model as PynamoDbModel
from pynamodb.attributes import UnicodeAttribute, BinaryAttribute, NumberAttribute

from chalicelib.models.registration import RegistrationDetail, EncodedPassword

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
USERS_TABLE = os.getenv('users_table')
AWS_REGION = os.getenv('aws_region')

##################
# Boto3
##################
cognito = boto3.client('cognito-idp')
sm = boto3.client('secretsmanager')
dynamodb = boto3.client('dynamodb')

##################
# PynamoDb models
##################
class UserModel(PynamoDbModel):
    class Meta:
        table_name = USERS_TABLE
        region = AWS_REGION
    username = UnicodeAttribute(hash_key=True)
    hash_method = UnicodeAttribute()
    salt = BinaryAttribute()
    rounds = NumberAttribute()
    hashed = BinaryAttribute()


##################
# Helper functions
##################
def security_token_is_valid(secret: str, security_token: str) -> bool:
    secret_response = sm.get_secret_value(SecretId=secret)
    secret_string = json.loads(secret_response['SecretString'])
    if secret_string['security_token'] != security_token:
        return False
    return True


def user_already_exists(username: str):
    try:
        UserModel.get(username)
        return True
    except UserModel.DoesNotExist:
        return False
    

def encode_password(password: str) -> EncodedPassword:
    salt = os.urandom(32)
    rounds = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, rounds)

    return EncodedPassword(hash_method='sha256', salt=salt, rounds=rounds, hashed=hashed)


##################
# API authorizer
##################
@app.authorizer(ttl_seconds=1800)
def api_auth(auth_request):
    token: str = auth_request.token
    #TODO:implement
    return AuthResponse(routes=[''], principal_id='id-todo')


##################
# API routes
##################
@app.route('/user/register', methods=['POST'])
def register_user() -> Response:
    try:
        registration_detail = RegistrationDetail(**app.current_request.json_body)
    except ValidationError as e:
        raise BadRequestError(e.errors())

    if security_token_is_valid(SECURITY_TOKEN_SECRET, registration_detail.security_token) is False:
        raise UnauthorizedError('Invalid security token.')

    if user_already_exists(registration_detail.username):
        raise BadRequestError('Username already exists.')

    encoded_password = encode_password(registration_detail.password)

    new_user = UserModel(
        hash_key=registration_detail.username,
        hash_method=encoded_password.hash_method,
        salt=encoded_password.salt,
        rounds=encoded_password.rounds,
        hashed=encoded_password.hashed
    )
    new_user.save()

    return Response(
        body='success',
        status_code=200,
        headers={'Content-Type': 'text/plain'}
    )


@app.route('/upload_file', methods=['POST'])
def upload_file() -> Response:
    pass
