import hashlib
import hmac
import logging
import os
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import boto3
import jwt
from chalice import (AuthResponse, BadRequestError, Chalice, Response,
                     UnauthorizedError)
from pydantic import BaseModel, ValidationError
from pynamodb.attributes import (BinaryAttribute, NumberAttribute,
                                 UnicodeAttribute)
from pynamodb.models import Model as PynamoDbModel

from chalicelib import config
from chalicelib.models.auth import AuthDetail, JWTDecoded
from chalicelib.models.registration import EncodedPassword, RegistrationDetail

##################
# Chalice app
##################
app = Chalice(app_name='telepoop-backend')
app.log.setLevel(logging.INFO)

##################
# Boto3
##################
cognito = boto3.client('cognito-idp')
ssm = boto3.client('ssm')
dynamodb = boto3.client('dynamodb')

##################
# PynamoDb models
##################
class UserModel(PynamoDbModel):
    class Meta:
        table_name = config.USERS_TABLE
        region = config.AWS_REGION
    username = UnicodeAttribute(hash_key=True)
    hash_method = UnicodeAttribute()
    salt = BinaryAttribute()
    rounds = NumberAttribute()
    hashed = BinaryAttribute()


##################
# Helper functions
##################
def security_token_is_valid(security_token: str) -> bool:
    expected_security_token = ssm.get_parameter(
        Name=config.TELEPOOP_SECURITY_TOKEN,
        WithDecryption=True
    )['Parameter']['Value']
    if expected_security_token != security_token:
        return False
    return True


def user_exists(username: str) -> bool:
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


def validate_request_body(body: Any, model: BaseModel):
    try:
        detail = model(**body)
    except ValidationError as e:
        raise BadRequestError(e.errors())
    return detail


def get_jwt_token(user: UserModel, password: str, secret: str):
    # generate a hash from the username and supplied password from the request
    actual = hashlib.pbkdf2_hmac(
        user.hash_method,
        password.encode('utf-8'),
        user.salt,
        user.rounds
    )
    # take the existing hash already stored for the user
    expected = user.hashed
    # compare the incoming hash to the existing hash
    if hmac.compare_digest(actual, expected):
        now = datetime.utcnow()
        payload = {
            'sub': user.username,
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(1), # tokens are valid for one day
            'jti': str(uuid4())
        }
        return jwt.encode(payload, secret, algorithm='HS256')
    raise UnauthorizedError('Invalid credentials.')


def get_jwt_key():
    return ssm.get_parameter(
        Name=config.TELEPOOP_JWT_KEY,
        WithDecryption=True
    )['Parameter']['Value']


##################
# API authorizer
##################
@app.authorizer(ttl_seconds=1800)
def api_auth(auth_request):
    token: str = auth_request.token
    decoded = JWTDecoded(**jwt.decode(token, get_jwt_key(), algorithms=['HS256']))
    if decoded.exp < datetime.utcnow():
        raise UnauthorizedError('Token expired.')
    return AuthResponse(routes=['*'], principal_id=decoded.sub)


##################
# API routes
##################
@app.route('/user/register', methods=['POST'])
def register_user() -> Response:
    registration_detail: RegistrationDetail = validate_request_body(app.current_request.json_body, RegistrationDetail)

    if not security_token_is_valid(registration_detail.security_token):
        raise UnauthorizedError('Invalid security token.')

    if user_exists(registration_detail.username):
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


@app.route('/auth/token', methods=['POST'])
def get_auth_token():
    auth_detail: AuthDetail = validate_request_body(app.current_request.json_body, AuthDetail)

    if user_exists(auth_detail.username):
        user = UserModel.get(auth_detail.username)
        jwt_token = get_jwt_token(
            user, auth_detail.password, get_jwt_key()
        )
        return {
            'access_token': jwt_token
        }
    else:
        raise UnauthorizedError('Invalid credentials.')


@app.route('/upload_file', methods=['POST'])
def upload_file() -> Response:
    pass
