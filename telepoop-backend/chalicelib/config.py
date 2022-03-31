import os

##################
# Environment
##################
TELEPOOP_SECURITY_TOKEN = os.getenv('telepoop_security_token')
USERS_TABLE = os.getenv('users_table')
AWS_REGION = os.getenv('aws_region')
TELEPOOP_JWT_KEY = os.getenv('telepoop_jwt_key')