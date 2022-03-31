import os

##################
# Environment
##################
TELEPOOP_SECURITY_TOKEN = os.getenv('telepoop_security_token')
TELEPOOP_APP_CLIENT = os.getenv('telepoop_app_client')
USERS_TABLE = os.getenv('users_table')
AWS_REGION = os.getenv('aws_region')
TELEPOOP_JWT_KEY = os.getenv('telepoop_jwt_key')