import json
import os

# this script runs in the github-actions workflow to gleam environment variable values from the repository secrets

CONFIG_PATH = 'telepoop-backend/.chalice/config.json'

with open(CONFIG_PATH, 'r') as f:
    chalice_config: dict = json.load(f)

try:
    shared_env = chalice_config['environment_variables']
except KeyError as e:
    chalice_config['environment_variables'] = {}
    shared_env = chalice_config['environment_variables']

try:
    shared_env['users_table'] = os.environ['USERS_TABLE']
    shared_env['aws_region'] = os.environ['AWS_REGION']
    shared_env['telepoop_jwt_key'] = os.environ['TELEPOOP_JWT_KEY']
    shared_env['telepoop_security_token'] = os.environ['TELEPOOP_SECURITY_TOKEN']
    shared_env['telepoop_app_client'] = os.environ['TELEPOOP_APP_CLIENT']
except KeyError as e:
    print(f'Required environment variable {str(e)} is missing.')
    raise KeyError

chalice_config['environment_variables'] = shared_env


with open(CONFIG_PATH, 'w') as f:
    json.dump(chalice_config, f)
