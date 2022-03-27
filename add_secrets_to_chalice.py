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
    shared_env['cognito_user_pool'] = os.environ['COGNITO_USER_POOL']
    shared_env['security_token_secret'] = os.environ['SECURITY_TOKEN_SECRET']
    shared_env['telepoop_app_client'] = os.environ['TELEPOOP_APP_CLIENT']
except KeyError as e:
    print(f'Required environment variable {str(e)} is missing.')
    raise KeyError

chalice_config['environment_variables'] = shared_env


with open(CONFIG_PATH, 'w') as f:
    json.dump(chalice_config, f)
