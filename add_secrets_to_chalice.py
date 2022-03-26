import os
import json

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
    shared_env['cognito_user_pool'] = os.environ['cognito_user_pool']
    shared_env['security_token_secret'] = os.environ['security_token_secret']
except KeyError as e:
    print(f'Required environment variable {str(e)} is missing.')
    raise KeyError

chalice_config['environment_variables'] = shared_env


with open(CONFIG_PATH, 'w') as f:
    json.dump(chalice_config)