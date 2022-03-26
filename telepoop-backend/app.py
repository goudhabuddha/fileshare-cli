from chalice import Chalice
import boto3
import logging

##################
# Chalice app
##################
app = Chalice(app_name='telepoop-backend')
app.debug = True
app.log.setLevel(logging.DEBUG)

##################
# boto3
##################
cognito = boto3.client('cognito-idp')
sm = boto3.client('secretsmanager')

@app.route('/user/register', methods=['POST'])
def register_user():
    registration_detail = app.current_request.json_body

    user_name = registration_detail['username']
    user_password = registration_detail['password']
    security_token = registration_detail['security_token']

    app.log.debug(f'incoming security token: {security_token}')

    




    return {'hello': 'world'}
