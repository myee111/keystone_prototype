from flask import Flask, request, abort
import boto
import boto.s3.connection
from boto.s3.connection import Location
from keystoneclient.v2_0 import client
from keystoneclient.exceptions import AuthorizationFailure, Unauthorized
import q
import requests
import base64
import hmac
import hashlib
import json

app = Flask(__name__)

PUBLIC_ENDPOINT = 'http://10.96.96.53:5000/v2.0'

my_grid1 = {
    'name': 'mygrid1',
    'access_id': 'GFYMM7ES9K6FQSVCM5E8',
    'access_secret': 'n90teyZboWQENpUd3Wn5wdBLIBsmLz08bjRiRN6w',
    'host': '10.96.96.54',
    'port': 8082,
    'is_secure': True,
    'keystone_user': 'keystone_python_test_user',
    'keystone_password': 'netapp01'
}


class S3Conn:
    def __init__(self, credential):
        self.conn = boto.connect_s3(
            aws_access_key_id=credential['access_id'],
            aws_secret_access_key=credential['access_secret'],
            host=credential['host'],
            calling_format=boto.s3.connection.OrdinaryCallingFormat(),
            port=credential['port'],
            is_secure=credential['is_secure'],
        )


@app.route('/s3/buckets', methods=['GET', 'POST'])
def get_buckets():
    if request.method == 'GET':
        if check_credential_keystone_s3(str(request.headers['access_id']),
                                        str(request.headers['access_secret']),
                                        str(request.headers['token'])):
            return str(s3_get_buckets(my_grid1)), 201
        else:
            abort(404)
    if request.method == 'POST':
        if check_credential_keystone_s3(str(request.headers['access_id']),
                                        str(request.headers['access_secret']),
                                        str(request.headers['token'])):
            return str(s3_create_bucket(my_grid1, request.json['bucket'])), 202
        else:
            abort(404)


def return_buckets():
    if check_credential(request.json['access_id'], request.json['access_secret']):
            if auth_keystone(my_grid1) is True:
                return str(s3_get_buckets(my_grid1)), 201


def check_credential(access_id, access_secret, credential_dict):
    if credential_dict['access_id'] == access_id and credential_dict['access_secret'] == access_secret:
        return True
    else:
        return False

@q
def check_credential_keystone_s3(access_id, access_secret, msg):

    decoded = base64.urlsafe_b64decode(msg)
    keystone_server = 'http://10.96.96.53:35357/v2.0/s3tokens'
    signed_msg = base64.encodestring(hmac.new(access_secret, str(decoded), hashlib.sha1).digest()).strip()
    creds = {'credentials': {'access': access_id, 'token': msg, 'signature': signed_msg}}
    data = json.dumps(creds)

    req = requests.post(
        keystone_server,
        headers={'Content-Type': 'application/json'},
        data=data,
        verify=None
    )

    if req.text:
        return True
    else:
        return False


def auth_keystone(cred):
    if authenticate_user(cred['keystone_user'], cred['keystone_password'], PUBLIC_ENDPOINT):
        result = True
    else:
        result = False
    return result


def authenticate_user(user_name, password, url):
    # User authenticates to Keystone server using public endpoint.
    # Must specify a user, password and tenant.

    print 'Authenticating user: ' + user_name
    try:
        keystone = client.Client(username=user_name, password=password, auth_url=url)
        print 'User Token: ' + keystone.auth_token
    except AuthorizationFailure as af:
        print 'Authorization Failure: ' + af.message
    except Unauthorized as u:
        print 'Unauthorized: ' + u.message
    return keystone.auth_token

@q
def s3_get_buckets(credentials):
    grid = S3Conn(credentials)
    all_buckets = grid.conn.get_all_buckets()
    return all_buckets

@q
def s3_create_bucket(credential, bucket_name):
    q(credential)
    my_grid = S3Conn(credential)
    try:
        return my_grid.conn.create_bucket(bucket_name)
    except boto.exception.S3ResponseError, e:
        print e


if __name__ == '__main__':
    app.run()

