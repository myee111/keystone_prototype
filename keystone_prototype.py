from flask import Flask, request, abort
import boto
import boto.s3.connection
from boto.s3.connection import Location
import q
import requests
import base64
import hmac
import hashlib
import json

app = Flask(__name__)

PUBLIC_ENDPOINT = 'http://10.96.96.53:5000/v2.0'
KEYSTONE_SERVER_S3 = 'http://10.96.96.53:35357/v2.0/s3tokens'

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


@app.route('/mygrid1', methods=['GET', 'POST'])
def middleware():

    if request.method == 'GET':
        if check_keystone_token(str(request.headers['access_id']),
                                str(request.headers['signed_msg']),
                                str(request.headers['token'])):
            return str(s3_get_buckets(my_grid1)), 201
        else:
            abort(404)

    if request.method == 'POST':
        if check_keystone_token(str(request.headers['access_id']),
                                str(request.headers['signed_msg']),
                                str(request.headers['token'])):
            return str(s3_create_bucket(my_grid1, request.json['bucket'])), 202
        else:
            abort(404)


@app.route('/', methods=['GET'])
def dump():
    headers = request.headers
    print headers
    return headers, 203


def check_credential_keystone_s3(access_id, access_secret, msg):

    decoded = base64.urlsafe_b64decode(msg)
    keystone_server = 'http://10.96.96.53:35357/v2.0/s3tokens'
    # The signed_msg should be calculated by the client and should be passed through in the POST request.
    # That way the secret key doesn't need to be sent in the request.
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


def check_keystone_token(access_id, signed_msg, token):
    data = json.dumps({'credentials': {'access': access_id, 'token': token, 'signature': signed_msg}})
    req = requests.post(
        KEYSTONE_SERVER_S3,
        headers={'Content-Type': 'application/json'},
        data=data,
        verify=None
    )

    if req.text:
        return True
    else:
        return False


def s3_get_buckets(credentials):
    grid = S3Conn(credentials)
    all_buckets = grid.conn.get_all_buckets()
    return all_buckets


def s3_create_bucket(credential, bucket_name):
    my_grid = S3Conn(credential)
    try:
        return my_grid.conn.create_bucket(bucket_name)
    except boto.exception.S3ResponseError, e:
        print e


if __name__ == '__main__':
    app.run()

