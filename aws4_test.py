__author__ = 'MATTHEWY'

import boto
import boto.s3.connection
from boto.s3.connection import Location
import requests
from keystoneclient.v2_0 import client
from keystoneclient.exceptions import AuthorizationFailure, Unauthorized
import json
import hashlib
import hmac

admin_token = '744e5660f5d746ea88bb9d7dc80ad78e'

openstack = {
    'name': 'openstack',
    'access_id': '1b3e0523f37a4542aeb67edf378f1eaf',
    'access_secret': '35484d5ca9214b3c81c58f72a0ffcd56',
    'host': '10.96.96.53',
    'port': 35357,
    'is_secure': True
}

credential_my_grid = {
    'name': 'mygrid1',
    'access_id': 'GFYMM7ES9K6FQSVCM5E8',
    'access_secret': 'n90teyZboWQENpUd3Wn5wdBLIBsmLz08bjRiRN6w',
    'host': '10.96.96.54',
    'port': 8082,
    'is_secure': True
}

mirantis = {
    'name': 'mirantis',
    'access_id': '2fe83d85502d4dda90fa802c39603f99',
    'access_secret': 'fda6d4ddfe6b4db4afde06028de96c68',
    'host': '158.85.165.2',
    'port': 35357,
    'is_secure': True
}

USER = 'keystone_python_test_user'
USER_PASSWORD = 'netapp01'
PUBLIC_ENDPOINT = 'http://10.96.96.53:5000/v2.0'

keystone_python_test_user = {
    'name': 'keyston_python_test_user',
    'access_id': '044980ca5e5a4766a9659cb3fef712c4',
    'access_secret': 'f2ece77030ee489ea669f9be7fa60b40',
    'host': '10.96.96.53',
    'port': 35357,
    'is_secure': True
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


def list_buckets(bucket_list):
    for bucket in bucket_list:
        print 'Buckets: '
        print bucket.name + ' ' + bucket.creation_date


def s3_test(credential):
    my_grid = S3Conn(credential)
    print 'Listing buckets.'
    all_buckets = my_grid.conn.get_all_buckets()
    print all_buckets
    list_buckets(my_grid.conn.get_all_buckets())


def string_sign(msg):
    pass


def authenticate_user(user_name, password, url):
    # User authenticates to Keystone server using public endpoint.
    # Must specify a user, password and tenant.

    print 'Authenticating user: ' + user_name
    try:
        keystone = client.Client(username=user_name, password=password, auth_url=url)
        print 'User Token: ' + keystone.auth_token
        return keystone.auth_token
    except AuthorizationFailure as af:
        print 'Authorization Failure: ' + af.message
        return af
    except Unauthorized as u:
        print 'Unauthorized: ' + u.message
        return u


def verify_token(user_token, admin_endpoint):
    # Verify a user token via private endpoint.
    # Requires the user token to be verified, an admin token and the private admin endpoint.

    print 'Verifying token: ' + user_token

    admin_client = client.Client(token=user_token, auth_url=admin_endpoint)

    try:
        result = admin_client.tokens.authenticate(token=user_token)
        print 'The result is: '
        print json.dumps(result.token, indent=4)
    except Unauthorized as u:
        print 'Unauthorized: ' + u.message
    except Exception as e:
        print 'Exception: ' + e.message


def canonical_request_string(input_string):
    return input_string


def string_sign(input_string, key):
    return hmac.new(key, input_string.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = string_sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = string_sign(k_date, region_name)
    k_service = string_sign(k_region, service_name)
    k_signing = string_sign(k_service, "aws4_request")
    return k_signing


def main():

    headers = {'Content-Type': 'application/json'}

    access = keystone_python_test_user['access_id']
    signature = ''

    creds = {
        'credentials':
            {
                'access': access,
                'token': 'f2ece77030ee489ea669f9be7fa60b40',
                'signature': signature
            }
    }

    req = requests.post(
        'http://10.96.96.53:35357/v2.0/s3tokens',
        headers=headers,
        data=json.dumps(creds),
        verify=False
    )

    # print json.dumps(json.loads(req.text), indent=4)

    # verify_token(token, 'http://10.96.96.53:35357/v2.0')

    print get_signature_key(openstack['access_secret'], )


if __name__ == '__main__':
    main()
