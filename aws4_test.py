__author__ = 'MATTHEWY'

import boto
import boto.s3.connection
from boto.s3.connection import Location
import requests
import json


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


def sign(msg):
    pass


def main():

    headers = {'Content-Type': 'application/json'}

    access = openstack['access_id']
    token = json.dumps('the_quick_brown_fox_jumps_over_the_lazy_dogs')
    signature = ''

    creds = {
        'credentials':
            {
                'access': access,
                'token': token,
                'signature': signature
            }
    }

    req = requests.post(
        'http://10.96.96.53:35357/v2.0/s3tokens',
        headers=headers,
        data=json.dumps(creds),
        verify=False
    )

    print req.text


if __name__ == '__main__':
    main()
