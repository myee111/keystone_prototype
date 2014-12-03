__author__ = 'MATTHEWY'

import requests
from awsauth import S3Auth

my_grid = {
    'name': 'mygrid1',
    'access_id': 'GFYMM7ES9K6FQSVCM5E8',
    'access_secret': 'n90teyZboWQENpUd3Wn5wdBLIBsmLz08bjRiRN6w',
    'host': '10.96.96.54',
    'port': 8082,
    'is_secure': True
}


credential_s3 = {'name': 's3',
                 'access_id': 'AKIAIX63ID7CZSG6PVPA',
                 'access_secret': '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',
                 'host': 's3.amazonaws.com',
                 'port': 443}


def auth(cred):
    # Authenticate against S3, return auth dict.
    AWS_ACCESS_KEY_ID = cred['access_id']
    AWS_SECRET_ACCESS_KEY = cred['access_secret']
    BASE_URL = cred['host']
    PORT = cred['port']

    req = requests.get('https://' + BASE_URL + ':' + str(PORT), auth=S3Auth(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), verify=False)
    return req


def test(cred):
    AWS_ACCESS_KEY_ID = cred['access_id']
    AWS_SECRET_ACCESS_KEY = cred['access_secret']
    BASE_URL = cred['host']
    PORT = cred['port']

    s = 'The quick brown fox jumps over the lazy dogs.'
    req = requests.put('https://' + BASE_URL + ':' + str(PORT) + '/file.txt', data=s, auth=S3Auth(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), verify=False)
    print req

    req = requests.get('https://' + BASE_URL + ':' + str(PORT) + '/file.txt', auth=S3Auth(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), verify=False)
    print req.text


def main():
    # print auth(my_grid)
    # print auth(credential_s3)
    # test(my_grid)
    test(credential_s3)

if __name__ == '__main__':
    main()