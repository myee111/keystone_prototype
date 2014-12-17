__author__ = 'matthewy'
import base64
import hmac
import hashlib
import json
import requests
import q

@q
def check_credential_keystone_s3(access_id, access_secret, msg):

    decoded = base64.urlsafe_b64decode(msg)
    keystone_server = 'http://10.96.96.53:35357/v2.0/s3tokens'
    signed_msg = base64.encodestring(hmac.new(access_secret, str(decoded), hashlib.sha1).digest()).strip()
    print signed_msg
    creds = {'credentials': {'access': access_id, 'token': msg, 'signature': signed_msg}}
    data = json.dumps(creds)

    req = requests.post(
        keystone_server,
        headers={'Content-Type': 'application/json'},
        data=data,
        verify=None
    )

    if req == 200:
        return True
    else:
        return False

# print check_credential_keystone_s3('1b3e0523f37a4542aeb67edf378f1eaf', '35484d5ca9214b3c81c58f72a0ffcd56',
#                                    'R0VUCgoKV2VkLCAxMCBEZWMgMjAxNCAyMjo0NzowNiBHTVQKLw==')

# print base64.urlsafe_b64decode('rVFr+pdYisUpW6I4aafP3wp5+J4=')
# print base64.urlsafe_b64decode('R0VUCgoKV2VkLCAxMCBEZWMgMjAxNCAyMjo0NzowNiBHTVQKLw==')

string = 'GET\n\n\nFri, 12 Dec 2014 17:43:23 GMT\n/'
# print base64.urlsafe_b64encode(string)
# secret = base64.encodestring(hmac.new('', string, hashlib.sha1).digest()).strip()
# print secret
#
# print string
# msg = base64.urlsafe_b64decode('R0VUCgoKRnJpLCAxMiBEZWMgMjAxNCAyMzowODoyMSBHTVQKLw==')
# print 'msg: ' + msg
# print base64.encodestring(hmac.new('35484d5ca9214b3c81c58f72a0ffcd56', msg, hashlib.sha1).digest()).strip()

access_key = '1b3e0523f37a4542aeb67edf378f1eaf'
secret_key = '35484d5ca9214b3c81c58f72a0ffcd56'
message = 'GET\n\n\nWed, 10 Dec 2014 17:26:09 GMT\n/'
hashed_message = base64.urlsafe_b64encode(message)
signed_message = base64.encodestring(hmac.new(secret_key, message, hashlib.sha1).digest()).strip()

print 'access key: ' + access_key
print 'secret key: ' + secret_key
print 'message: '
print message
print 'hashed message: ' + hashed_message
print 'signed message: ' + signed_message

print 'The AWS authorization header should be: ' + 'AWS ' + access_key + ':' + signed_message