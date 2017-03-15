from flask import Flask, request, jsonify
from random import randint
import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


def stringify_json(json):
    result_string = ""
    for value in json.values():
        if type(value) is dict:
            result_string += stringify_json(value)
        else:
            result_string += str(value)

    return result_string


class Broker(object):
    def __init__(self):
        self.identity = 'broker'

        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey().exportKey(format='OpenSSH')

        self.signer = PKCS1_v1_5.new(self.private_key)

    def sign_json(self, json):
        hashable_str = stringify_json(json)
        h = SHA.new(hashable_str)

        return self.signer.sign(h)

    def authorize(self, authorization_request):
        authorization_request = dict(authorization_request)

        # validate required fields
        for field in ['identity', 'key']:
            if authorization_request.get(field, None) is None:
                return 404

        authorization_request['ip'] = request.remote_addr

        expiration = str((datetime.date.today() + datetime.timedelta(days=1)))
        authorization_request['expiration'] = expiration

        authorization_request['emitting_authority'] = self.identity

        authorization_request['authority_key'] = str(self.public_key).encode('base-64')

        authorization_request['credit_limit'] = randint(5, 100)

        signed_certificate = self.sign_json(authorization_request).encode('base-64')

        return {'message': authorization_request, 'signature': signed_certificate}

    def verify_commit(self, commit_request):
        if commit_request['message']['vendor_id'] != self.identity or\
                        commit_request['message']['chain_length'] \
                        > \
                        commit_request['message']['payword_certificate']['message']['credit_limit']:
            return None

        hashable_str = stringify_json(commit_request['message'])
        h = SHA.new(hashable_str)
        signer = PKCS1_v1_5.new(
            RSA.importKey(
                str(
                    commit_request['message']['payword_certificate']['message']['key']
                ).decode('base-64')
            )
        )

        return \
            signer.verify(h, str(commit_request['signature']).decode('base-64')) \
            and \
            self.verify_signature(commit_request['message']['payword_certificate'])

    @staticmethod
    def verify_signature(payword_certificate):
        hashable_str = stringify_json(payword_certificate['message'])
        h = SHA.new(hashable_str)

        signer = PKCS1_v1_5.new(RSA.importKey(str(payword_certificate['message']['authority_key']).decode('base-64')))

        return signer.verify(h, str(payword_certificate['signature']).decode('base-64'))


app = Flask("broker")
broker = Broker()


@app.route('/authorize', methods=['POST'])
def authorize():
    authorization_request = request.get_json(force=True, silent=True)
    response_json = broker.authorize(authorization_request)
    return jsonify(message=response_json['message'],signature=response_json['signature']), 200

app.run(port=4356)
