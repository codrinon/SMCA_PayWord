from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, request, jsonify


def stringify_json(json):
    result_string = ""
    for value in json.values():
        if type(value) is dict:
            result_string += stringify_json(value)
        else:
            result_string += str(value)

    return result_string


class Vendor(object):
    def __init__(self):
        self.identity = 'vendor'
        self.users = dict()

    def accept_payment(self, payment):
        paying_user = str(payment['identity'])
        token = str(payment['token']).decode('base-64')
        ammount = payment['sum']

        h = token
        for i in xrange(0, ammount):
            h = SHA.new(h).digest()

        if h != self.users[paying_user]['last_token']:
            return False

        self.users[paying_user]['last_token'] = h
        self.users[paying_user]['sum'] = self.users[paying_user]['sum'] + ammount
        return True

    def accept_commit(self, commit_request):
        if self.verify_commit(commit_request):
            user_id = commit_request['message']['payword_certificate']['message']['identity']
            self.users[user_id] = {
                'payword_certificate': commit_request['message']['payword_certificate'],
                'last_token': str(commit_request['message']['hash_chain_root']).decode('base-64'),
                'sum': 0
            }

            return True

        return False

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

vendor = Vendor()
app = Flask('Vendor')


@app.route('/commit', methods=['POST'])
def on_commit():
    commit = request.get_json(force=True, silent=True)
    response = vendor.accept_commit(commit)
    if response:
        return jsonify({"accepted": True}), 200
    return jsonify({"accepted": False}), 400


@app.route('/pay', methods=['POST'])
def on_payment():
    payment = request.get_json(force=True, silent=True)
    response = vendor.accept_payment(payment)
    if response:
        return jsonify({"accepted": True}), 200
    return jsonify({"accepted": False}), 400

app.run(port=4359)
