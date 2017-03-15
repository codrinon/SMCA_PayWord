from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
import requests
from random import randint
from os import urandom


def stringify_json(json):
    result_string = ""
    for value in json.values():
        if type(value) is dict:
            result_string += stringify_json(value)
        else:
            result_string += str(value)

    return result_string


class User(object):
    def __init__(self):
        self.identity = 'user'

        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey().exportKey('OpenSSH')

        self.signer = PKCS1_v1_5.new(self.private_key)

        self.payword_certificate = None
        self.coins = []
        self.last_used_token = None

    def get_payword_cert(self):
        payword_certificate = requests.post(
            "http://localhost:4356/authorize",
            json={'identity': self.identity, 'key': str(self.public_key).encode('base-64')}
        ).json()

        if self.verify_signature(payword_certificate):
            self.payword_certificate = payword_certificate

        else:
            print "Did not get a PayWord certificate"

    def get_coins(self):
        n = randint(1, int(self.payword_certificate['message']['credit_limit']) + 10)
        first_token = urandom(64)
        self.coins.append(first_token)
        for i in range(1, n):
            self.coins.append(SHA.new(str(self.coins[len(self.coins) - 1])).digest())

        self.last_used_token = len(self.coins) - 1

    def commit_to_vendor(self, vendor_id):
        commit = {
            'vendor_id': vendor_id,
            'payword_certificate': self.payword_certificate,
            'hash_chain_root': str(self.coins[len(self.coins) - 1]).encode('base-64'),
            'chain_length': len(self.coins)
        }

        response_on_commit = requests.post(
            'http://localhost:4359/commit',
            json={'message': commit, 'signature': str(self.sign_json(commit)).encode('base-64')}
        ).status_code

        if response_on_commit is 200:
            print "Commit Successful"
        else:
            print "Commit denied"

    def pay_vendor(self, coins):
        self.last_used_token -= coins
        response_on_payment = requests.post(
            'http://localhost:4359/pay',
            json={
                'identity': self.identity,
                'token': str(self.coins[self.last_used_token]).encode('base-64'),
                'sum': coins
            }
        ).status_code

        if response_on_payment is 200:
            print "Commit Successful"
        else:
            print "Commit denied"

    def sign_json(self, json):
        hashable_str = stringify_json(json)
        h = SHA.new(hashable_str)

        return self.signer.sign(h)

    @staticmethod
    def verify_signature(payword_certificate):
        hashable_str = stringify_json(payword_certificate['message'])
        h = SHA.new(hashable_str)

        signer = PKCS1_v1_5.new(RSA.importKey(str(payword_certificate['message']['authority_key']).decode('base-64')))

        return signer.verify(h, str(payword_certificate['signature']).decode('base-64'))


user = User()
user.get_payword_cert()
user.get_coins()
user.commit_to_vendor('vendor')
user.pay_vendor(5)
