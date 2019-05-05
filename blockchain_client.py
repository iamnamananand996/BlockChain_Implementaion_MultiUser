'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template,url_for,session,flash,redirect
from functools import wraps

from blockChain import Blockchain


# Login Firebase
import pyrebase
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from firebase_admin import auth


cred = credentials.Certificate('key.json')
firebase_admin.initialize_app(cred)
db = firestore.client()


config = {
    "apiKey": "AIzaSyBDjvuxxp_ih4kxhIMDJM2dOFqRyyeoZ-E",
    "authDomain": "blockchain-1411b.firebaseapp.com",
    "databaseURL": "https://blockchain-1411b.firebaseio.com",
    "projectId": "blockchain-1411b",
    "storageBucket": "blockchain-1411b.appspot.com",
    "messagingSenderId": "810361715263"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()




MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value,username):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value
        self.username = username

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value,
                            'username': self.username})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')



app = Flask(__name__)

app.config['SECRET_KEY'] = 'ec830e5ae057c5b08f5a435a7b13e891'


blockchain = Blockchain()

@app.route('/')
def index():
    print(blockchain.chain)
    return render_template('./index.html')


@app.route('/login',methods=['POST','GET'])
def login():
    try:
        if session['username']:
            return render_template('index.html')
    except:
        if request.method == 'POST':

            email = request.form['username']
            password = request.form['password']
            # new_user = re.findall('.*(?=\@)',email)
            # print("new_user",new_user)
            user = auth.sign_in_with_email_and_password(email, password)
            if user:
                session['logged_in'] = True
                session['username'] = email
                flash('You are now logged in', 'success')
                return redirect(url_for('index'))

        return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/view/blockchain')
def blockChain_data():
    return render_template('./blockchain.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    print(random_gen)
    private_key = RSA.generate(1024, random_gen)
    print(private_key)
    public_key = private_key.publickey()
    print(public_key)
    print(binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'))
    
    response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}
    
    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']
    username = session['username']
    
    transaction = Transaction(sender_address, sender_private_key, recipient_address, value, username)
    print(transaction.to_dict())
    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}
    
    print(response)
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    print('come here')

    

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'], values['amount'], values['signature'],session['username'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        print(response)
        return jsonify(response), 201



@app.route('/chain', methods=['GET'])
def full_chain():
    chain = []
    for chains in blockchain.chain:
        if chains['username'] == session['username']:
            print(chains['username'])
            chain.append(chains)
    response = {
        'chain': chain,
        'length': len(chain),
    }
    return jsonify(response), 200

@app.route('/chain_all', methods=['GET'])
def blockChain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions
    print(transactions)
    # print(transactions[1]['username'])
    print(len(transactions))
    new_transaction = []
    for transaction in transactions:
        if transaction['username'] == session['username']:
            new_transaction.append(transaction)
        # print(transaction['username'])
    print(type(transactions))

    response = {'transactions': new_transaction}
    return jsonify(response), 200



@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()
    print(nonce)

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="",username=session['username'])

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash,session['username'])

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port,debug=True)