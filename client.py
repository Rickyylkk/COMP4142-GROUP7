#Library for networking
import pickle
import socket
import sys
import threading

import os

import hashlib #importing hashing library
import time

import rsa

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender        #Who send the transaction
        self.receiver = receiver    #The receiver of this transaction
        self.amounts = amounts      #The amount of this transaction
        self.fee = fee              #Handling fee of this transaction
        self.message = message      #The message of the transaction
     
def handle_receive():
    while True:
        response = client.recv(4096)
        if response:
            print(f"[*] Message from node: {response}")

def generate_address():
#Generate public and private key, the public key will be the user address and the key will save as pkcs1 format
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()

    #Put keys into a txt file
    f = open("client_key.txt", "w")
    
    #Save private keys  
    f.write(f"You Public key (address): " + get_address_from_public(public_key))
    f.write(" \n\n ")
    f.write(f"Your private key: " + get_address_from_private(private_key))
    
    f.close()

    return get_address_from_public(public_key), get_address_from_private(private_key)
    
def get_address_from_public(public):
#Get trimed public address
    addr = str(public).replace('\\n','')            #Remove useless part after the keypair generation
    addr = addr.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    addr = addr.replace("-----END RSA PUBLIC KEY-----'", '')
    addr = addr.replace(' ', '')
    return addr

def get_address_from_private(private):
#Get trimed private address
    key = str(private).replace('\\n','')            #Remove useless part after the keypair generation
    key = key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    key = key.replace("-----END RSA PRIVATE KEY-----'", '')
    key = key.replace(' ', '')
    return key

def transaction_to_string(transaction):   #Turn the transaction information into a string     
    transaction_info = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
        }
    return str(transaction_info)
    

def initialize_transaction(sender, receiver, amount, fee, message):
#Initailize the transaction and no need to check balance in client side 
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction

def sign_transaction(transaction, private):
#Transaction siging
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))       #Load the rsa private key which saved as pkcs1
    transaction_str = transaction_to_string(transaction)       
    signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-256')  #Sign the transaction by using 'sign' function from rsa library
    return signature
    
if __name__ == '__main__':
    try:
        #connect to the mining node
        target_host = "127.0.0.1"
        target_port = int(sys.argv[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_host, target_port))

        receive_handler = threading.Thread(target=handle_receive, args=())
        receive_handler.start()

        command_dict = {
            "1": "generate_address",
            "2": "get_balance",
            "3": "transaction"
        }

        while True:
            print("Command list:")
            print("1. generate_address")
            print("2. get_balance")
            print("3. transaction")
            command = input("Command: ")
            if str(command) not in command_dict.keys():
                print("Unknown command.")
                continue
            message = {
                "request": command_dict[str(command)]
            }
            if command_dict[str(command)] == "generate_address":
                address, private_key = generate_address()
                print(f"Address: {address}")
                print(f"Private key: {private_key}")

            elif command_dict[str(command)] == "get_balance":
                address = input("Address (Public key): ")
                message['address'] = address
                client.send(pickle.dumps(message))

            elif command_dict[str(command)] == "transaction":
                address = input("Sender address/public key: ")
                private_key = input("Sender private_key: ")
                receiver = input("Receiver adress/public key: ")
                amount = input("Amount of payment: ")
                fee = input("Handling fee: ")
                comment = input("Comment: ")
                new_transaction = initialize_transaction(
                    address, receiver, int(amount), int(fee), comment
                )
                signature = sign_transaction(new_transaction, private_key)
                message["data"] = new_transaction
                message["signature"] = signature

                client.send(pickle.dumps(message))

            else:
                print("Unknown command.")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)



