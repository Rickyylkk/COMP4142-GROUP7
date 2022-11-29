#Library for networking
import pickle   
import socket
import sys
import threading

import os

from pw import *
import pymysql

import hashlib #importing hashing library
import time
import random
import rsa



# Part 1: Block, chain and transaction structure

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender        #Who send the transaction
        self.receiver = receiver    #The receiver of this transaction
        self.amounts = amounts      #The amount of this transaction
        self.fee = fee              #Handling fee of this transaction
        self.message = message      #The message of the transaction
     
class Block:
    def __init__(self, index, previous_hash, difficulty, miner):
        self.index = index                      #Height of block
        self.merkle_root = ""                                         
        self.previous_hash = previous_hash      #Hash of the previous block
        self.hash = ''                          #Hash of the current block
        self.difficulty = difficulty            #Difficulty of the current block aka how many 0s 
        self.nonce = 0                          #The key of the hash
        self.timestamp = int(time.time())       #Time that the block has been mined
        self.transactions = []                  #The transaction information in this block
        self.miner = miner                      #The miner of this block
        
 
class Blockchain:
    def __init__(self):
        self.adjust = 5                       #The mining difficulty will change after mined this value of block
        self.difficulty = 1                     #The default difficulty 
        self.block_time = 30                    #The ideal time for mining a block
        self.block_limitation = 32              #The maximum amount of transaction that can be included in a block to prevent network latency
        self.chain = []                         #The chain to save all the blocks
        self.pending_transactions = []          #Since the transaction number is limited, the miner will proccess with the transaction with high transaction fee first
        self.transaction_hash = []              #Saving the hash of each processed transaction
        
        # Storage

        self.db_setting = {
            "host": "127.0.0.1",
            "port": 3306,
            "user": "ricky",
            "password": password(),
            "db": "4142",
            "charset": "utf8"
        }

        # P2P connection

        self.socket_host = "127.0.0.1"
        self.socket_port = int(sys.argv[1])
        self.node_address = {f"{self.socket_host}:{self.socket_port}"}
        self.connection_nodes = {}
        if len(sys.argv) == 3:
            self.clone_blockchain(sys.argv[2])
            print(f"Node list: {self.node_address}")
            self.broadcast_message_to_nodes("add_node", self.socket_host+":"+str(self.socket_port))

        # For broadcast block
        self.receive_verified_block = False
        self.start_socket_server()
            

# Part 2: Build first block and start mining

    def create_genesis_block(self): #Generate a genesis block
        print("The first block is generated....")
        genesis_block = Block(1, 'Genesis', self.difficulty, 'rickylau')    #Putting the block information in the genesis block in form of (`index, previous_hash, difficulty, miner,` miner_rewards)
        genesis_block.hash = self.get_hash(genesis_block, 0)    #Get the hashed value of the genesis block  
        self.chain.append(genesis_block)    #Append the genesis block into the chain

    def mysql_block_table(self):
        # Generate table in mysql
        db = pymysql.connect(**self.db_setting)
        cursor = db.cursor()

        cursor.execute("DROP TABLE IF EXISTS block")
        sql = """CREATE TABLE `block` (
         `index`  VARCHAR(255) NOT NULL,
         `merkle_root` VARCHAR(255),
         `previous_hash` VARCHAR(255),
         `hash` VARCHAR(255),
         `difficulty` VARCHAR(10),
         `nonce` VARCHAR(255),
         `timestamp` VARCHAR(255),  
         `miner` VARCHAR(255),
         `transaction` VARCHAR(255))"""

        cursor.execute(sql)

        db.close()

    def mysql_transaction_table(self):
        # Generate table in mysql
        db = pymysql.connect(**self.db_setting)
        cursor = db.cursor()

        cursor.execute("DROP TABLE IF EXISTS transactions")
        sql = """CREATE TABLE `transactions` (
         `sender`  VARCHAR(255) NOT NULL,
         `receiver` VARCHAR(255),
         `amounts` VARCHAR(255),
         `fee` VARCHAR(100),
         `message` VARCHAR(255))"""

        cursor.execute(sql)

        db.close()


    def mine_block(self, miner):
    #Mining process aka proof of work algorithm
        start = time.process_time() #Recording the start time

        last_block = self.chain[-1] #[-1] is last item of an array in here it means the last block of the chain.
        new_block = Block(last_block.index + 1, last_block.hash, self.difficulty, miner)
        #Put stuffs in the new block in a format of (index, previous_hash, difficulty, miner, miner_rewards)
        
        self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)
        new_block.nonce = random.getrandbits(32)    #Preventing blocks will always mined by highest computing power system 


        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
        #Check if the block hash fulfil the difficulty of the block
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

            if self.receive_verified_block:
                print(f"[**] Verified received block.... Mine next....")
                self.receive_verified_block = False
                return False
        
        self.broadcast_block(new_block)

        # use a temporary array to store each value in the block
        
        tmp = []

        for i in self.block_to_string(new_block).values():
            tmp.append(str(i))
        
        db = pymysql.connect(**self.db_setting)
        cursor = db.cursor()
        
        sql = """insert into `block` (`index`, `merkle_root`, `previous_hash`, `hash`, `difficulty`, `nonce`, `timestamp`, `miner`, `transaction`)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""

        cursor.execute(sql,(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8]))
        db.commit()

        db.close()
        

        time_consumed = round(time.process_time() - start, 5)   #Calculate the round time of a mining process
        print(f"New block Hash: {new_block.hash} with nonce: {new_block.nonce}\nPrevious Hash: {new_block.previous_hash}, Height: {new_block.index} , difficulty: {self.difficulty}, time cost: {time_consumed} ")
        
        #Chain validation
        if last_block.hash == new_block.previous_hash:
            print("Chain valid, keep mining!!!")
            self.chain.append(new_block)
        else:
            print("Chain is invalid!!")
        

    def get_hash(self, block, nonce):
        s = hashlib.sha256()            #Creating a variable that use sha256 to encrypt the information
        s.update(                       #update the information in byte-like
            (
                str(block.index)
                +block.previous_hash     #The previous block hash inside the current block
                + str(block.timestamp)  #The timestamp of the current block
                + self.get_transactions_string(block)   #Use the function to get transaction string
                + str(nonce)    #The nonce of the current block
            ).encode("utf-8")   #Encode the information with UTF-8
        )
        h = s.hexdigest()       #Return a string onject of with only hexadecimal digits
        return h                #Return the hashed information
        

# Part 3: Dynamic difficulty Proof of Work

    def adjust_difficulty(self):
    #Function to make the mining process with a dynamic difficulty
        if len(self.chain) % self.adjust != 0:
            return self.difficulty
        elif len(self.chain) <= self.adjust:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust-1].timestamp      #Calculate a start time of mining a block
            finish = self.chain[-1].timestamp                   #Calculate the finish time of mining a block
            average_time_consumed = round((finish - start) / (self.adjust), 2)  #Calculate the average consumed time of mining a block
            if average_time_consumed > self.block_time:         #If the average consume time is greater than the ideal block mining time, the difficulty will decrease
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:                                               #If the average consume time is lesser than the ideal block mining time, the difficulty will increase
                print(f"Average mining time:{average_time_consumed}s. Increasing difficulty by dynamic PoW")
                self.difficulty += 1
   

# Part 4: Basic transaction processing

    def block_to_string(self, block):
        block_data ={
            'index': str(block.index),
            'merkle_root' : str(block.merkle_root),
            'previous_hash' : str(block.previous_hash),
            'hash' : str(block.hash),
            'difficulty' : block.difficulty,
            'nonce' : block.nonce,
            'timestamp' : str(block.timestamp),
            'miner' : str(block.miner),
            'transaction' : block.transactions
        }
        return block_data

    def transaction_to_string(self, transaction):   #Turn the transaction information into a string     
        transaction_info = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_info)

    def transaction_to_dict(self, transaction):   #Turn the transaction information into a dict     
        transaction_info = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': str(transaction.amounts),
            'fee': str(transaction.fee),
            'message': str(transaction.message)
        }
        return transaction_info
        
    def get_transactions_string(self, block):       #Getting a transaction string from a block
        t_str = ''      #An empty string
        for transaction in block.transactions:  #Using for loop to get each transaction data in a block
            t_str += self.transaction_to_string(transaction)    #Putting the transaction information together with the transaction to string function (def transaction_to_string)
        return t_str    #Return the string
    
   
    def add_transaction_to_block(self, block):
    # Get the transaction with highest fee by block_limitation
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True) #Sort the transaction value form descending order (reverse=True) by comparing with transaction.fee (key=lambda x: x.fee)
        if len(self.pending_transactions) > self.block_limitation:
        #What will happen if the pending transaction number is larger than the maximum transaction amount.
            transcation_accepted = self.pending_transactions[:self.block_limitation] #Choose the first item to be the accepted transaction after sorting *Refer to array slicing: https://stackoverflow.com/questions/509211/understanding-slicing
            self.pending_transactions = self.pending_transactions[self.block_limitation:] #Reset the pending transaction 
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        
        block.transactions = transcation_accepted
        
        

    
       
    def get_balance(self, account):
    #Function to get the balance of an account
        current_balance = 0
        for block in self.chain:
            # Check miner reward
            miner = False
            if block.miner == account:                      #If block miner is same as the account name, the reward will add to his balance.
                miner = True    
                current_balance += 10
            for transaction in block.transactions:          
                if miner:                                   #Add transaction handling fee to miner if the transaction maker is miner.
                    current_balance += transaction.fee
                if transaction.sender == account:
                    current_balance -= transaction.amounts  #Deduct balance if the transaction maker is sender.
                    current_balance -= transaction.fee
                elif transaction.receiver == account:       #Add balance if the transaction maker is receiver.
                    current_balance += transaction.amounts
        return current_balance  

#Part 5: Get miner own public and private key in pkcs1 
       
    def generate_address(self):
    #Generate public and private key, the public key will be the user address and the key will save as pkcs1 format
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        return self.get_address_from_public(public_key), self.get_address_from_private(private_key)
    
    def get_address_from_public(self, public):
    #Get trimed public address
        addr = str(public).replace('\\n','')            #Remove useless part after the keypair generation
        addr = addr.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        addr = addr.replace("-----END RSA PUBLIC KEY-----'", '')
        addr = addr.replace(' ', '')
        return addr
    
    def get_address_from_private(self, private):
    #Get trimed private address
        key = str(private).replace('\\n','')            #Remove useless part after the keypair generation
        key = key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
        key = key.replace("-----END RSA PRIVATE KEY-----'", '')
        key = key.replace(' ', '')
        return key

# Part 6: Transaction signing with RSA

    def initialize_transaction(self, sender, receiver, amount, fee, message):
    #Initailize the transaction
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction
    
    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            return False , "Balance not enough!"
        try:
            # Verify the sender
            rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)

            '''
            result = self.pending_transactions.append(transaction)
            if result == 'None':
                # Save transaction hash
                s = hashlib.sha256()
                s.update(self.transaction_to_string(transaction))
                hash = s.digest()
                self.transaction_hash.append(hash)
            '''

            #print(dir(transaction))
            tmp = []

            for i in self.transaction_to_dict(transaction).values():
                tmp.append(str(i))
                

            db = pymysql.connect(**self.db_setting)
            cursor = db.cursor()
            
            sql = """insert into `transactions` (`sender`, `receiver`, `amounts`, `fee`, `message`)
                values (%s, %s, %s, %s, %s)"""
            
            cursor.execute(sql,(str(tmp[0]), str(tmp[1]), str(tmp[2]), str(tmp[3]), str(tmp[4])))
            db.commit()

            db.close()


            return True, "Authourized"
        except Exception:
            print("Failed RSA verification....")

# Part 7: Start network socket
    
    def start_socket_server(self):
        t = threading.Thread(target=self.wait_for_socket_connection)
        t.start()


    def wait_for_socket_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:        #Choose the address family, which is IPv4 in this session
            s.bind((self.socket_host, self.socket_port))                    #Assigns an IP address and a port number to a socket instance                   
            s.listen()                                                      #Listen for incoming session
            while True:
            #If a connection is received, start the 
                conn, address = s.accept()
                client_handler = threading.Thread(
                    target=self.receive_socket_message,
                    args=(conn, address)
                )
                client_handler.start()
               
    def receive_socket_message(self, connection, address):
    #Check user request for further action
        with connection:
            print(f'Connected by: {address}')
            address_concat = address[0]+":"+str(address[1])
            while True:
                message = b""
                while True:
                    message += connection.recv(4096)
                    if len(message) % 4096:
                        break
                try:
                    parsed_message = pickle.loads(message)
                except Exception:
                    print(f"{message} cannot be parsed")
                if message:
                    if parsed_message["request"] == "get_balance":          # Call get balance function if 'get balance' request is received from other network node that running client.py
                        print("Getting balance for client...")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = {
                            "address": address,
                            "balance": balance
                        }
                    elif parsed_message["request"] == "transaction":        # Call transaction function if 'transaction' request is received from other network node that running client.py
                        print("Starting transaction for client...")
                        new_transaction = parsed_message["data"]
                        result, result_message = self.add_transaction(
                            new_transaction,
                            parsed_message["signature"]
                        )
                        response = {
                            "result": result,
                            "result_message": result_message
                        }
                        if result:
                            self.broadcast_transaction(new_transaction)

                    # Received sync request
                    elif parsed_message["request"] == "clone_blockchain":
                        print(f"[*] Receive chain cloning request by {address}...")
                        message = {
                            "request": "upload_blockchain",
                            "blockchain_data": self
                        }
                        connection.sendall(pickle.dumps(message))
                        continue

                    # Receive broadcast blocks
                    elif parsed_message["request"] == "broadcast_block":
                        print(f"[*] Receive block broadcast by {address}...")
                        self.receive_broadcast_block(parsed_message["data"])
                        continue

                    # Receive broadcast transaction
                    elif parsed_message["request"] == "broadcast_transaction":
                        print(f"[*] Receive transaction broadcast by {address}...")
                        self.pending_transactions.append(parsed_message["data"])
                        continue

                    # Receive node request 
                    elif parsed_message["request"] == "add_node":
                        print(f"[*] Receive add_node broadcast by {address}...")
                        self.node_address.add(parsed_message["data"])
                        continue
                    else:
                        response = {
                            "message": "Unknown command."
                        }
                    response_bytes = str(response).encode('utf8')
                    connection.sendall(response_bytes)
    
    def clone_blockchain(self, address):
        print(f"Start to clone blockchain by {address}")
        target_host = address.split(":")[0]
        target_port = int(address.split(":")[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_host, target_port))
        message = {"request": "clone_blockchain"}
        client.send(pickle.dumps(message))
        response = b""
        print(f"Retriving data from {address}")
        while True:
            response += client.recv(4096)
            if len(response) % 4096:
                break
        client.close()
        response = pickle.loads(response)["blockchain_data"]

        self.adjust = response.adjust
        self.difficulty = response.difficulty
        self.block_time = response.block_time
        self.block_limitation = response.block_limitation
        self.chain = response.chain
        self.pending_transactions = response.pending_transactions
        self.node_address.update(response.node_address)



    def broadcast_block(self, new_block):
    # Broadcasting block to nodes by socket
        self.broadcast_message_to_nodes("broadcast_block", new_block)

    def broadcast_transaction(self, new_transaction):
    # Broadcasting transaction to nodes by socket
        self.broadcast_message_to_nodes("broadcast_transaction", new_transaction)

    def broadcast_message_to_nodes(self, request, data=None):
    # Broadcasting message to nodes by socket
        address_concat = self.socket_host + ":" + str(self.socket_port)
        message = {
            "request": request,
            "data": data
        }
        for node_address in self.node_address:
            if node_address != address_concat:
                target_host = node_address.split(":")[0]
                target_port = int(node_address.split(":")[1])
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((target_host, target_port))
                client.sendall(pickle.dumps(message))
                client.close()

    # Verify the broadcast block information is correct or not
    def receive_broadcast_block(self, block_data):
        last_block = self.chain[-1]
        # Check the hash of received block
        if block_data.previous_hash != last_block.hash:
            print("[**] Received block error: Previous hash not matched!")
            return False
        elif block_data.difficulty != self.difficulty:
            print("[**] Received block error: Difficulty not matched!")
            return False
        elif block_data.hash != self.get_hash(block_data, block_data.nonce):
            print(block_data.hash)
            print("[**] Received block error: Block hash not matched!")
            return False
        else:
            if block_data.hash[0: self.difficulty] == '0' * self.difficulty:
                for transaction in block_data.transactions:
                        self.pending_transaction.remove(transaction)    #Prevent the transaction execute twice
                self.receive_verified_block = True
                self.chain.append(block_data)
                return True
            else:
                print(f"[**] Received block error: Hash not matched!")
                return False

# Part 8: Start blockchain service

    def start(self):
        #self.mysql_block_table()
        #self.mysql_transaction_table()
        address, private = self.generate_address()  #generate the address by generate_address() function
        print(f"Miner address: {address}")
        print(" ")
        print(f"Miner private: {private}")
        

        #Put keys into a txt file
        f = open("test.txt", "a")
        
        #Writing keys  
        f.write(f"Miner public key (address): {address}")
        f.write(" \n\n")
        f.write(f"Miner private key: {private}")
        f.write(" \n\n")
        f.write("Shhh..Keep it secret...")

        
        f.close()


        if len(sys.argv) < 3:
            self.create_genesis_block()
        while(True):
            self.mine_block(address)
            self.adjust_difficulty()


if __name__ == '__main__':
    try:
        block = Blockchain()
        block.start()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)




