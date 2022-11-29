from tmp_index import Block,Blockchain
import sys
import time
import random
import threading
import socket
import pickle

class Attack:
    def __init__(self):
       self.private_chain = list()
       self.block = Blockchain()
       self.spend_once = False
       self.address = str()
       self.private = str()
       self.larger_than_fifty_one = False

    def secret_mining(self,miner):
        last_block = self.private_chain[-1] 
        new_block = Block(last_block.index + 1, last_block.hash, self.block.difficulty, miner, self.block.miner_rewards)
        
        #self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.block.difficulty
        new_block.hash = self.block.get_hash(new_block, new_block.nonce)
        new_block.nonce = random.getrandbits(32)    

        while new_block.hash[0: self.block.difficulty] != '0' * self.block.difficulty:
        #Check if the block hash fulfil the difficulty of the block
            new_block.nonce += 2   #Assuming the attacker has higher hashing power
            new_block.hash = self.block.get_hash(new_block, new_block.nonce)
            
        
        self.private_chain.append(new_block)
        fifty_one_percent_attack_thread = threading.Thread(target=self.fifty_one_percent_attack)
        fifty_one_percent_attack_thread.start()

    def fifty_one_percent_attack(self):
        while True:
            public_blockchain = self.block.get_blockchain(list(self.block.node_address)[0])
            if len(self.private_chain) > len(public_blockchain.chain):
                self.larger_than_fifty_one = True
                break

        if self.larger_than_fifty_one:
            self.random_address,self.random_private = self.block.generate_address()
            transaction = self.block.initialize_transaction(self.address,self.random_address,5,1,'First Spend')
            signature = self.block.sign_transaction(transaction,self.private)
            self.block.add_transaction(transaction,signature)
            print('Remaining balance before broadcasting secret chain to the public: ', self.block.get_balance(self.address))
            self.block.broadcast_block(self.private_chain[0])
            self.block.public_or_private = 'Private'
            print("Remaining balance after broadcasting secret chain to the public: ",self.block.get_balance(self.address))  #double spending attack
            new_transaction = self.block.initialize_transaction(self.address,self.random_address,5,1,'Double Spend')
            new_signature = self.block.sign_transaction(new_transaction,self.private)
            self.block.add_transaction(new_transaction,new_signature)
            print('After double spending, the remaining amount is', self.block.get_balance(self.address))
            
            
            
    def create_secret_genesis_block(self): #Generate a genesis block
        print("The first block is generated....")
        genesis_block = Block(1, 'Genesis', self.block.difficulty, 'Leo', self.block.miner_rewards)    
        genesis_block.hash = self.block.get_hash(genesis_block, 0)      
        self.private_chain.append(genesis_block)   
    
    def start(self):
        
        self.address,self.private = self.block.generate_address()
        if len(self.block.chain) == 0:
            self.block.create_genesis_block()
        if len(self.private_chain) == 0:
            self.create_secret_genesis_block()
    
        for i in range(50):
            self.block.mine_block(self.address)
            secret_mining_thread = threading.Thread(target=self.secret_mining,args=(self.address,))
            secret_mining_thread.start()


if __name__ == '__main__':
    attack = Attack()
    attack.start()
