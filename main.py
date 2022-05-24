from typing import Dict, List, Tuple, Set, Optional
import sys
import time
import pprint
from solcx import set_solc_version
# from web3.providers.eth_tester import EthereumTesterProvider
import web3
from web3 import Web3
from solcx import compile_source

set_solc_version('v0.8.0')

def compile_source_file(file_path):
   with open(file_path, 'r') as f:
      source = f.read()
   return compile_source(source)


def deploy_contract(w3, contract_interface):
    # print(contract_interface)
    # accounts = web3.geth.personal.list_accounts()
    # if len(wb3.eth.accounts) == 0:
    #     w3.geth.personal.new_account('123456')
    account=wb3.eth.accounts[0]
    # w3.geth.personal.unlock_account(account,"123456")
    contract = wb3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin'])
    tx_hash = contract.constructor().transact({'from': account, 'gas': 500_000_000})

    # tx_hash = contract.constructor({'from': account, 'gas': 500_000_000}).transact()
    address = wb3.eth.getTransactionReceipt(tx_hash)['contractAddress']
    return address


# w3 = Web3(EthereumTesterProvider())
wb3=web3.Web3(web3.HTTPProvider('http://127.0.0.1:7550', request_kwargs={'timeout': 60 * 10}))

contract_source_path = './contracts/Contract.sol'
compiled_sol = compile_source_file(contract_source_path)

# #BN256G2.sol
# contract_id, contract_interface = compiled_sol.popitem()
# address = deploy_contract(wb3, contract_interface)
# print("Deployed {0} to: {1}\n".format(contract_id, address))

#Contract.sol
contract_id, contract_interface = compiled_sol.popitem()
address = deploy_contract(wb3, contract_interface)
print("Deployed {0} to: {1}\n".format(contract_id, address))


ctt = wb3.eth.contract(
   address=address,
   abi=contract_interface['abi'])
# print(contract_interface['abi'])

from random import randint
from past.builtins import long
import py_ecc.bn128
from py_ecc import bn128
from py_ecc.bn128 import add, multiply, curve_order, G1,G2,pairing,neg
# from py_ecc.bn128.bn128_field_elements import inv, field_modulus, FQ

from sha3 import keccak_256

# def hashs(*x):
#     data = b''.join(map(tobe256, x))
#     return bytes_to_int(keccak_256(data).digest())


print(int(keccak_256("data".encode()).hexdigest(),16))
def hash2G1(data):
   return multiply(G1, int(keccak_256(data).hexdigest(),16))

def hash2int(data):
   return int(keccak_256(data).hexdigest(),16)

def G1ToArr(g):
   return [list(g)[0].n,list(g)[1].n]

def G2ToArr(g):
   a=G1ToArr(g[0].coeffs)
   b=G1ToArr(g[1].coeffs)
   return [[a[1],a[0]], [b[1],b[0]]]

gid="gid"
attr="ATTR1@AUTH"
alpha=randint(1, curve_order - 1)
beta=randint(1, curve_order - 1)
d=randint(1, curve_order - 1)
SK=randint(1, curve_order - 1)
PK=multiply(G1, SK)
def simulateKeyGen(attr, alpha, beta, d, PK):
   A=multiply(PK, alpha)
   B=multiply(hash2G1(gid.encode()), beta)
   C=multiply(hash2G1(attr.encode()), d)
   EK0=add(add(A,B),C)
   EK1=multiply(G2, d)
   EK2=multiply(G1, d)
   return (EK0,EK1,EK2)

EK0,EK1,EK2=simulateKeyGen(attr, alpha, beta, d, PK)

alphap=randint(1, curve_order - 1)
betap=randint(1, curve_order - 1)
dp=randint(1, curve_order - 1)
EK0p,EK1p,EK2p=simulateKeyGen(attr, alphap, betap, dp, PK)

c=hash2int((str(EK0)+str(EK1)+str(EK0p)+str(EK1p)).encode())

w1=alphap + c*alpha % curve_order
w2=betap + c*beta % curve_order
w3=dp + c*d % curve_order

tmp=[c,w1,w2,w3]
def checkKey0(PK, EK0, EK0p, tmp, gid, attr):
   A=multiply(PK, tmp[1])
   B=multiply(hash2G1(gid.encode()), tmp[2])
   C=multiply(hash2G1(attr.encode()), tmp[3])
   V0=add(add(A,B),C)

   assert(V0==add(EK0p, multiply(EK0, tmp[0])))
   

def checkKey1(EK1, EK1p, EK2, EK2p, tmp):
   
   V1=multiply(G1, tmp[3])
   assert(V1==add(EK2p, multiply(EK2, tmp[0])))   
   # print(G2,EK2,EK1,G1)
   assert(pairing(G2,EK2)==pairing(EK1,G1))

checkKey0(PK, EK0, EK0p, [c, w1, w2, w3], gid, attr)
checkKey1(EK1, EK1p, EK2, EK2p, tmp)   
# print(c,w1)
# print(G1ToArr(PK), G1ToArr(EK0), G2ToArr(EK1), G1ToArr(EK0p), G2ToArr(EK1p), c, w1, w2, w3)
print(G2ToArr(G2))

gas_estimate = ctt.functions.checkKey0(G1ToArr(PK), G1ToArr(EK0), G1ToArr(EK0p),  [c, w1, w2, w3], gid, attr).estimateGas()
print("Sending transaction to checkKey0 ",gas_estimate)
ret = ctt.functions.checkKey0(G1ToArr(PK), G1ToArr(EK0), G1ToArr(EK0p),  [c, w1, w2, w3], gid, attr).call({"from":wb3.eth.accounts[0], 'gas': 500_000_000})
print("checkKey0:",ret)

print(curve_order)
print(d)
# multiply(G2, curve_order-(d%curve_order))
# print(pairing(G2,EK2)/pairing(EK1,G1))
# EK1=neg(EK1)
# print(pairing(G2,EK2)*pairing(EK1,G1))
gas_estimate = ctt.functions.checkKey1(G2ToArr(EK1), G2ToArr(EK1p), G1ToArr(EK2), G1ToArr(EK2p),  [c, w1, w2, w3]).estimateGas()
print("Sending transaction to checkKey1 ",gas_estimate)
ret = ctt.functions.checkKey1(G2ToArr(EK1), G2ToArr(EK1p), G1ToArr(EK2), G1ToArr(EK2p),  [c, w1, w2, w3]).call({"from":wb3.eth.accounts[0], 'gas': 500_000_000})
print("checkKey1:",ret)


# gas_estimate = ctt.functions.verifyBGLS2().estimateGas()
# print("Sending transaction to verifyBGLS2 ",gas_estimate)
# ret = ctt.functions.verifyBGLS2().call({"from":wb3.eth.accounts[0], 'gas': 500_000_000})
# print("verifyBGLS2:",ret)



# import pysolcrypto.aosring as ring
# msg = ring.randsn()
# keys = ring.aosring_randkeys(4)
# sigs=ring.aosring_sign(*keys, message=msg)
# pks=[]
# for i in range(0,len(sigs[0])):
#    pks.append(sigs[0][i][0].n)
#    pks.append(sigs[0][i][1].n)
# assert ring.aosring_check(*sigs, message=msg)
# gas_estimate = ctt.functions.VerifyRingSig(pks,sigs[1],sigs[2],msg).estimateGas()
# print("Sending transaction to VerifyRingSig(pks,sigs[2],sigs[3],msg)",gas_estimate)
# ret = ctt.functions.VerifyRingSig(pks,sigs[1],sigs[2],msg).call({"from":wb3.eth.accounts[0], 'gas': 500_000_000})
# print("ring Signature verify:",ret)





# exit()