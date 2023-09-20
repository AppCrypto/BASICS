from web3 import Web3
# from eth_abi import encode_single, encode_abi
from eth_abi.packed import encode_abi_packed
import setting
bn128 = setting.getBn128()
from py_ecc import optimized_bn128
# Web3.soliditySha3(['bytes32'],[encode_abi(['uint256', 'uint256'], [1,2])])
# Web3.soliditySha3(['bytes32'],[encode_single('(uint256,uint256)', [1, 2])])




def random(self):
    return int(random.random()*(2**256))

def mulMod(a, b, mod):  
    res = 0; 
    a = a % mod; 
    while (b > 0): 
        if (b % 2 == 1): 
            res = (res + a) % mod;
        a = (a * 2) % mod;         
        b //= 2; 
    return res % mod; 

# def tuplePairing(g2tuple, g1tuple):
# 	# tp = str(type(t[0]))
# 	# print(tp,x)
# 	ret=[]
# 	for i in range(0, len(g2tuple)):
# 		ret.append(bn128.pairing(g2tuple[i],g1tuple[i]))
# 	return tuple(ret)
def tupleMultiply(t, x):
	# tp = str(type(t[0]))
	# print(tp,x)
	return tuple(i*x for i in t)


def gPowFQ12(h, fq12,mod):
    return [util.modPow(h,int(fq12.coeffs[i]),field_modulus) for i in range(0, fq12.degree)]

def minusFQ12(fq121, fq122):
    return [int(fq121.coeffs[i] - fq122.coeffs[i]) for i in range(0, fq121.degree)]


def FQ12ToInt(FQ12v):
	res=""
	for i in range(0, FQ12v.degree):
		v=str(FQ12v.coeffs[i])
		res=res+v+str(len(v))+"00000" 
	return int(res)

def Int2FQ12(v):
	print(v)
	arr=[]
	nextStr=str(v)
	# start=0
	while 1:
		end=nextStr.find("00000")
		if end <=0:
			break
		assert(int(nextStr[end-2:end]) == end-2)
		arr.append(int(nextStr[:end-2]))
		nextStr=nextStr[end+len("00000"):]
	# print(arr)
	return bn128.FQ12(arr)

def tuplePow(t, x):
	# tp = str(type(t[0]))
	# print(tp,x)
	return tuple(i**x for i in t)
	# if "<class 'py_ecc.fields.bn128_FQ2'>" == tp:
	# 	return tuple(bn128.FQ2(i)**x for i in t)
	# if "<class 'py_ecc.fields.bn128_FQ'>" == tp:
	# 	return tuple(bn128.FQ(i)**x for i in t)

def modPow(b, e, m):
	"""computes s = (b ^ e) mod m
	args are base, exponent, modulus
	(see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
	x = 1
	while e > 0:
		b, e, x = (
			b * b % m,
			e // 2,
			b * x % m if e % 2 else x
		)
 
	return x


# encode_abi_packed(['int8[]', 'uint32'], ([1, 2, 3, 4], 12345))
prime=21888242871839275222246405745257275088696311157297823662689037894645226208583
pminus = 21888242871839275222246405745257275088696311157297823662689037894645226208582;
pplus = 21888242871839275222246405745257275088696311157297823662689037894645226208584;
# def api_packed(types,args):
# 	return encode_abi_packed(types,args)


def keccak256(types,args):
	return int(Web3.soliditySha3(['bytes32'],[encode_abi_packed(types,args)]).hex(),16)

# x=0
def hashToG1(str):
	# [i for i in bytearray(b"asbx@adsaf_234ljsdfjoas-l12+")]
	b = bytearray()
	b.extend(map(ord, str))
	arr= [i for i in b]
	x=0
	while (1) :
		x=x%256
		types,args = ['uint256[]','uint8'], (arr, x)
		hx=keccak256(types,args)%prime
		px = modPow(hx,3,prime) + 3
		# hex(px)
		if (modPow(px, pminus//2, prime) == 1) :
			py = modPow(px,pplus//4, prime)			
			types,args = ['uint256[]','uint8'], (arr, 255)
			# keccak256(arr,args)
			if (keccak256(types,args)%2 == 0):

				
				if bn128==optimized_bn128:
					return (bn128.FQ(hx),bn128.FQ(py),bn128.FQ(1))
				else:
					return (bn128.FQ(hx),bn128.FQ(py))
			else:
				if bn128==optimized_bn128:
					return (bn128.FQ(hx),bn128.FQ(prime-py),bn128.FQ(1))
				else:
					return (bn128.FQ(hx),bn128.FQ(prime-py))
		else:
			x+=1
# test1
# p1=hashToG1("1223")
# print(p1)

# lib=bn128
# FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
# G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply
# print(is_on_curve((FQ(p1[0]),FQ(p1[1]),FQ(1)),b))

# # test2
# g11=(FQ(9121282642809701931333593728297233225556711250127745709186816755779879923737),FQ(8783642022119951289582979607207867126556038468480503109520224385365741455513),FQ(1))
# is_on_curve(g11,b)
# g12=(FQ(19430493116922072356830709910231609246608721301711710668649991649389881488730),FQ(4110959498627045907440291871300490703579626657177845575364169615082683328588),FQ(1))
# is_on_curve(g12,b)
# expect_g=(FQ(17981918273786386398769813244173616322667195802888989780909050086192926768907),FQ(18658404630663819378315425423756597890713010608083111245835977740656931644247),FQ(1))
# print(eq(add(g11,g12),expect_g))




