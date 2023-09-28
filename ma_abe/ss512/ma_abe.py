# coding=utf-8

from charm.toolbox.pairinggroup import *
from newsecretutils import Utils
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import re,sys
import matplotlib.pyplot as plt
# from newjson import ElementEncoder, ElementDecoder
import newjson
import queue
import time
import threading
debug = False


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def merge_dicts2(dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

import hashlib
def hash(str):
    x = hashlib.sha256()
    x.update(str.encode())
    return x.hexdigest()

def hash2(str):
    x = hashlib.sha256()
    x.update((str+"2").encode())
    return x.hexdigest()


class MaabeRW15(ABEncMultiAuth):

    def __init__(self, group, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = group
        self.util = Utils(group, verbose)

    def setup(self):
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        egg = pair(g1, g2)
        H = lambda x: self.group.hash(x, G2)
        F = lambda x: self.group.hash(x, G2)
        gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F}
        if debug:
            print("Setup")
            print(gp)
        return gp

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = MaabeRW15(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        alpha, y = self.group.random(), self.group.random()
        sigy = self.group.random()
        egga = gp['egg'] ** alpha
        gy = gp['g1'] ** y
        siggy = gp['g1'] ** sigy
        pk = {'name': name, 'egga': egga, 'gy': gy, 'siggy':siggy}
        sk = {'name': name, 'alpha': alpha, 'y': y, 'sigy':sigy}
        if debug:
            print("Authsetup: %s" % name)
            print(pk)
            print(sk)

        return pk, sk

    def keygen(self, gp, sk, gid, attribute):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        t = self.group.random()
        K = gp['g2'] ** sk['alpha'] * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
        KP = gp['g1'] ** t
        if debug:
            print("Keygen")
            print("User: %s, Attribute: %s" % (gid, attribute))
            print({'K': K, 'KP': KP})
        return {'K': K, 'KP': KP}

    def multiple_attributes_keygen(self, gp, sk, gid, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        uk = {}
        for attribute in attributes:
            uk[attribute] = self.keygen(gp, sk, gid, attribute)
        return uk

    def encrypt(self, gp, pks, message, policy_str):
        """
        Encrypt a message under an access policy
        :param gp: The global parameters.
        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
        :param message: The message to encrypt.
        :param policy_str: The access policy to use.
        :return: The encrypted message.
        """
        s = self.group.random()  # secret to be shared

        w = self.group.init(ZR, 0)  # 0 to be shared


        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)

        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)

        M= message
        C0 = message * (gp['egg'] ** s)
        C1, C2, C3, C4 = {}, {}, {}, {}

        tx={}

        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            tx[i] = self.group.random()
            C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** tx[i]
            C2[i] = gp['g1'] ** (-tx[i])
            C3[i] = pks[auth]['gy'] ** tx[i] * gp['g1'] ** zero_shares[i]
            C4[i] = gp['F'](attr) ** tx[i]

        if debug:
            print("Encrypt")
            print(message)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4})
        # return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

    def decrypt(self, gp, sk, ct):
        """
        Decrypt the ciphertext using the secret keys of the user.
        :param gp: The global parameters.
        :param sk: The secret keys of the user.
        :param ct: The ciphertext to decrypt.
        :return: The decrypted message.
        :raise Exception: When the access policy can not be satisfied with the user's attributes.
        """
        policy = self.util.createPolicy(ct['policy'])
        # coefficients = self.util.newGetCoefficients(policy)
        pruned_list = self.util.prune(policy, sk['keys'].keys())
        coefficients = self.util.newGetCoefficients(policy, pruned_list)

        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B = self.group.init(GT, 1)
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            B *= (ct['C1'][y] * pair(ct['C2'][y], sk['keys'][x]['K']) * pair(ct['C3'][y], gp['H'](sk['GID'])) * pair(
                sk['keys'][x]['KP'], ct['C4'][y])) ** coefficients[y]
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk)
            print("Decrypted Message:")
            print(ct['C0'] / B)
        return ct['C0'] / B




if __name__ == '__main__':
    from charm.core.math.pairing import pairing, pc_element, ZR, G1, G2, GT, init, pair
    group = PairingGroup('SS512')
    maabe = MaabeRW15(group)
    MaxNode = int(input("输入你期待的权威中心个数："))
#权限机构集
    Autoritys = ['UT', 'OU', 'HN', 'OT']
#GID测试组
    GID = ['Alice', 'Bob', 'John', 'Emily', 'David', 'Sarah', 'Michael', 'Olivia', 'Daniel', 'Sophia']
#设定不同的访问控制策略
    access_policy1 = '(2 of (STUDENT@UT, PROFESSOR@UT, (PHD2@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU)'
    access_policy2 = '(2 of (STUDENT@UT, PROFESSOR@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or STUDENT@OU)'
    access_policy3 = '((2 of (STUDENT@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or STUDENT@HN)) or PROFESSOR@HN)'
    access_policy4 = '(1 of (STUDENT@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU) or STUDENT@UT)'
    access_policys = [access_policy1, access_policy2, access_policy3, access_policy4]
#设定不同权威机构的属性集
    user_attributes1 = ['STUDENT@UT', 'PHD@UT', 'PHD2@UT']  # user_attributes1 = ['k@node1']
    user_attributes2 = ['STUDENT@OU']  # user_attributes2 = ['k@node2']
    user_attributes3 = ['STUDENT@HN', 'PROFESSOR@HN']
    user_attributes4 = ['STUDENT@OT', 'PROFESSOR@OT']
    user_attributess = [user_attributes1, user_attributes2, user_attributes3,user_attributes4]

# 指定权威机构的数量下，各部分的时间开销
    time_au_getkeys = [None] * len(GID)
    time_user_getkeys = [None] * len(GID)
    time_enc = [None] * len(GID)
    time_dec = [None] * len(GID)
    global size_public_keys
    global size_CT
    global size_user_keys
    global size_EK
    global size_message
    global user_keys
    Public_keys = [None] * MaxNode
    Secret_keys = [None] * MaxNode
    User_keys = [None] * MaxNode

    for access_policy in access_policys:
        for gid_n in range(len(GID)):
            public_parameters = maabe.setup()  # 初始化global setup，返回全局公共参数public_parameters
            t = time.perf_counter()
            for Nindex in range(0, MaxNode):
                (Public_keys[Nindex], Secret_keys[Nindex]) = maabe.authsetup(public_parameters, Autoritys[Nindex])  # 节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
            time_au_getkeys[gid_n] = time.perf_counter() - t
            public_keys = {}
            # t3 = time.perf_counter() - t
            for Rindex in range(0, MaxNode):
                public_keys.update({Autoritys[Rindex]: Public_keys[Rindex]})
            # print(public_keys)
            # print(public_key1,'\n',secret_key1)
            size_public_keys = sys.getsizeof(Public_keys)
            # print(" size of public_keys in bytes: ", size_public_keys)

            # Create a random message
            message = group.random(GT)  # t_0时刻, 各节点（以节点i为例）生成随机数Mi
            size_message = sys.getsizeof(message)
            # message2 =group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
            # Encrypt the message
            # access_policy = '(2 of (STUDENT@UT, PROFESSOR@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU)'
            # t_0时刻, 构造 access_policy = '(t of (k@node1, k@node2, ... k@nodeN))'
            t = time.perf_counter()
            # print(public_keys)
            cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)  # t_0时刻, 各节点（以节点i为例）生成CTi
            size_CT = sys.getsizeof(cipher_text)
            time_enc[gid_n] = time.perf_counter() - t
            t = time.perf_counter()
            t = time.perf_counter()
            for i in range(MaxNode):
                User_keys[i] = maabe.multiple_attributes_keygen(public_parameters, Secret_keys[i], GID[gid_n],user_attributess[i])
            time_user_getkeys[gid_n] = time.perf_counter() - t
            # print(User_keys[i])  # node1生成的密钥key1,t2~t3广播
            size_EK = sys.getsizeof(User_keys[1])
            # user_keys2 = maabe.multiple_attributes_keygen(public_parameters, Secret_keys[1], gid,user_attributes2)  # node2生成的密钥key2,t2~t3广播
            user_keys = {'GID': GID[gid_n], 'keys': merge_dicts(*User_keys)}  # t3时刻 各节点合成当前轮次的私钥key_k
            size_user_keys = sys.getsizeof(user_keys)

            # Decrypt the message
            t = time.perf_counter()
            decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
            time_dec[gid_n] = time.perf_counter() - t
            size_decrypted_mes = sys.getsizeof(decrypted_message)
            if decrypted_message != message:
                # 执行某些操作
                break


            # print(f'\n公共参数:{t1:.8f}s\n', f'解密:{t_dec:.8f}s\n', f'加密:{t_enc:.8f}s')
            # print(decrypted_message == message)
        # print(time_dec)ave_dec_time =  sum(time_dec) / len(time_dec)
        print('在授权机构数量为{}时'.format(MaxNode), '在访问策略{}下'.format(access_policy), f'\nAU产生密钥:{(sum(time_au_getkeys) / len(time_au_getkeys)):.8f}s\n', f'加密时间:{(sum(time_enc) / len(time_enc)):.8f}s\n', f'用户获取密钥:{(sum(time_user_getkeys) / len(time_user_getkeys)):.8f}s\n', f'解密时间:{(sum(time_dec) / len(time_dec)):.8f}s\n')
        print('公钥组:', size_public_keys, '\n秘密：', size_message, "\n密文:", size_CT, '\n单组EK：', size_EK, '\n解密密钥组：', size_user_keys, '\n')
        print(User_keys[1])
        print(user_keys)
        print('此伦已经结束\n')


'''
    def measure_time(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"{func.__name__} 执行时间: {execution_time} 秒")
            return result
        return wrapper

    def get_object_size(obj):
        return sys.getsizeof(obj)
'''

'''if __name__ == '__main__':

    group = PairingGroup('SS512')
    maabe = MaabeRW15(group)
    MaxNode = input("输入你期待的权威中心个数：")
    Autoritys = ['UT','OU','HN','OT']
    public_parameters = maabe.setup() # 初始化global setup，返回全局公共参数public_parameters
    #print(f'耗时:{t1:.8f}s')
    #t1 = time.perf_counter()-t
    from charm.core.math.pairing import pairing, pc_element, ZR, G1, G2, GT, init, pair

    (public_key1, secret_key1) = maabe.authsetup(public_parameters, Autoritys[0]) #节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
    (public_key2, secret_key2) = maabe.authsetup(public_parameters, Autoritys[1]) #节点OU作为权限授予中心，执行setup，返回公私钥对(pk,sk)
    #t3 = time.perf_counter() - t
    public_keys = {'UT': public_key1, 'OU': public_key2} # pk通过P2P网络共享后，收到的pk集合
    #print(public_key1,'\n',secret_key1)
    size_public_keys = sys.getsizeof(public_keys)
    print(" size of public_keys in bytes: ", size_public_keys)
    t_public_keys = time.perf_counter() - t
    #print(t1,t2,t3)
    #user_keys1_size = maabe.get_object_size(public_key1)
    #print(f"secret_key1 尺寸: {public_key1} 字节")

        # Setup a user and give him some keys
    gid = "bob" # The global user identifier 用作标记轮次？
    user_attributes1 = ['STUDENT@UT', 'PHD@UT'] # user_attributes1 = ['k@node1']
    user_attributes2 = ['STUDENT@OU']           # user_attributes2 = ['k@node2']

            # Create a random message
    message = group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
    size_message = sys.getsizeof(message)
    # message2 =group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
    # Encrypt the message
    access_policy = '(2 of (STUDENT@UT, PROFESSOR@OU, (XXXX@UT or PHD@UT))) and (STUDENT@UT or MASTERS@OU)'
    # t_0时刻, 构造 access_policy = '(t of (k@node1, k@node2, ... k@nodeN))'
    t = time.perf_counter()
    cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy) # t_0时刻, 各节点（以节点i为例）生成CTi
    size_cipher_text = sys.getsizeof(cipher_text)
    t_enc = time.perf_counter()-t

    t = time.perf_counter()
    user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1) # node1生成的密钥key1,t2~t3广播
    size_EK = sys.getsizeof(user_keys1)
    user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2) # node2生成的密钥key2,t2~t3广播
    user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)} # t3时刻 各节点合成当前轮次的私钥key_k
    t_get_user_keys = time.perf_counter()-t




            # Decrypt the message
    t = time.perf_counter()
    decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text) #t3时刻，解密得到[Mi]
    t_dec = time.perf_counter()-t
    size_decrypted_mes = sys.getsizeof(decrypted_message)

    #print(f'\n公共参数:{t1:.8f}s\n',f'解密:{t_dec:.8f}s\n',f'加密:{t_enc:.8f}s')
    print('公钥组:',size_public_keys,"\n密文:",size_cipher_text,'\n单组EK：',size_EK,'\n秘密：',size_message,'\n解密后秘密：',size_decrypted_mes)
    print(decrypted_message == message)
'''
# import time,sys
'''
if __name__ == '__main__':

    maxNode = int(sys.argv[1])
    group = PairingGroup('SS512')
    maabe = MaabeRW15(group)

    public_parameters = maabe.setup()  # 初始化global setup，返回全局公共参数public_parameters
    print(1/(group.random()+group.random()))
    gid = "K"
    keyPaires = {}
    public_keys = {}  # pk通过P2P网络共享后，收到的pk集合
    user_attributes = {}
    for i in range(0,maxNode):
        keyPaires["AA%d"%i] = maabe.authsetup(public_parameters, "AA%d"%i)
        public_keys["AA%d"%i] = keyPaires["AA%d"%i][0]
        user_attributes["AA%d"%i] = ["%s@AA%d"%(gid,i)]

    report = {}

    for nodeNum in range(2, maxNode):
        t = nodeNum/2     #0~maxNode/2
        rIndex = "%d-%d" % (t,nodeNum)
        report[rIndex] = {}
        message = group.random(GT)
        nattributes = ["%s@AA%d"%(gid,j) for j in range(0,nodeNum)]
        access_policy = '(%d of (%s))'%(t,", ".join(nattributes))
        t1 = time.time()
        # print(t,nodeNum)
        cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)  # t_0时刻, 各节点（以节点i为例）生成CTi
        t2 = time.time()
        report[rIndex]["enc"] = float('%.3f' % (t2 - t1))
        user_keys = {'GID': gid, 'keys': merge_dicts2(
            [maabe.multiple_attributes_keygen(public_parameters, keyPaires["AA%d"%j][1], gid, user_attributes["AA%d"%j]) for j in range(0,nodeNum)])}
        t3 = time.time()
        report[rIndex]["keygen"] = float('%.3f' % (t3 - t2))
        decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
        t4 = time.time()
        report[rIndex]["dec"] = float('%.3f' % (t4 - t3))

        t = nodeNum *2/3
        rIndex = "%d-%d" % (t, nodeNum)
        report[rIndex] = {}
        message = group.random(GT)
        nattributes = ["%s@AA%d" % (gid, j) for j in range(0, nodeNum)]
        access_policy = '(%d of (%s))' % (t, ", ".join(nattributes))
        print(access_policy)
        t1 = time.time()
        cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)  # t_0时刻, 各节点（以节点i为例）生成CTi
        t2 = time.time()
        report[rIndex]["enc"] = float('%.3f' % (t2 - t1))
        user_keys = {'GID': gid, 'keys': merge_dicts2(
            [maabe.multiple_attributes_keygen(public_parameters, keyPaires["AA%d" % j][1], gid,
                                              user_attributes["AA%d" % j]) for j in range(0, nodeNum)])}
        t3 = time.time()
        report[rIndex]["keygen"] = float('%.3f' % (t3 - t2))
        decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
        t4 = time.time()
        report[rIndex]["dec"] = float('%.3f' % (t4 - t3))

        print(decrypted_message == message)
    open("maabe_report.json","w").write(newjson.dumps(report))
    print(report)
'''