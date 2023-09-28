
import setting
import sys
import util
import random
import re
import time
from abeutils import Utils
import hashlib
# import optimized_curve
# from charm.toolbox.pairinggroup import PairingGroup
# import newjson
bn128=setting.getBn128()
lib=bn128
FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
pairing, G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = \
lib.pairing, lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply

def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


class MaabeRW15():

    def __init__(self):
        # ABEncMultiAuth.__init__(self)
        # self.group = group

        self.abeutils = Utils()

        return
    def random(self):
        # return 2
        return int(random.random()*(2**256)) % curve_order

    def unpack_attribute(self, attribute):
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        # print(parts[0], parts[1])
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]


    def setup(self):
        g1 = multiply(G2,self.random())
        g2 = multiply(G1,self.random())
        # print("example g2",multiply(g1,self.random()))
        egg = (g1, g2)
        # egg=multiply(G12,self.random())
        # print(egg)
        H = lambda x: util.hashToG1(x)
        F = lambda x: util.hashToG1(x)
        # print(H("123"),F("123"))
        # print(type(g1[0]))
        # print(type(gp[""]))
        gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F,'h':FQ(int(2**256*random.random())% field_modulus),'j':FQ(int(2**256*random.random())% field_modulus),'k':FQ(int(2**256*random.random())% field_modulus),"l":FQ2([2342343, 199999999239832]) / FQ2([23417298349, 23411])}
        if debug:
            print("Global Setup=========================")
            print(gp["egg"])
            print("\n")
        return gp
    
    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        alpha, y = self.random(), self.random()
        # egga = multiply(gp['egg'], alpha)
        egga = (gp['g1'], multiply(gp['g2'], alpha))#gp['egg'] ** alpha

        # gy={}
        gy=multiply(gp['g1'],y)      
        g2y=multiply(gp['g2'],y)      
        # print("11111111")  
        # print(type(gy["g1"][0]),type(gp["g1"][0]))
        # print(is_on_curve(gy, b2))
        # print(is_on_curve(egga, b12))
        pk = {'name': name, 'egga': egga, 'gy': gy, 'g2y':g2y}
        sk = {'name': name, 'alpha': alpha, 'y': y}
        if debug:
            print("Authsetup: =======================%s" % name)
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

        t = self.random()
        # print(multiply(gp['g2'],sk['alpha']))

        r=multiply(gp['H'](gid), sk['y'])
        # print(type(r[0]))
        # print(multiply(gp['F'](attribute), t))
        # K = gp['g2'] ** sk['alpha'] * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
        # KP = gp['g1'] ** t
        k1=multiply(gp['g2'],sk['alpha'])
        k2=multiply(gp['H'](gid), sk['y'])
        k3=multiply(gp['F'](attribute), t)
        # print(type(k1[0]),type(k2[0]))
        K=add(k1,k2)
        K=add(K,k3)
        # K = add(\
        #     add(multiply(gp['g2'],sk['alpha']),\
        #         	multiply(gp['H'](gid), sk['y'])),\
        #     multiply(gp['F'](attribute), t))
        # print("........",is_on_curve(K, b))
        # KP = gp['g1'] ** t
        KP = multiply(gp['g1'], t)
        # print("11111111",is_on_curve(KP, b2))

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
        z = self.random()  # secret to be shared
        zp = self.random()  # secret to be shared
        w = 0  # 0 to be shared
        wp= 0

        policy = self.abeutils.createPolicy(policy_str)
        attr_list = self.abeutils.getAttributeList(policy)
        attribute_list = self.abeutils.getAttributeList(policy)
        # print("policy",policy,"attribute_list", attribute_list)
        secret_shares = self.abeutils.calculateSharesDict(z, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.abeutils.calculateSharesDict(w, policy)
        # print(secret_shares)
        
        M=message

        L =(gp['g1'], multiply(gp['g2'], z))
        C0 = (gp['g1'], add(L[1], M[1]))
        C1, C2, C3, C4 = {}, {}, {}, {}
        
        tx={}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            
            tx[i] = self.random()
            C1[i] = (gp['g1'], add(multiply(gp['egg'][1], secret_shares[i]), multiply(pks[auth]['egga'][1], tx[i])))
            C2[i] = multiply(gp['g1'], (curve_order-tx[i]))            
            C3[i] = add(multiply(pks[auth]['gy'], tx[i]), multiply(gp['g1'], zero_shares[i]))
            C4[i] = multiply(gp['F'](attr), tx[i])
            
        
        # print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4})        
        return {'policy': policy_str, 'attr_list':attr_list, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

    def decrypt(self, gp, sk, ct):
        # print(ct)
        policy = self.abeutils.createPolicy(ct['policy'])
        # coefficients = self.abeutils.newGetCoefficients(policy)
        pruned_list = self.abeutils.prune(policy, sk['keys'].keys())
        coefficients = self.abeutils.newGetCoefficients(policy, pruned_list)
        # print(pruned_list)
        # print(coefficients)
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B  = FQ12([1] + [0] * 11)
        Bp = FQ12([1] + [0] * 11)
        
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            exp=int(coefficients[y])
            if exp < 0:
                exp+=curve_order
            # print("C4,",ct['C4'], y in ct['C4'])
            a=pairing(ct['C2'][y], sk['keys'][x]['K'])
            b=pairing(ct['C3'][y], gp['H'](sk['GID']))
            c=pairing(sk['keys'][x]['KP'], ct['C4'][y])
            B = B*((pairing(ct['C1'][y][0],ct['C1'][y][1])*a*b*c) ** exp)

            
        # print("B===",B)
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk)
            print("Decrypted Message:")
            print(pairing(ct['C0'][0],ct['C0'][1]) / B)
        # print(ct["C0"]/B == ct["C0p"]/Bp)
        # print(type(pairing(ct['C0'][0],ct['C0'][1]) / B))
        return pairing(ct['C0'][0],ct['C0'][1]) / B


debug = False
if __name__ == '__main__':

    maabe = MaabeRW15()
    MaxNode = int(input("输入期待参与的权威中心个数："))
# 设置权限机构集
    Autoritys = ['UT', 'OU', 'TO', 'HN', 'SY', 'DL', 'BJ', 'CD', 'WH', 'NJ']
# GID测试组
    GID = ['Alice', 'Bob', 'John', 'Emily', 'David', 'Sarah', 'Michael', 'Olivia', 'Daniel', 'Sophia']
# 设定不同的访问控制策略
    access_policy1 = '(1 of (STUDENT@UT, STUDENT@OU))'
    access_policy2 = '(1 of (STUDENT@UT, STUDENT@OU) or STUDENT@TO)'
    access_policy3 = '(2 of (STUDENT@UT, STUDENT@UT , STUFENT@TO))'
    access_policy4 = '((1 of (STUDENT@UT, PHD@UT) or STUDENT@OU) or STUDENT@HN)'
    access_policys = [access_policy1, access_policy2, access_policy3, access_policy4]
# 设定不同权威机构的属性集
    user_attributes1 = ['STUDENT@UT', 'PHD@UT', 'PHD2@UT', 'PHD3@UT', 'PHD4@UT', 'PHD5@UT', 'PHD6@UT', 'PHD7@UT', 'PHD8@UT', 'PHD9@UT']  # user_attributes1 = ['k@node1']
    user_attributes2 = ['STUDENT@OU', 'PHD1@OU', 'PHD2@OU', 'PHD3@OU', 'PHD4@OU', 'PHD5@OU', 'PHD6@OU', 'PHD7@OU', 'PHD8@OU', 'PHD9@OU']
    user_attributes3 = ['STUDENT@TO', 'PROFESSOR@TO']
    user_attributes4 = ['STUDENT@HN', 'PROFESSOR@HN']
    user_attributes5 = ['STUDENT@SY', 'PROFESSOR@SY']
    user_attributes6 = ['STUDENT@DL', 'PROFESSOR@DL']
    user_attributes7 = ['STUDENT@BJ', 'PROFESSOR@BJ']
    user_attributes8 = ['STUDENT@CD', 'PROFESSOR@CD']
    user_attributes9 = ['STUDENT@WH', 'PROFESSOR@WH']
    user_attributes10 = ['STUDENT@NJ', 'PROFESSOR@NJ']
    user_attributess = [user_attributes1, user_attributes2, user_attributes3, user_attributes4,user_attributes5, user_attributes6, user_attributes7, user_attributes8, user_attributes9, user_attributes10]

    time_au_getkeys = [None] * len(GID)
    time_user_getkeys = [None] * len(GID)
    time_enc = [None] * len(GID)
    time_dec = [None] * len(GID)

    global size_public_keys
    global size_CT
    global size_user_keys
    global size_EK
    global size_message

    if MaxNode < 3:
        access_policy = access_policys[0]
    elif MaxNode == 3:
        access_policy = access_policys[random. randint(1, 2)]
    else:
        access_policy = access_policys[3]

    for gid_n in range(len(GID)):
        gp = maabe.setup()
        Public_keys = [None] * MaxNode
        Secret_keys = [None] * MaxNode

        t = time.perf_counter()
        for Nindex in range(0, MaxNode):
            (Public_keys[Nindex], Secret_keys[Nindex]) = maabe.authsetup(gp, Autoritys[Nindex])  # 节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
        time_au_getkeys[gid_n] = time.perf_counter() - t
        public_keys = {}
        # t3 = time.perf_counter() - t
        for Rindex in range(0, MaxNode):
            public_keys.update({Autoritys[Rindex]: Public_keys[Rindex]})
        size_public_keys = sys.getsizeof(public_keys)

        message = (gp['g1'], multiply(gp['g2'], maabe.random()))  # gp["egg"]**maabe.random()
        size_message = sys.getsizeof(message)
        # print("message", pairing(message[0], message[1]))
        t = time.perf_counter()
        cipher_text = maabe.encrypt(gp, public_keys, message, access_policy)
        time_enc[gid_n] = time.perf_counter() - t

        size_CT = sys.getsizeof(cipher_text)

        User_keys = [None] * MaxNode
        t = time.perf_counter()
        for i in range(MaxNode):
            User_keys[i] = maabe.multiple_attributes_keygen(gp, Secret_keys[i], GID[gid_n],user_attributess[i])
        time_user_getkeys[gid_n] = time.perf_counter() - t
        size_EK = sys.getsizeof(User_keys[0])
        user_keys = {'GID': GID[gid_n], 'keys': merge_dicts(*User_keys)}  # t3时刻 各节点合成当前轮次的私钥key_k
        size_user_keys = sys.getsizeof(user_keys)
        t = time.perf_counter()
        decrypted_message = maabe.decrypt(gp, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
        time_dec[gid_n] = time.perf_counter() - t

    print('在授权机构数量为{}时'.format(MaxNode), '在访问策略{}下'.format(access_policy),
              f'\nAU产生密钥:{(sum(time_au_getkeys) / len(time_au_getkeys)):.8f}s\n',
              f'加密时间:{(sum(time_enc) / len(time_enc)):.8f}s\n',
              f'用户获取密钥:{(sum(time_user_getkeys) / len(time_user_getkeys)):.8f}s\n',
              f'解密时间:{(sum(time_dec) / len(time_dec)):.8f}s\n')
    print('公钥组:', size_public_keys, '\n秘密：', size_message, "\n密文:", size_CT, '\n单组EK：', size_EK, '\n解密密钥组：', size_user_keys, '\n')
            #print(GID[gid_n])
            # print(public_keys)
            # print(public_key1,'\n',secret_key1)


            # 自定义一个权限机构
            #(pk1, sk1) = maabe.authsetup(gp, 'UT')
            #user_keys1 = maabe.multiple_attributes_keygen(gp, sk1, "bob", user_attributes1)
            # print(user_keys1)

            #(pk2, sk2) = maabe.authsetup(gp, 'OU')
            #user_keys2 = maabe.multiple_attributes_keygen(gp, sk2, "bob", user_attributes2)
            # print(user_keys2)

            #(pk3, sk3) = maabe.authsetup(gp, 'TO')
            #user_keys3 = maabe.multiple_attributes_keygen(gp, sk3, "bob", user_attributes3)
            # print(user_keys2)

            #public_keys = {'UT': pk1, 'OU': pk2, 'TO': pk3}

            #access_policy = '(2 of (STUDENT@UT, STUDENT@OU, STUDENT@TO))'

            # print("ciphertext",cipher_text)
'''
            user_keys = {'GID': "bob", 'keys': merge_dicts(user_keys1, user_keys2, user_keys3)}
            decrypted_message = maabe.decrypt(gp, user_keys, cipher_text)
            print(user_keys)
            # print("decrypted_message",decrypted_message)

            print(decrypted_message == pairing(message[0], message[1]))



import time

if __name__ == '__main__':
    #from charm.core.math.pairing import pairing, pc_element, ZR, G1, G2, GT, init, pair
    #group = PairingGroup('SS512')
    maabe = MaabeRW15()
    MaxNode = int(input("输入你期待的权威中心个数："))
#权限机构集
    Autoritys = ['UT', 'OU', 'HN', 'OT']
#GID测试组
    GID = ['Alice', 'Bob', 'John', 'Emily', 'David', 'Sarah', 'Michael', 'Olivia', 'Daniel', 'Sophia']
#设定不同的访问控制策略
    access_policy1 = '(2 of (STUDENT@UT, PROFESSOR@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU)'
    access_policy2 = '(2 of (STUDENT@UT, PROFESSOR@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or STUDENT@OU)'
    access_policy3 = '(1 of (STUDENT@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU) or STUDENT@HN'
    access_policys = [access_policy1,access_policy2,access_policy3]
#设定不同权威机构的属性集
    user_attributes1 = ['STUDENT@UT', 'PHD@UT', 'PHD2@UT']  # user_attributes1 = ['k@node1']
    user_attributes2 = ['STUDENT@OU']  # user_attributes2 = ['k@node2']
    user_attributes3 = ['STUDENT@HN', 'PROFESSOR@HN']
    user_attributes4 = ['STUDENT@OT', 'PROFESSOR@OT']
    user_attributess = [user_attributes1, user_attributes2, user_attributes3,user_attributes4]
    time_enc = [None] * len(GID)
    time_dec = [None] * len(GID)
    for gid_n in range(len(GID)):
        Public_keys = [None] * MaxNode
        Secret_keys = [None] * MaxNode
        public_parameters = maabe.setup()  # 初始化global setup，返回全局公共参数public_parameters
        for Nindex in range(0, MaxNode):
            (Public_keys[Nindex], Secret_keys[Nindex]) = maabe.authsetup(public_parameters, Autoritys[
                Nindex])  # 节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
        public_keys = {}
        # t3 = time.perf_counter() - t
        for Rindex in range(0, MaxNode):
            public_keys.update({Autoritys[Rindex]: Public_keys[Rindex]})
        # print(public_keys)
        # print(public_key1,'\n',secret_key1)
        size_public_keys = sys.getsizeof(public_keys)
        #print(" size of public_keys in bytes: ", size_public_keys)

        # Create a random message
        message = (gp['g1'], multiply(gp['g2'], maabe.random()))#gp["egg"]**maabe.random()
        size_message = sys.getsizeof(message)
        # message2 =group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
        # Encrypt the message
        # access_policy = '(2 of (STUDENT@UT, PROFESSOR@UT, (XXXX@UT or PHD@UT))) and (STUDENT@OU or MASTERS@OU or PROFESSOR@OU)'
        # t_0时刻, 构造 access_policy = '(t of (k@node1, k@node2, ... k@nodeN))'
        t = time.perf_counter()
        # print(public_keys)
        cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy2)  # t_0时刻, 各节点（以节点i为例）生成CTi
        size_cipher_text = sys.getsizeof(cipher_text)
        time_enc[gid_n] = time.perf_counter() - t
        t = time.perf_counter()
        User_keys = [None] * MaxNode
        for i in range(MaxNode):
            User_keys[i] = maabe.multiple_attributes_keygen(public_parameters, Secret_keys[i], GID[gid_n],user_attributess[i])
        #print(User_keys[i])  # node1生成的密钥key1,t2~t3广播
        # size_EK = sys.getsizeof(user_keys1)
        # user_keys2 = maabe.multiple_attributes_keygen(public_parameters, Secret_keys[1], gid,user_attributes2)  # node2生成的密钥key2,t2~t3广播
        user_keys = {'GID': GID[gid_n], 'keys': merge_dicts(User_keys[0], User_keys[1])}  # t3时刻 各节点合成当前轮次的私钥key_k
        t_get_user_keys = time.perf_counter() - t

        # Decrypt the message
        t = time.perf_counter()
        decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
        time_dec[gid_n] = time.perf_counter() - t
        size_decrypted_mes = sys.getsizeof(decrypted_message)

        # print(f'\n公共参数:{t1:.8f}s\n', f'解密:{t_dec:.8f}s\n', f'加密:{t_enc:.8f}s')
        # print('公钥组:', size_public_keys, "\n密文:", size_cipher_text, '\n单组EK：', size_EK, '\n秘密：', size_message, '\n解密后秘密：',size_decrypted_mes)
        #print(decrypted_message == message)
    #print(time_dec)ave_dec_time =  sum(time_dec) / len(time_dec)
    print(f'\n加密时间:{(sum(time_enc) / len(time_enc)):.8f}s\n', f'\n解密时间:{(sum(time_dec) / len(time_dec)):.8f}s\n')



'''


