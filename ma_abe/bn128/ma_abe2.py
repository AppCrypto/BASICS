
import setting

import util
import random
import re
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
    gp = maabe.setup() 
    (pk1, sk1) = maabe.authsetup(gp, "UT") 
    # print(pk, sk)
    user_attributes1 = ['STUDENT@UT', 'PHD1@UT', 'PHD2@UT', 'PHD3@UT', 'PHD4@UT', 'PHD5@UT', 'PHD6@UT', 'PHD7@UT', 'PHD8@UT', 'PHD9@UT'] 
    user_keys1 = maabe.multiple_attributes_keygen(gp, sk1, "bob", user_attributes1) 
    # print(user_keys1)

    (pk2, sk2) = maabe.authsetup(gp, "OU") 
    user_attributes2 = ['STUDENT@OU', 'PHD1@OU', 'PHD2@OU', 'PHD3@OU', 'PHD4@OU', 'PHD5@OU', 'PHD6@OU', 'PHD7@OU', 'PHD8@OU', 'PHD9@OU'] 
    user_keys2 = maabe.multiple_attributes_keygen(gp, sk2, "bob", user_attributes2) 
    # print(user_keys2)


    (pk3, sk3) = maabe.authsetup(gp, "TO") 
    user_attributes3 = ['STUDENT@TO'] 
    user_keys3 = maabe.multiple_attributes_keygen(gp, sk3, "bob", user_attributes3) 
    # print(user_keys2)


    public_keys = {'UT': pk1, 'OU': pk2, 'TO': pk3} 
    # private_keys = {'UT': sk1, 'OU': sk2} 
    # access_policy = '(2 of (STUDENT@UT, PROFESSOR@OU, (XXXX@UT or PHD@UT))) and (STUDENT@UT or MASTERS@OU)'
    access_policy = '(2 of (STUDENT@UT, STUDENT@OU, STUDENT@TO))'
    # access_policy = 'STUDENT@UT and STUDENT@OU'
    # access_policy = 'STUDENT@UT'
    # access_policy = 'STUDENT@OU'
    message = (gp['g1'], multiply(gp['g2'], maabe.random()))#gp["egg"]**maabe.random()
    print("message",pairing(message[0],message[1]))
    cipher_text = maabe.encrypt(gp, public_keys, message, access_policy) 
    # print("ciphertext",cipher_text)
    user_keys = {'GID': "bob", 'keys': merge_dicts(user_keys1, user_keys2)}
    decrypted_message = maabe.decrypt(gp, user_keys, cipher_text) 
    # print(user_keys)
    # print("decrypted_message",decrypted_message)
    
    print(decrypted_message == pairing(message[0],message[1]))












