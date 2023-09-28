import math
import numpy as np
import sys


def encode(s):
    b_list = []
    for c in s:
        c = bin(ord(c)).replace('0b', '')
        if len(c) <= 8:
            b_list.append(c.zfill(8))
        else:
            b_list_rev = []
            c_list = list(c)
            while True:
                b_list_rev.append(''.join(c_list[-8:]))
                del c_list[-8:]
                if not c_list:
                    break
                if len(c_list) <= 8:
                    c_list = list(''.join(c_list).zfill(8))
            b_list_rev.reverse()
            if b_list:
                b_list += b_list_rev
            else:
                b_list = b_list_rev
    print("Message send: --{}--".format(s))
    print("Bits send: --{}--".format(' '.join(b_list)))
    return b_list


def decode(s):
     return ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])


M, N = (320, 320)
q = 297
A = []
s = []

def encrypt(str_p):
    global A
    bin_list = np.array(list(''.join(encode(str_p))), dtype=np.int32).reshape(M, 1)

    A = np.random.randint(0, q, [M, N])
    s = np.random.randint(0, q, [N, 1])
    e = np.random.randint(0, math.ceil(q / 2) - 1, [M, 1])

    m = bin_list * math.ceil(q / 2)
    b = (np.matmul(A, s) + e + m) % q
    print(b.shape)
    return s, b


def decrypt(s, b, str_len):
    global A
    b_ = (b - np.matmul(A, s)) % q
    print((b - np.matmul(A, s) % q).reshape(1, -1))
    print(b_.reshape(1, -1))
    b_[b_ < (q / 2)] = 0
    b_[b_ >= (q / 2)] = 1
    bin_res = ''
    i = 0
    for x in b_:
        bin_res += str(x[0])
        i += 1
        if i % 8 == 0 and i < len(b_):
            bin_res += ' '
    print("Bits received: --{}--".format(bin_res))
    print("Message received: --{}--".format(decode(bin_res)[:str_len]))

def main():
    str1 = input("send a  message to encrypt:")
    print(sys.getsizeof(str1))
    len_str1 = len(str1)
    if len_str1 < 40:
        str1 = str1.ljust(40, ' ')
    print(sys.getsizeof(str1))
    decrypt(*encrypt(str1), len_str1)


if __name__ == "__main__":
    main()
