'''
Contains all the auxillary functions to do linear secret sharing (LSS) over an access structure. Mainly, we represent the
access structure as a binary tree. This could also support matrices for representing access structures.
'''
# from py_ecc import optimized_bn128
# bn128=optimized_bn128
import setting
bn128=setting.getBn128()
from policytree import *
import sys
import random
from decimal import *

getcontext().prec = 256

class Utils:
    def random(self):
        #todo
        # return 2
        return int(random.random()*(2**256)) % bn128.curve_order

    

    def __init__(self):
        pass
    

    def P(self, coeff, x):
        share = coeff[0]
        # newx = self.group.init(ZR, x)
        newx = x
        # print(newx,x)
        # evaluate polynomial
        for j in range(1, len(coeff)):
            # print("j::  "+str(j))
            # i = self.group.init(ZR, j)
            i = j
            share += coeff[j] * (newx**i)
        return share

    def genShares(self, secret, k, n):
        # SecretSharer.split_secret(str(secret), 2, 3)
        if (k <= n):
            rand = self.random
            a = []  # will hold polynomial coefficients
            for i in range(0, k):
                if (i == 0):
                    a.append(secret)  # a[0]
                else:
                    a.append(rand())

            shares = [self.P(a, i) for i in range(0, n + 1)]
        return shares

    # shares is a dictionary
    def recoverCoefficients(self, list):
        """recovers the coefficients over a binary tree."""
        coeff = {}
        # list2 = [self.group.init(ZR, i) for i in list]
        list2 = [i for i in list]
        for i in list2:
            result = 1
            result2 = 1
            for j in list2:
                if not (i == j):
                    # lagrange basis poly
                    result = result * Decimal(0 - j) 
                    result2 = result2 * Decimal(i - j)
            
            coeff[int(i)] = result/result2
            # print("coeff '%d' => '%s','%s','%s'" % (i, result,result2,coeff[int(i)]))
        return coeff



    def inv(self, a, prime):
        """
        Compute multiplicative inverse modulo a prime.
        """
        return pow(a, prime-2, prime)


    def interpolate(self, X, Y, prime):
        points={}
        for i in range(0, len(X)):
            points[X[i]]=Y[i]
        # Compute the Langrange coefficients at 0.
        coefficients = {}
        for i in points:
            coefficients[i] = 1
            for j in points:
                if j != i:
                    coefficients[i] = (coefficients[i] * (0-j) * self.inv(i-j, prime)) % prime

        value = 0
        for i in points:
            value = (value + points[i] * coefficients[i]) % prime
        # print(value)
        return value



    def recoverSecret(self, shares):
        """take shares and attempt to recover secret by taking sum of coeff * share for all shares.
        if user indeed has at least k of n shares, then secret will be recovered."""
        list = shares.keys()
        # if self.verbose: print(list)
        coeff = self.recoverCoefficients(list)
        secret = 0
        for i in list:
            secret += (coeff[i] * shares[i])

        return secret

    def getCoefficients(self, tree):
        coeffs = {}
        self._getCoefficientsDict(tree, coeffs)
        return coeffs

    def newGetCoefficients(self, tree, useList):
        coeffs = {}
        self._newGetCoefficientsDict(tree, coeffs, 1, useList)
        return coeffs

    def _newGetCoefficientsDict(self, tree, coeff_list, coeff=1, useList=[]):
        if tree:
            node = tree.getNodeType()
            if (node == OpType.AND):
                this_coeff = self.recoverCoefficients([1, 2])
                # left child => coeff[1], right child => coeff[2]
                self._newGetCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1], useList)
                self._newGetCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[2], useList)
            elif (node == OpType.OR):
                this_coeff = self.recoverCoefficients([1])
                self._newGetCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1], useList)
                self._newGetCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[1], useList)
            elif node == OpType.THRESHOLD:
                list2 = []
                for i in range(len(tree.children)):
                    if tree.children[i].getNodeType()==OpType.ATTR:
                        if str(tree.children[i]) in useList:
                            list2.append(i+1)
                    else:
                        str2 = str(tree.children[i])
                        for j in useList:
                            if str2.find(str(j)) != -1:
                                list2.append(i+1)
                                break
                list2 = list(set(list2))
                this_coeff = self.recoverCoefficients(list2)
                j = 1
                for i in list2:
                    self._newGetCoefficientsDict(tree.children[i-1], coeff_list, coeff * this_coeff[i], useList)
            elif (node == OpType.ATTR):
                attr = tree.getAttributeAndIndex()
                coeff_list[attr] = coeff
            else:
                return None

    def _getCoefficientsDict(self, tree, coeff_list, coeff=1):
        """recover coefficient over a binary tree where possible node types are OR = (1 of 2)
        and AND = (2 of 2) secret sharing. The leaf nodes are attributes and the coefficients are
        recorded in a coeff-list dictionary."""
        if tree:
            node = tree.getNodeType()
            if (node == OpType.AND):
                this_coeff = self.recoverCoefficients([1, 2])
                # left child => coeff[1], right child => coeff[2]
                self._getCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1])
                self._getCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[2])
            elif (node == OpType.OR):
                this_coeff = self.recoverCoefficients([1])
                self._getCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1])
                self._getCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[1])
            elif node == OpType.THRESHOLD:
                list2 = []
                # for i in range(tree.threshold):
                for i in range(len(tree.children)):
                    list2.append(i+1)
                this_coeff = self.recoverCoefficients(list2)
                j = 1
                for i in tree.getChildren():
                    self._getCoefficientsDict(i, coeff_list, coeff * this_coeff[j])
                    j += 1
                    # if j > tree.threshold:
                    #     j = tree.threshold
            elif (node == OpType.ATTR):
                attr = tree.getAttributeAndIndex()
                coeff_list[attr] = coeff
            else:
                return None

    def _calculateShares(self, secret, tree, _type=dict):
        """performs secret sharing over a policy tree. could be adapted for LSSS matrices."""
        attr_list = []
        self._compute_shares(secret, tree, attr_list)
        if _type == list:
            return attr_list
        else:  # assume dict
            share = {}
            for i in range(0, len(attr_list)):
                key = attr_list[i][0].getAttributeAndIndex()
                if not key in share.keys():
                    share[key] = attr_list[i][1]
            return share

    def calculateSharesList(self, secret, tree):
        """calculate shares from given secret and returns a list of shares."""
        return self._calculateShares(secret, tree, list)

    def calculateSharesDict(self, secret, tree):
        """calculate shares from given secret and returns a dict as {attribute:shares} pairs"""
        return self._calculateShares(secret, tree, dict)

    def _compute_shares(self, secret, subtree, List):
        """computes recursive secret sharing over the binary tree. Start by splitting 1-of-2 (OR) or 2-of-2 (AND nodes).
         Continues recursively down the tree doing a round of secret sharing at each boolean node type."""
        k = 0
        if (subtree == None):
            return None

        type = subtree.getNodeType()
        if (type == OpType.ATTR):
            # visiting a leaf node
            #            t = (subtree.getAttribute(), secret)
            t = (subtree, secret)
            List.append(t)
            return None
        elif (type == OpType.OR or type == OpType.AND):
            k = subtree.threshold  # 1-of-2 or 2-of-2
        #        elif(type == OpType.AND):
        #            k = 2 # 2-of-2
        # else:
        #     return None
        # generate shares for k and n
            shares = self.genShares(secret, k, n=2)
            # recursively generate shares for children nodes
            self._compute_shares(shares[1], subtree.getLeft(), List)
            self._compute_shares(shares[2], subtree.getRight(), List)
        elif type == OpType.THRESHOLD:
            k = subtree.threshold
            n = len(subtree.children)
            shares = self.genShares(secret, k, n)
            # recursively generate shares for children nodes
            for i in range(n):
                self._compute_shares(shares[i+1], subtree.children[i], List)

    def strip_index(self, node_str):
        if node_str.find('_') != -1: return node_str.split('_')[0]
        return node_str

    def createPolicy(self, policy_string):
        assert type(policy_string) == str, "invalid type for policy_string"
        parser = PolicyParser()
        policy_obj = parser.parse(policy_string)
        _dictCount, _dictLabel = {}, {}
        parser.findDuplicates(policy_obj, _dictCount)
        for i in _dictCount.keys():
            if _dictCount[i] > 1: _dictLabel[i] = 0
        parser.labelDuplicates(policy_obj, _dictLabel)
        return policy_obj

    def prune(self, policy, attributes):
        """determine whether a given set of attributes satisfies the policy"""
        parser = PolicyParser()
        return parser.prune(policy, attributes)

    def getAttributeList(self, Node):
        aList = []
        self._getAttributeList(Node, aList)
        return aList

    def _getAttributeList(self, Node, List):
        """retrieve the attributes that occur in a policy tree in order (left to right)"""
        if (Node == None):
            return None
        # V, L, R
        if (Node.getNodeType() == OpType.ATTR):
            List.append(Node.getAttributeAndIndex())  # .getAttribute()
        else:
            for i in Node.getChildren():
                self._getAttributeList(i, List)
            # self._getAttributeList(Node.getLeft(), List)
            # self._getAttributeList(Node.getRight(), List)
        return None


# TODO: add test cases here for SecretUtil
if __name__ == "__main__":
    # group = PairingGroup('SS512')
    a = Utils()
    s=int(random.random()*(2**256)) % bn128.curve_order
    print(s)
    x = a.genShares(s, 5, 10)
    print(x)
    # y = a.recoverCoefficients([1, 2, 3])
    # print(y)
    # z = x[1]*y[1]+x[2]*y[2]+x[3]*y[3]
    # print(z)
    y = a.recoverCoefficients([1, 3, 5, 7, 8])
    # print(y)
    z = int((x[1]*y[1]+x[3]*y[3]+x[5]*y[5]+x[7]*y[7]+x[8]*y[8])%bn128.curve_order)
    print(z==s)


