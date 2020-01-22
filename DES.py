#!/bin/env python3

##
# Vittorio Mignini aka M1gnus -- -- PGiatasti
# DES cipher/decipher
##

import argparse
import threading
import re

from Exp_Perms import *
from Err_codes import *
from utils import *

def create_keys(key): # Create round keys by following the schedule
    print("Generating key schedule...")
    K = []
    C = []
    D = []
    K.append(pad_bytes(perm(pad_bytes(string_to_bin(key), 64), KP), 56))
    C.append(K[0][:28])
    D.append(K[0][28:])
    for i in range(1,17):
        C.append(shift_bytes_left(C[i-1], KS[i-1]))
        D.append(shift_bytes_left(D[i-1], KS[i-1]))
        k = C[i] + D[i]
        K.append(perm(k, KP2))
    for i in range(len(K)):
        print("{}: K = {}[{}] C = {}[{}] D = {}[{}]".format(i,K[i],len(K[i]), C[i], len(C[i]), D[i], len(D[i])))
    return C, D, K

def round_func(A, J):
    X = perm(A, E)
    B = ''
    for i in range(len(J)):
        B += xor(X[i], J[i])
    B = re.findall("......", B)
    C = ''
    for i in range(len(B)):
        C += SBOX_sub(B[i], i)
    C = perm(C, P)
    return C

def DES_encrypt(plaintext, K):
    L = []
    R = []
    print("\nCalculating L and R:")
    plaintext = string_to_bin(plaintext)

    # Initial permutation
    plaintext = perm(plaintext, IP)

    # Init L & R
    L.append(plaintext[:32])
    R.append(plaintext[32:])

    # exec encryption rouds
    for i in range(1, 17):
        L.append(R[i-1])
        tmp = round_func(R[i-1], K[i])
        R.append('')
        for j in range(len(tmp)):
            R[i] += xor(L[i-1][j], tmp[j])

    ciphertext = perm(R[16] + L[16], IPI)

    for i in range(len(R)):
        print("{}: L = {}[{}] R = {}[{}] K = {}[{}]".format(i,L[i],len(L[i]), R[i], len(R[i]), K[i], len(K[i])))

    print("\nEncrypted text: ", bin_to_hex(ciphertext))


def main():
    parser = argparse.ArgumentParser(description="A python3 implementation on DES cryptosystem")

    # Implement triple DES (-t, --triple) | implement file encryption/decryption
    parser.add_argument('-k', '--key', dest='key', action='store', default=None, help="KEY (8 bytes)")
    parser.add_argument('-p', '--plain', dest='plaintext', action='store', default=None, help="plaintext to crypt")
    parser.add_argument('-c', '--cipher', dest='ciphertext', action='store', default=None, help="ciphertext to decrypt")
    parser.add_argument('-i', '--init-vector', dest='iv', action='store', default=None, help="initialization vector iv")
    parser.add_argument('-m', '--mode', dest='mode', action='store', default=None, help="mode of operation")
    parser.add_argument('-t', '--triple', dest='triple', action='store_const', const=True, default=False, help="Use Triple DES")

    args = parser.parse_args()

    if args.plaintext == args.ciphertext:
        print("[ERROR]: Please insert ciphertext only or plaintext only\n")
        usage()
        exit(ERR_BADARGS)
    elif args.key == None:
        print("[ERROR]: Please specify a key")
        usage()
        exit(ERR_MISSINGKEY)
    elif len(args.key) != 8:
        print("[ERROR]: the key must be of length 8")
        usage()
        exit(ERR_BADKEYLENGTH)
    elif args.mode != 'ECB' and args.iv == None:
        print("[ERROR]: the requested mode needs an IV in order to work properly")
        usage()
        exit(ERR_IVNEEDED)
    else:
        plaintext = args.plaintext
        ciphertext = args.ciphertext
        key = args.key
        IV = args.iv
        triple = args.triple
        C, D, K = create_keys(key)
        DES_encrypt(plaintext, K)

if __name__=="__main__":
    main()
