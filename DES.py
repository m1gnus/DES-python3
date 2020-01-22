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

ciphertext = ''
plaintext = ''
key = ''
IV = ''
triple = False

def round_function(L, R, key, i):
    L.append(R[i-1])
    e = expand(R[i-1])
    x = ''
    for j in range(48):
        x += str(xor(key[j], e[j]))
    T = re.findall("......", x)
    for j in range(8):
        T[j] = bin(SBOX_sub(T[j], j))[2:]
    C = pad(int(''.join(T), 2), 20, 32)[0]
    t = ''
    t2 = ''
    for j in range(32):
        t += C[P[j]]
    t = pad(int(t,2), 100, 32)[0]
    print(len(L[0]), len(t))
    for j in range(32):
        t2 += str(xor(t[j], L[i-1][j]))
    R.append(t2)
    return L,R

def DES_encrypt(ciphertext, plaintext, key):
    L = []
    R = []
    C,D = init_key(key)
    plaintext=pad(int(plaintext, 16),int(plaintext, 16), 64)[0]
    ciphertext = iperm(plaintext, IP)
    L.append(ciphertext[:32])
    R.append(ciphertext[32:])
    for i in range(1,17):
        C,D,k = create_key(C,D,i)
        L,R = round_function(L, R, k, i)
    ciphertext = R[16]+L[16]
    ciphertext = iperm(ciphertext, IPI)
    print(hex(int(ciphertext,2))[2:])

def main():
    global plaintext
    global ciphertext
    global key
    global IV
    global triple

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
    elif args.mode != 'EBC' and IV == None:
        print("[ERROR]: the requested mode needs an IV in order to work properly")
        usage()
        exit(ERR_IVNEEDED)
    else:
        plaintext = prepare(args.plaintext)
        ciphertext = prepare(args.ciphertext)
        key = prepare(args.key)
        IV = prepare(args.iv)
        triple = args.triple
        #Implement menu, divisione del plaintext in blocchi TODO:
        DES_encrypt(ciphertext, plaintext, key)


if __name__ == '__main__':
    main()
