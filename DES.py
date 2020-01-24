#!/bin/env python3

##
# Vittorio Mignini aka M1gnus -- -- PGiatasti
# DES cipher/decipher
##

import argparse
import re

from Exp_Perms import *
from Err_codes import *
from utils import *

def create_blocks(text: str, padding: bool) -> list:
    if len(text)%64 != 0:
        text = text + '00001000'*(8 - (len(text) % 64)//8)
    if padding:
        text = text + '00001000'*8
    pattern = "."*64
    B = re.findall(pattern, text)
    return B

def ECB_encrypt(Blocks: list, K: list) -> str:
    result=''
    for i in Blocks:
        result += DES_encrypt(i, K)
    return result

def ECB_decrypt(Blocks: list, K: list) -> str:
    result=''
    for i in Blocks:
        result += DES_decrypt(i, K)
    return result

def CBC_encrypt(Blocks: list, K: list, IV: str) -> str:
    result=''
    for i in Blocks:
        tmp = ''
        for j in range(64):
            tmp += xor(IV[j], i[j])
        IV = DES_encrypt(tmp, K)
        result += IV
    return result

def CBC_decrypt(Blocks: list, K: list, IV: str) -> str:
    result=''
    for i in Blocks:
        tmp = ''
        plain = DES_decrypt(i, K)
        for j in range(64):
            tmp += xor(IV[j], plain[j])
        IV = i
        result += tmp
    return result

def OFB_encrypt_decrypt(Blocks: list, K: list, IV: str) -> str:
    result=''
    for i in Blocks:
        tmp = ''
        IV = DES_encrypt(IV, K)
        print(len(IV), len(i))
        for j in range(64):
            tmp += xor(i[j], IV[j])
        result += tmp
    return result

def CFB_encrypt_decrypt(Blocks: list, K: list, IV: str) -> str:
    result=''
    for i in Blocks:
        tmp = ''
        IV = DES_encrypt(IV, K)
        print(len(IV), len(i))
        for j in range(64):
            tmp += xor(i[j], IV[j])
        IV = tmp
        result += tmp
    return result

def CTR_encrypt_decrypt(Blocks: list, K: list, IV: str) -> str:
    result=''
    print(IV)
    for i in Blocks:
        tmp = ''
        print(IV)
        IV = increment_counter(IV)
        print(IV)
        t = DES_encrypt(IV, K)
        for j in range(64):
            tmp += xor(i[j], t[j])
        result += tmp
    return result

def create_keys(key: str) -> tuple: # Create round keys by following the schedule
    print("\nGenerating key schedule from ", bin_to_hex(key), " ...")
    K = []
    C = []
    D = []
    K.append(pad_bytes(perm(pad_bytes(key, 64), KP), 56))
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

def round_func(A: str, J: str) -> str:
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

def DES_encrypt(plaintext: str, K: list) -> str:
    L = []
    R = []
    print("\nCalculating L and R:")

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

    # Final permutation
    ciphertext = perm(R[16] + L[16], IPI)

    for i in range(len(R)):
        print("{}: L = {}[{}] R = {}[{}] K = {}[{}]".format(i,L[i],len(L[i]), R[i], len(R[i]), K[i], len(K[i])))

    return ciphertext

def DES_decrypt(ciphertext: str, K: list) -> str:
    L = []
    R = []
    print("\nCalculating L and R:")

    # Initial permutation
    ciphertext = perm(ciphertext, IP)

    # Init L & R
    L.append(ciphertext[32:])
    R.append(ciphertext[:32])

    # exec encryption rouds
    for i in range(1, 17):
        R.append(L[i-1])
        tmp = round_func(L[i-1], K[17-i])
        L.append('')
        for j in range(len(tmp)):
            L[i] += xor(R[i-1][j], tmp[j])

    # Final permutation
    plaintext = perm(L[16] + R[16], IPI)

    for i in range(len(R)):
        print("{}: L = {}[{}] R = {}[{}] K = {}[{}]".format(16-i,L[i],len(L[i]), R[i], len(R[i]), K[16-i], len(K[16-i])))

    return plaintext

def menu(plaintext: str, ciphertext: str, key: str, IV: str, mode: str, C: list, D: list, K: list, pad: bool, raw: bool) -> None:
    B = create_blocks((plaintext if plaintext is not None else ciphertext), pad)
    if mode == 'ECB':
        result = (ECB_encrypt(B, K) if plaintext != None else ECB_decrypt(B, K))
    elif mode == 'CBC':
        result = (CBC_encrypt(B, K, IV) if plaintext != None else CBC_decrypt(B, K, IV))
    elif mode == 'OFB':
        result = OFB_encrypt_decrypt(B, K, IV)
    elif mode == 'CFB':
        result = CFB_encrypt_decrypt(B, K, IV)
    elif mode == 'CTR':
        result = CTR_encrypt_decrypt(B, K, IV)
    else:
        print("Unknown mode of operation")

    result = bin_to_hex(result)
    if raw:
        result = hex_to_str(result)

    print("\nResult:", result)
    exit(0)

def main() -> None:
    parser = argparse.ArgumentParser(description="A python3 implementation on DES cryptosystem")

    parser.add_argument('-k', '--key', dest='key', action='store', default=None, help="KEY (8 bytes)")
    parser.add_argument('-p', '--plain', dest='plaintext', action='store', default=None, help="plaintext to crypt")
    parser.add_argument('-c', '--cipher', dest='ciphertext', action='store', default=None, help="ciphertext to decrypt")
    parser.add_argument('-i', '--init-vector', dest='iv', action='store', default=None, help="initialization vector iv")
    parser.add_argument('-x', '--hex', dest='hex_input', action='store_const', const=True, default=False, help="read input as hex value")
    parser.add_argument('-m', '--mode', dest='mode', action='store', default='ECB', help="mode of operation (ECB, CBC, CFB, OFB, CTR)")
    parser.add_argument('-P', '--padding', dest='pad', action='store_const', const=True,  default=False, help="add 8 bytes of padding at the end of the ciphertext... use it for compatibility with cyberchef when the blocks are correctly divided without padding")
    parser.add_argument('-I', '--pad-iv', dest='piv', action='store_const', const=True,  default=False, help="pad iv if it's not long 64 bytes")
    parser.add_argument('-r', '--raw', dest='raw', action='store_const', const=True,  default=False, help="set raw outputs")

    args = parser.parse_args()

    if (args.plaintext == None and args.ciphertext == None) or (args.plaintext != None and args.ciphertext != None):
        print("[ERROR]: Please insert ciphertext only or plaintext only\n")
        usage()
        exit(ERR_BADARGS)
    elif args.key == None:
        print("[ERROR]: Please specify a key")
        usage()
        exit(ERR_MISSINGKEY)
    elif (len(args.key) != 8 and not args.hex_input) or (len(args.key) != 16 and args.hex_input):
        print("[ERROR]: the key must be of length 8 (bytes)")
        usage()
        exit(ERR_BADKEYLENGTH)
    elif args.mode != 'ECB' and args.iv == None:
        print("[ERROR]: the requested mode needs an IV in order to work properly")
        usage()
        exit(ERR_IVNEEDED)
    elif args.iv != None and (((len(args.iv) < 8 and not args.piv) or len(args.iv) > 8) if not args.hex_input else ((len(args.iv) < 16 and not args.piv) or len(args.iv) > 16)):
        print("[ERROR]: the iv must be of length 8 (bytes)")
        exit(ERR_BADIVLENGTH)
    else:
        plaintext = (hex_to_bin(args.plaintext) if args.hex_input else string_to_bin(args.plaintext)) if args.plaintext != None else None
        ciphertext = (hex_to_bin(args.ciphertext) if args.hex_input else string_to_bin(args.ciphertext)) if args.ciphertext != None else None
        key = hex_to_bin(args.key) if args.hex_input else string_to_bin(args.key)
        IV = (hex_to_bin(args.iv) if args.hex_input else string_to_bin(args.iv)) if args.iv != None else None
        if IV is not None and args.piv:
            IV = pad_bytes(IV, 64)
        C, D, K = create_keys(key)
        menu(plaintext, ciphertext, key, IV, args.mode, C, D, K, args.pad, args.raw)

if __name__=="__main__":
    main()
