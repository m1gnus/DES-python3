from SBox import *
import re

def pad_bytes(A, n):
    return '0'*(n-len(A))+A

def shift_bytes_left(A, n):
    return A[n:]+A[:n]

def shift_bytes_right(A, n):
    return A[-n:]+A[:-n]

def perm(A, P):
    return ''.join([ A[i] for i in P ])

def usage():
    print("[Usage]: python3 DES.py -k [key] -m CBC -p [plaintext] -i [IV]")

def xor(A,B):
    if A==B:
        return '0'
    else:
        return '1'

def string_to_bin(s):
    tmp = ''
    for i in s:
        x = ord(i)
        if(len(hex(x)[2:]) > 2):
            x = int(hex(x)[-2:], 16)
        tmp += pad_bytes(bin(x)[2:], 8)
    return tmp

def bin_to_hex(b):
    L = re.findall("....", b)
    tmp = ''.join( [hex(int(i,2))[2:] for i in L ] )
    return tmp

def SBOX_sub(s, l):
    i = int(s[0] + s[-1],2)
    j = int(s[1:-1], 2)
    return pad_bytes(bin(SB[l][i][j])[2:], 4)
