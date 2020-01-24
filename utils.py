from SBox import SB
from Err_codes import ERR_OVERFLOW
import re

def pad_bytes(A: str, n: int) -> str:
    return '0'*(n-len(A))+A

def shift_bytes_left(A: str, n: int) -> str:
    return A[n:]+A[:n]

def shift_bytes_right(A: str, n: int) -> str:
    return A[-n:]+A[:-n]

def perm(A: str, P: list) -> str:
    return ''.join([ A[i] for i in P ])

def usage():
    print("[Usage]: python3 DES.py -k [key] -m CBC -p [plaintext] -i [IV]")

def xor(A: str, B: str) -> str:
    if A==B:
        return '0'
    else:
        return '1'

def string_to_bin(s: str) -> str:
    tmp = ''
    for i in s:
        x = ord(i)
        if(len(hex(x)[2:]) > 2):
            x = int(hex(x)[-2:], 16)
        tmp += pad_bytes(bin(x)[2:], 8)
    return tmp

def bin_to_hex(b: str) -> str:
    L = re.findall("....", b)
    tmp = ''.join( [hex(int(i,2))[2:] for i in L ] )
    return tmp

def hex_to_bin(h: str) -> str:
    tmp = ''
    for i in h:
        tmp += pad_bytes(bin(int(i,16))[2:], 4)
    return tmp

def hex_to_str(h: str) -> str:
    tmp = ''
    if len(h) % 2 == 1:
        h = '0' + h
    L = re.findall("..", h)
    for i in L:
        tmp += chr(int(i,16))
    return tmp

def SBOX_sub(s: str, l: int) -> str:
    i = int(s[0] + s[-1],2)
    j = int(s[1:-1], 2)
    return pad_bytes(bin(SB[l][i][j])[2:], 4)

def increment_counter(b: str) -> str:
    b = list(b)
    n = len(b)
    overflow = True
    for i in range(n):
        if b[n-i-1] == '1':
            b[n-i-1] = '0'
        else:
            b[n-i-1] = '1'
            overflow = False
            break
    if overflow:
        print("[ERROR]: overflow while incrementing counter")
        exit(ERR_OVERFLOW)
    return ''.join(b)
