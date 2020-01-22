from Exp_Perms import *
from SBox import *

def pad(A, B, n):
    t1 = bin(A)[2:]
    t2 = bin(B)[2:]
    t1 = '0'*(n-len(t1))+t1
    t2 = '0'*(n-len(t2))+t2
    return t1,t2

def shift_key(A, B, n):
    A,B = pad(A,B, 28)
    tmp = A[-n:]
    A = A[n:]
    A = A+tmp
    tmp = B[-n:]
    B = B[n:]
    B = B + tmp
    return A,B

def iperm(x, P):
    tmp=[0 for i in range(64)]
    for i in range(64):
        tmp[P[i]] = x[i]
    return ''.join(tmp)

def usage():
    print("[Usage]: ", end='')
    print("python3 DES.py -k [key] -m CBC -p [plaintext] -i [IV]")

def prepare(s):
    if s == None:
        return None
    tmp = ''
    for i in s:
        x = ord(i)
        if x < 16:
            tmp += '0'+hex(x)[2:]
        else:
            tmp += hex(x)[2:]
    return tmp

def xor(A,B):
    if A==B:
        return 0
    else:
        return 1

def init_key(key):
    C = []
    D = []
    t = pad(int(key, 16), int(key, 16), 64)[0]
    t2 = ''
    for i in range(len(KP)):
        t2 += t[KP[i]]
    C.append(t2[:28])
    D.append(t2[28:])
    return C,D

def create_key(C, D, i):
    K = C[i-1]+D[i-1]
    t = ''
    for j in range(48):
        t += K[KP2[j]]
    t1,t2 = shift_key(int(C[i-1],2), int(D[i-1],2), KS[i-1])
    C.append(t1)
    D.append(t2)
    return C,D,t

def expand(A):
    t = ''
    for i in range(48):
        t += A[E[i]]
    return t

def SBOX_sub(s, l):
    t1 = int(s[1] + s[-1],2)
    t2 = int(s[2:-1], 2)
    return SB[l][t1-1][t2-1]
