# DES-python3
an implementation of DES algorithm in python3
# Positional Parameters

-k [KEY] -> the key must be of length 8 bytes, so 8 chars or 16 hex digits (if -x is set)

-p [PLAIN] -> plaintext

-c [CIPHER] -> ciphertext

-m [MODE] -> mode of operation (ECB, CBC, OFB, CFB, CTR)

-i [IV] -> initialization vector... not required in ECB mode

-x -> if set all inputs will be read as hex values

-P -> add 8 bytes of padding to plaintext before the encryption

-I -> pad IV if it's less than 8 bytes

-r -> raw output
