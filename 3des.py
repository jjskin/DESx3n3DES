import math
import datetime
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from secrets import token_bytes

keyT = token_bytes(24)
key1 = keyT[0:8]
key2 = keyT[8:16]
key3 = keyT[16:24]

def DESx3Encrypt(read):
    DESx3 = b''
    ile = int(math.ceil(len(read)/8))
    reszta = 8-len(read)%8
    read = read+' '*reszta
    read = bytes(read, 'utf-8')

    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    cipher3 = DES.new(key3, DES.MODE_ECB)

    for i in range(0, ile):
        p1 = cipher1.encrypt(read[(0+8*i):(8+8*i)])
        p2 = cipher2.decrypt(p1)
        p3 = cipher3.encrypt(p2)
        DESx3 = DESx3+p3

    return DESx3


def TDESEncrypt(read):
    pDES3 = b''
    ile = int(math.ceil(len(read)/24))
    reszta = 24-len(read)%24
    read = read+' '*reszta
    read = bytes(read, 'utf-8')

    cipherT = DES3.new(keyT, DES3.MODE_ECB)

    if(len(read)>24): 
        for i in range(0, ile):
            pDES3 = pDES3+cipherT.encrypt(read[(0+24*i):(24+24*i)])
    else:
        pDES3 = cipherT.encrypt(read)

    return pDES3


def DESx3Decrypt(read):
    DESx3 = b''
    ile = int(math.ceil(len(read)/8))

    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    cipher3 = DES.new(key3, DES.MODE_ECB)

    for i in range(0, ile):
        p1 = cipher3.decrypt(read[(0+8*i):(8+8*i)])
        p2 = cipher2.encrypt(p1)
        p3 = cipher1.decrypt(p2)
        DESx3 = DESx3+p3

    return DESx3


def TDESDecrypt(read):
    pDES3 = b''
    ile = int(math.ceil(len(read)/24))

    cipherT = DES3.new(keyT, DES3.MODE_ECB)
    
    if(len(read)>24): 
        for i in range(0, ile):
            pDES3 = pDES3+cipherT.decrypt(read[(0+24*i):(24+24*i)])
    else:
        pDES3 = cipherT.decrypt(read)

    return pDES3


#Input file--------------------------------------------------------------------------------------#
with open('input.txt', 'r') as input:
    read = input.read()
    input.close() 
#------------------------------------------------------------------------------------------------#


#3 razy DES kodowanie----------------------------------------------------------------------------#
startDesX3E = datetime.datetime.now()
outBytesDESx3 = DESx3Encrypt(read)
durationDesX3E = datetime.datetime.now() - startDesX3E

with open('outputBytesDESx3.txt', 'wb') as outByte:
    outByte.write(outBytesDESx3)
    outByte.close
#------------------------------------------------------------------------------------------------#


#3DES kodowanie----------------------------------------------------------------------------------#
startTDesE = datetime.datetime.now()
outBytes3DES = TDESEncrypt(read)
durationTDesE = datetime.datetime.now() - startTDesE

with open('outputByte3DES.txt', 'wb') as outByte2:
    outByte2.write(outBytes3DES)
    outByte2.close
#------------------------------------------------------------------------------------------------#


#3 razy DES dekodowanie--------------------------------------------------------------------------#
with open('outputBytesDESx3.txt', 'rb') as outByte2:
    readDESx3 = outByte2.read()
    outByte2.close()

startDesX3D = datetime.datetime.now()
outDESx3 = DESx3Decrypt(readDESx3)
durationDesX3D = datetime.datetime.now() - startDesX3D

with open('outputDESx3.txt', 'w') as output:
    output.write(bytes.fromhex(outDESx3.hex()).decode('utf-8'))
    output.close
#------------------------------------------------------------------------------------------------#


#3DES dekodowanie--------------------------------------------------------------------------------#
with open('outputByte3DES.txt', 'rb') as outByte2:
    read3DES = outByte2.read()
    outByte2.close()

startTDesD = datetime.datetime.now()
out3DES = TDESDecrypt(read3DES)
durationTDesD = datetime.datetime.now() - startTDesD

with open('output3DES.txt', 'w') as output2:
    output2.write(bytes.fromhex(out3DES.hex()).decode('utf-8'))
    output2.close
#------------------------------------------------------------------------------------------------#


#Klucze------------------------------------------------------------------------------------------#
print("Klucz hex 3 razy DES:        ", (key1 + key2 + key3).hex()) 
print("Klucz hex 3DES:              ", keyT.hex())
#------------------------------------------------------------------------------------------------#


#Czasy-------------------------------------------------------------------------------------------#
print("Czas kodowania 3 razy DES:   ", durationDesX3E)
print("Czas kodowania 3DES:         ", durationTDesE)
print("Czas dekodowania 3 razy DES: ", durationDesX3D)
print("Czas dekodowania 3DES:       ", durationTDesD)
#------------------------------------------------------------------------------------------------#