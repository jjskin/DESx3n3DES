import datetime
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from secrets import token_bytes

keyT = token_bytes(24)
key1 = keyT[0:8]
key2 = keyT[8:16]
key3 = keyT[16:24]

def DESx3Encrypt(read):
    reszta = 8 - len(read)%8
    read = read + b' '*reszta

    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    cipher3 = DES.new(key3, DES.MODE_ECB)

    p1 = cipher1.encrypt(read)
    p2 = cipher2.decrypt(p1)
    p3 = cipher3.encrypt(p2)

    return p3


def TDESEncrypt(read):
    reszta = 8 - len(read)%8
    read = read + b' '*reszta

    cipherT = DES3.new(keyT, DES3.MODE_ECB)

    pDES3 = cipherT.encrypt(read)

    return pDES3


def DESx3Decrypt(read):
    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    cipher3 = DES.new(key3, DES.MODE_ECB)

    p1 = cipher3.decrypt(read)
    p2 = cipher2.encrypt(p1)
    p3 = cipher1.decrypt(p2)

    return p3


def TDESDecrypt(read):
    cipherT = DES3.new(keyT, DES3.MODE_ECB)
    
    pDES3 = cipherT.decrypt(read)

    return pDES3


#Input file--------------------------------------------------------------------------------------#
input = open("input.txt", "rb")
read = input.read()
#------------------------------------------------------------------------------------------------#


#3 razy DES kodowanie----------------------------------------------------------------------------#
startDesX3E = datetime.datetime.now()
outBytesDESx3 = DESx3Encrypt(read)
durationDesX3E = datetime.datetime.now() - startDesX3E

outByte = open('outputBytesDESx3.bin', 'wb')
outByte.write(outBytesDESx3)
outByte.close()
#------------------------------------------------------------------------------------------------#


#3DES kodowanie----------------------------------------------------------------------------------#
startTDesE = datetime.datetime.now()
outBytes3DES = TDESEncrypt(read)
durationTDesE = datetime.datetime.now() - startTDesE

outByte2 = open('outputByte3DES.bin', 'wb')
outByte2.write(outBytes3DES)
outByte2.close()
#------------------------------------------------------------------------------------------------#


#3 razy DES dekodowanie--------------------------------------------------------------------------#
inputByte = open('outputBytesDESx3.bin', 'rb')
readDESx3 = inputByte.read()
inputByte.close()

startDesX3D = datetime.datetime.now()
outDESx3 = DESx3Decrypt(readDESx3)
durationDesX3D = datetime.datetime.now() - startDesX3D

output = open('outputDESx3.txt', 'w')
output.write(bytes.fromhex(outDESx3.hex()).decode('utf-8'))
print(outDESx3)
output.close()
#------------------------------------------------------------------------------------------------#


#3DES dekodowanie--------------------------------------------------------------------------------#
inputByte2 = open('outputByte3DES.bin', 'rb')
read3DES = inputByte2.read()
inputByte2.close()

startTDesD = datetime.datetime.now()
out3DES = TDESDecrypt(read3DES)
durationTDesD = datetime.datetime.now() - startTDesD

output2 = open('output3DES.txt', 'w')
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

input.close()

