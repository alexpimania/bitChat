import random
import string
import hashlib
import Crypto
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import sys
import pickle
import json
import time


keyLength = 2048  # Key size (in bits)
    
    
def genRanString(size=16, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def generateAESKey():
    AESKey = genRanString()
    AESIV = genRanString()
    AESObj = AES.new(AESKey, AES.MODE_CBC, AESIV)
    return [AESKey, AESIV, AESObj]
   
   
def encryptAES(AESObject, payload):
    try:
        payload = payload.encode("utf-8")
    except: pass
    payload += ((16 - len(payload) % 16) * " ").encode("utf-8")
    return AESObject.encrypt(payload)
    
    
def importRSAPubKey(pubKey):
    return RSA.importKey(pubKey)
    

def importRSAPrivKey(privKey, password):
    return RSA.importKey(privKey, passphrase=password)

    
def encryptRSA(pubKey, payload):
    try:
        payload = payload.encode("utf-8")
    except: pass
    return pubKey.encrypt(payload, 32)[0]
    
    
def sign(keyPair, payload):
    try:
        payload = payload.encode("utf-8")
    except: pass
    return keyPair.sign(payload, '')
    
    
def hash256(payload):
    try:
        payload = payload.encode("utf-8")
    except: pass
    sha256Obj = hashlib.sha256()
    sha256Obj.update(payload)
    return sha256Obj.digest()
    
    
def generateRSAKeyPair():
    randomData = Random.new().read
    return RSA.generate(keyLength, randomData)
    
    
def encodeMessage(message, recipientPubKey):
    messageObj = {}
    messageBody = {}
    
    recipientKeyPair = importRSAPubKey(recipientPubKey)
    senderKeyPair = importRSAPrivKey(open("senderPrivKey.txt").read(), "a")
    AESKey, AESIV, AESObject = generateAESKey()
     
    ID = hash256(senderKeyPair.exportKey(format="PEM", passphrase="a") + str(time.time()))
    print(ID)
    rawSenderPubKey = senderKeyPair.publickey().exportKey()
    signedMessageHash = sign(senderKeyPair, hash256(message))
    signedIDHash = sign(senderKeyPair, hash256(ID))
    encryptedAESKey = encryptRSA(recipientKeyPair.publickey(), AESKey)
    encryptedAESIV = encryptRSA(recipientKeyPair.publickey(), AESIV)
    
    messageObj["encryptedAESKey"] = encryptedAESKey
    messageObj["encryptedAESIV"] = encryptedAESIV
    messageObj["ID"] = ID
    
    messageBody["ID"] = ID
    messageBody["senderPubKey"] = rawSenderPubKey
    messageBody["message"] = message
    messageBody["signedMessageHash"] = signedMessageHash
    messageBody["signedIDHash"] = signedIDHash
    
    messageBodyPickle = pickle.dumps(messageBody)
    encryptedMessageBody = encryptAES(AESObject, messageBodyPickle)
    messageObj["body"] = encryptedMessageBody
    
    return pickle.dumps(messageObj)
    
encodeMessage("hi", """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlWfMOXZVhdCiig6dv+MQ
uPRzmg6+sUG7Yu44lXKKYc60/q1cv21O1cbGrmBqMTXR03egRvYPLqm7cRtpwpV4
vf4Ogfqwrdk78VRci+0p/SYmskDb4EtNca8BhIF5fO/BH+6q7pZXe/RizYs6ci2q
iHq417Tej6oBzUYaNFhkAbxOgax9vdfn2QdW/+hpFEOIuME9UmYOlSDQrjdT20Rh
2D26r01f4d+AvwGBSDxrnVrH9NTGAKBX66If4HUmRC7RpEU3mDOP03WIwq97Kec9
ovLj1ZdalaLO1ixJDuSN/aLM4DZCDY5j6oxD1gxtqSQuPb5xfCcpYR6eR37bhgPT
LwIDAQAB
-----END PUBLIC KEY----- 
""")
