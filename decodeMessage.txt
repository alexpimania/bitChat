import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import pickle


def importRSAPrivKey(privKey, password):
    return RSA.importKey(privKey, passphrase=password)


def importRSAPubKey(pubKey):
    return RSA.importKey(pubKey)
    

def decryptAES(AESObj, payload):
    decryptedPayload =  AESObj.decrypt(payload)
    try:
        decryptedPayload = decryptedPayload.decode("utf-8")
    except: pass
    return decryptedPayload.rightstrip()
    

def decryptRSA(receiverKeyPair, payload):
    decryptedPayload =  receiverKeyPair.decrypt(payload)
    try:
        decryptedPayload = decryptedPayload.decode("utf-8")
    except: pass
    return decryptedPayload
    
    
def hash256(payload):
    try:
        payload = payload.encode("utf-8")
    except: pass
    sha256Obj = hashlib.sha256()
    sha256Obj.update(payload)
    return sha256Obj.digest()


def verifyRSA(pubKey, check, signature):
    return pubKey.verify(check, signature)
    
    
def verifySignature(messageBody, dataName):
    senderKeyPair = RSA.importKey(messageBody["senderPubKey"])
    dataHash = hash256(messageBody[dataName])
    signedDataHash = messageBody["signed" + dataName[0].upper() + dataName[1:] + "Hash"]
    return verifyRSA(senderKeyPair.publickey(), dataHash, signedDataHash)


def checkID(ID):
    IDList = "".join(open("IDList.txt").read().strip().split("\n"))
    if ID in IDList:
        return False
    with open("IDList.txt", "w+") as f:
        f.write(ID + "\n")
    return True
    

def decodeMessage(encodedMessagePickle):
    receiverKeyPair = importRSAPrivKey(open("receiverPrivKey.txt").read(), "a")
    encodedMessage = pickle.loads(encodedMessagePickle)
    
    AESKey = decryptRSA(receiverKeyPair, encodedMessage["encryptedAESKey"])
    AESIV = decryptRSA(receiverKeyPair, encodedMessage["encryptedAESIV"])
    
    try:
        AESObj = AES.new(AESKey, AES.MODE_CBC, AESIV)
        messageBody = pickle.loads(AESObj.decrypt(encodedMessage["body"]))
    except (KeyError, ValueError): return "Decryption Error"
    ID = messageBody["ID"]
    if not checkID(ID): return "Old ID"
    if not verifySignature(messageBody, "ID"): return "ID verification error"
    if not verifySignature(messageBody, "message"): return "Message verification error"
    return [messageBody["message"].strip(), messageBody["senderPubKey"].decode("utf-8")]
    
