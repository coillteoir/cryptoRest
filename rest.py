#Author: David Lynch
#Date: 18/04/2022


#importing libraries used in the program

import os
import string
import hashlib
import json
import base64
import random
import ast


from flask import Flask
from flask_restful import Resource, Api 
from Cryptodome.Cipher import AES               #Enables the use of AES encryption

app = Flask(__name__)                           
api = Api(app)

def fencrypt(src,key):
    #load json as a dictionary
    data = json.load(src)                       #Loads the json input into a python dictionary
    
    if(os.path.exists("nonces.txt")):           #checks if file exists it opens it
        nonfile = open("nonces.txt","rt+")
        pass
    else:
        nonfile = open("nonces.txt", "xt+")     #if file doesn't exist then it creates a new one

    for index in data:
        cipher = AES.new(key,AES.MODE_EAX)      #Generates a cipher using the key in the mode 'EAX'
        nonce = cipher.nonce                    #Generates a single use number for decrypting the ciphertext
        print(type(nonce))                      
        nonfile.writelines(str(nonce))          #writes nonce to file
        nonfile.writelines("\n")                
        
        cipherText,tag = cipher.encrypt_and_digest(str(data[index]).encode())   #converts the input text to be suitable for the cipher
        data[index] = str(base64.b64encode(cipherText),'utf-8')                 #writes ciphertext to the dictionary elements by decoding it from base64
    
    #writes encrypted data to the json file and the nonces to the noncefile

    src.seek(0)
    json.dump(data,src)
    src.truncate()
    nonfile.truncate()
    

    pass

def fdecrypt(src,key):
    data = json.load(src)

    noncefile = open("nonces.txt","r")  
    nonces = noncefile.readlines()      #reads the nonces to a list
    ind = 0                             
    for index in data:
        nonce = nonces[ind]
        nonce = str.encode(nonce)
        cipher = AES.new(key,AES.MODE_EAX,nonce=nonce)          #generates a cipher for decrypting 
        plainData = cipher.decrypt(str(data[index]).encode())   
        data[index] = str(base64.b64encode(plainData),'utf-8')
        ind += 1

    src,seek(0)
    json.dump(data,src)
    src.truncate()



#generates keys
def genkeys():
    if(os.path.exists("keys.key")): #checks filesystem for keyfile
            return "no keys need to be generated"
            pass
    else:
        fp = open("keys.key","xb+") #creates a new binary file to store keys
             
        key = os.urandom(16)        #generates a random 16 byte key

        fp.write(key) 
    
     

class HelloWorld(Resource):
    def get(self):
        return "Hello Evervault!"

class encrypt(Resource):
    def get(self):    
        Key = KF.read()
        return fencrypt(src,Key)

class decrypt(Resource):
    def get(self):
        Key = KF.read()
        return fdecrypt(src,Key)

class sign(Resource):
    def get(self):
        return "sign"

class verify(Resource):
    def get(self):
        return "verify"


#adds resources to the api

api.add_resource(HelloWorld,'/')
api.add_resource(encrypt,'/','/encrypt',endpoint='encrypt')
api.add_resource(decrypt,'/','/decrypt',endpoint='decrypt')
api.add_resource(decrypt,'/','/sign',endpoint='sign')
api.add_resource(decrypt,'/','/verify',endpoint='verify')

#Execution begins here
if __name__ == '__main__':
    src = open("./src.json","r+")

    genkeys() 
    KF = open("keys.key","rb")
     
    app.run()
    
    

