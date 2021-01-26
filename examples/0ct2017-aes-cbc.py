#!/usr/bin/python -u
from Crypto.Cipher import AES
from hashlib import md5
from Crypto import Random
from binascii import b2a_hex

from Crypto.SelfTest.st_common import a2b_hex

BS = 16  # BlockSize
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1:])]


class Scheme:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):  # raw = admin , return hex(iv+ AES(admin))
        raw = pad(raw)
        raw = md5(raw.encode('utf8') ).digest() + raw.encode('utf8')
        iv = Random.new().read(BS)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b2a_hex(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = a2b_hex(enc)
        iv = enc[:BS]
        enc = enc[BS:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        blob = cipher.decrypt(enc)
        checksum = blob[:BS]
        data = blob[BS:]
        if md5(data).digest() == checksum:
            return unpad(data)
        else:
            return


key = Random.new().read(BS)
scheme = Scheme(key)
#flag = open("flag", 'r').readline()
flag="111111111111111111111111"
#alarm(30)
print("Welcome to 0CTF encryption service!")
while True:
    print("Please [r]egister or [l]ogin")
    cmd = input()
    if not cmd:
        break
    if cmd[0] == 'r':
        name = input().strip()
        if (len(name) > 32):
            print("username too long!")
            break
        if pad(name) == pad("admin"):
            print("You cannot use this name!")
            break
        else:
            print("Here is your secret:")
            print(scheme.encrypt(name))
    elif cmd[0] == 'l':
        data = input().strip()
        name = scheme.decrypt(data)
        if name == "admin":
            print("Welcome admin!")
            print(flag)
        else:
            print("Welcome %s!" % name)
    else:
        print("Unknown cmd!")
        break
