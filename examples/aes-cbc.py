# -*- coding: utf-8 -*-
import sys
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


class prpcrypt():
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用  此处用的是AES-256
        length = 16
        count = len(text)
        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        text = text + (b'\0' * add)  # 补充为16的整数倍
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

        # 解密后，去掉补足的空格用strip() 去掉

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip(b'\0')


if __name__ == '__main__':
    pc = prpcrypt('BEGIN-KEY{4x@$^%`w~d##*9}END-KEY'.encode('utf-8'), 'IV{212&5^V!-!}IV'.encode('utf-8'))  # 初始化密钥和IV
    _str_ = '1234567890123456'.encode('utf-8')
    e = pc.encrypt(_str_)
    d = pc.decrypt(e)
    print('被加密的字符串长 : ' + str(len(_str_)))
    print('encrpt str is : ' + e.decode('utf-8'))

    print('decrypt str is : ' + d.decode('utf-8'))

    _str_ = '12345678901234561'.encode('utf-8')
    e = pc.encrypt(_str_)
    d = pc.decrypt(e)
    print('被加密的字符串长 : ' + str(len(_str_)))

    print('encrpt str is : ' + e.decode('utf-8'))

    print( 'decrypt str is : ' + d.decode('utf-8'))
    _str_ = '12345678901234562'.encode('utf-8')
    e = pc.encrypt(_str_)
    d = pc.decrypt(e)
    print('被加密的字符串长 : ' + str(len(_str_)))

    print('encrpt str is : ' + e.decode('utf-8'))

    print( 'decrypt str is : ' + d.decode('utf-8'))
