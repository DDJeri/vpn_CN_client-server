#!/usr/bin/env python  
# -*- coding:utf-8 -*-

import hmac
import hashlib
from binascii import b2a_hex, a2b_hex
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA

def RSA_cert(message,file,key = None,flag = True):  #flag = True encrypto, flag = false decrypto
	f = open(file).read()
	pubkey = RSA.importKey(f,key)
	cipher = PKCS1_v1_5.new(pubkey)
	if flag:
		cipher_text = cipher.encrypt(message)
	else:
		cipher_text = cipher.decrypt(message,"a")
	return cipher_text

def RSA_tup(message,module,exponent):
	pubkey = RSA.construct((module,exponent))
	cipher = PKCS1_v1_5.new(pubkey)
	return cipher.encrypt(message)

def RSA_verify(message,module,exponent,signature):
	pubkey = RSA.construct((module,exponent))
	cipher = Signature_pkcs1_v1_5.new(pubkey)
	digest = SHA.new()
	digest.update(message)
	return cipher.verify(digest,signature)

def RSA_sign(message,file,key = None):
	f = open(file).read()
	pubkey = RSA.importKey(f,key)
	signer = Signature_pkcs1_v1_5.new(pubkey)
	digest = SHA.new()
	digest.update(message)
	sign = signer.sign(digest)
	return sign

	
