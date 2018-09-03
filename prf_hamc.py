#!/usr/bin/env python  
# -*- coding:utf-8 -*-   

import hmac
import hashlib
from binascii import b2a_hex, a2b_hex  

def key_generator(K,S):   # 字节流
	
	SKEYSEED = hmac.new(K, S, digestmod=hashlib.sha1).hexdigest()
	
	key = a2b_hex(SKEYSEED)
	T = ''
	TotalKey = ''
	for i in range(0, 5): # 10 次循环足够生成所需密钥
		count_byte = a2b_hex('%02d' % i) # 0x01 0x02 0x03 ...
		data = T + S + count_byte
		T = hmac.new(key, data, digestmod=hashlib.sha1).hexdigest()
		T = a2b_hex(T)
		TotalKey += T
	
	#print len(TotalKey)
	# SK_d  = TotalKey[0:32]
	# SK_ai = TotalKey[32:32+32]
	# SK_ar = TotalKey[64:64+32]
	# SK_ei = TotalKey[96:96+16]
	# SK_er = TotalKey[112:112+16]
	# SK_pi = TotalKey[128:128+32]
	# SK_pr = TotalKey[160:160+32]

	# print 'SK_d  = ' + b2a_hex(SK_d)
	# print 'SK_ai = ' + b2a_hex(SK_ai)
	# print 'SK_ar = ' + b2a_hex(SK_ar)
	# print 'SK_ei = ' + b2a_hex(SK_ei)
	# print 'SK_er = ' + b2a_hex(SK_er)
	# print 'SK_pi = ' + b2a_hex(SK_pi)
	# print 'SK_pr = ' + b2a_hex(SK_pr)

	#return SK_d,SK_ai,SK_ar,SK_ei,SK_er,SK_pi,SK_pr
	return SKEYSEED , TotalKey
