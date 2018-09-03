# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#

"""
High level interface to `IKEv2 protocol <http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-rfc5996bis-02>`_
"""
from enum import IntEnum
from functools import reduce
import logging
import operator
import os
import hmac
from hashlib import sha256,sha1
from struct import unpack
import binascii
import struct
from math import ceil
import Queue
from ctypes import *

from auth import RSA_tup,RSA_cert,RSA_verify,RSA_sign
from prf import prfplus
import payloads
import const
import proposal
from prf_hamc import key_generator
import payloads


SPDADD_SYNTAX = """
spdadd {mysubip}/24 {peersubip}/24 any -P out ipsec\n\tesp/tunnel/{myip}-{peerip}/require;
spdadd {peersubip}/24 {mysubip}/24 any -P in ipsec\n\tesp/tunnel/{peerip}-{myip}/require;
"""
ESP_ADD_SYNTAX = 'add {ip_from} {ip_to} esp 0x{spi} -m tunnel\n\t-E aes-cbc 0x{key_e}\n\t-A hmac-sha1 0x{key_a};'

MACLEN = 16

logger = logging.getLogger(__name__)


class State(IntEnum):
    STARTING = 0
    INIT1 = 1
    INIT2 = 2
    INIT3 = 3
    INIT4 = 4
    INIT5 = 5
    INIT6 = 6
    QUICKINIT = 7
    QUICK1 = 8
    QUICK2 = 9
    QUICK3 = 10
    RECEIVING = 11
    PHASE1_KEY_CAL = 12
    FINISHED = 20

class sm4_context(Structure):
    _fields_ = [("mode", c_int), ("sk", c_ulong*32)]

class sm4cbc():
    def __init__(self):  
        SM4 = CDLL('./sm4.so')
        self.sm4_cbc = SM4.sm4_crypt_cbc
        self.sm4_setkey_enc = SM4.sm4_setkey_enc
        self.sm4_setkey_dec  =SM4.sm4_setkey_dec

    def trf_byte2c_ubyte(self,data_array,data):
        for i in range(len(data)):
            data_array[i] = c_ubyte(ord(data[i]))
        return data_array

    def trf_c_ubyte2byte(self,data_array):
        data = ''
        for i in range(len(data_array)):
            data += chr(data_array[i])
        return data

    def cbc(self,mode,data,key,iv):    #字节流
        ctx = sm4_context()
        type_ubyte_array_16 = c_ubyte * 16
        type_ubyte_array_data = c_ubyte * len(data)

        if mode == 1:
            self.sm4_setkey_enc.restype = None
            self.sm4_setkey_enc.argtypes = [POINTER(sm4_context),POINTER(c_ubyte)]
            key_array = type_ubyte_array_16()
            key_array = self.trf_byte2c_ubyte(key_array,key)
            self.sm4_setkey_enc(byref(ctx),key_array)
        else:
            self.sm4_setkey_dec.restype = None
            self.sm4_setkey_dec.argtypes = [POINTER(sm4_context),POINTER(c_ubyte)]
            key_array = type_ubyte_array_16()
            key_array = self.trf_byte2c_ubyte(key_array,key)
            self.sm4_setkey_dec(byref(ctx),key_array)

        self.sm4_cbc.restype = None
        self.sm4_cbc.argtypes = [POINTER(sm4_context),c_int,c_int,POINTER(c_ubyte),POINTER(c_ubyte),POINTER(c_ubyte)]
        iv_array = type_ubyte_array_16()
        iv_array = self.trf_byte2c_ubyte(iv_array,iv)
        in_array = type_ubyte_array_data()
        in_array = self.trf_byte2c_ubyte(in_array,data)
        out_array = type_ubyte_array_data()
        self.sm4_cbc(byref(ctx),mode,len(data),iv_array,in_array,out_array)
        return self.trf_c_ubyte2byte(out_array)

    def padding(self,nopadding , block_size):
        a = int(ceil(len(nopadding) * 1.0  / block_size))
        b = a*block_size - (len(nopadding))
        if b > 0:
            padding = nopadding + b'\x00' * (b-1) + struct.pack('!B',b-1)
        else:
            padding = nopadding + b'\x00' * (block_size-1) + struct.pack('!B',block_size-1)
        return padding

sm4 = sm4cbc()


class IkeError(Exception):
    pass


class IKE(object):
    """
    A single IKE negotiation / SA.

    Currently implements only Initiator side of the negotiation.
    """
    def __init__(self, address, peer,left,right):
        self.left = left
        self.right = right
        self.iSPI = 0
        self.rSPI = 0
        self.address = address
        self.peer = peer
        self.packets = list()
        self.symmetric = 128    #bits
        self.K = os.urandom(self.symmetric / 8)
        self.Nb = os.urandom(32)
        self.flags = const.IKE_HDR_FLAGS['N']
        self.exchange_type = const.ExchangeType.IKE_MAIN_MODE
        self.message_id = 0
        self.state = State.STARTING

    def set_state(self,state):
        self.state = state
    def set_iSPI(self):
        self.iSPI = struct.unpack('!Q',os.urandom(8))[0]
    def set_rSPI(self):
        self.rSPI = struct.unpack('!Q',os.urandom(8))[0]
    def set_ikeflags(self):
        self.flags = const.IKE_HDR_FLAGS['Y']
    def set_quick_messgeid(self,message_id = None):
        if message_id is None:
            self.message_id = struct.unpack('!L',os.urandom(4))[0]
        else:
            self.message_id = struct.unpack('!L',message_id)[0]
    def set_exchange_type(self):
        self.exchange_type = const.ExchangeType.IKE_QUIKE_MODE
    def set_nonce(self):
        self.Nb = os.urandom(32)
    def set_esp_SPIin(self,esp_SPIin):
        self.esp_SPIin = struct.pack('!L',esp_SPIin)

    def Hash_verify(self,hash_data,key,plain_text,state):
        if hash_data == hmac.new(key,plain_text,digestmod=sha1).digest():
            print state,'Hash verify successfully!'
        else:
            raise IkeError("Hash verify failed!")
        
    def send(self,pay):
        packet = Packet(iSPI=self.iSPI , rSPI=self.rSPI,flags = self.flags,exchange_type = self.exchange_type,message_id=self.message_id)
        for payload in pay:
            packet.add_payload(payload)
        self.packets.append(packet)
        return packet.__bytes__()
    
    def parse_packet(self, data):
        packet = Packet(data=data)
        packet.header = data[0:const.IKE_HEADER.size]
        (packet.iSPI, packet.rSPI, next_payload, packet.version, exchange_type, packet.flags,
         packet.message_id, packet.length) = const.IKE_HEADER.unpack(packet.header)
        packet.exchange_type = const.ExchangeType(exchange_type)

        self.iSPI = packet.iSPI
        self.rSPI = packet.rSPI
        self.message_id = packet.message_id
        self.exchange_type = packet.exchange_type
        self.flags = packet.flags

        data = data[const.IKE_HEADER.size:]

        while next_payload:
            logger.debug('Next payload: {0!r}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(data)))
            try:
                payload = payloads.get_by_type(next_payload,data)
            except KeyError as e:
                logger.error("Unidentified payload {}".format(e))
                payload = payloads._IkePayload(data=data)
            if payload._type == 6 and payload.next_payload != 6:
                self.peermodules = payload.pubmodules
                self.peerexponent = payload.pubexponent
                self.peercert = payload._data
            if payload._type == 10:
                self.Npeerb = payload._data
            if payload._type == 1:
                self.sapeer = payload._data
                self.sa = data[:const.PAYLOAD_HEADER.size] + payload._data
                if payload.spi:
                    self.esp_SPIout = payload.spi
            packet.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(packet.payloads))
            next_payload = payload.next_payload
            data = data[payload.length:]
        logger.debug("Packed parsed successfully")
        self.packets.append(packet)

class ike_initiator(IKE):
    def __init__(self,address, peer, qdata,left = None,right = None):
        super(ike_initiator, self).__init__(address, peer, left, right)
        self.q = Queue.Queue()
        for i in qdata:
            self.q.put(i)

    def init1(self):
        self.set_state(State.INIT1)
        self.set_iSPI()
        pay = list()
        pay.append(payloads.SA())
        return self.send(pay)
    
    def init3(self):
        self.set_state(State.INIT3)
        iv = b'\x00' * (self.symmetric / 8)
        address = self.address[0].split('.')

        #加密算法的使用
        idi_data = struct.pack('!B',int(address[0])) + struct.pack('!B',int(address[1])) + struct.pack('!B',int(address[2])) +struct.pack('!B',int(address[3]))
        #enN = AES128.encrypt(iv,self.K,AES128.padding(self.Nb,self.symmetric / 8))
        enN = sm4.cbc(1,sm4.padding(self.Nb,self.symmetric / 8),self.K,iv)
        #enIDI = AES128.encrypt(enN[-16:],self.K,AES128.padding(idi_data,self.symmetric / 8))
        enIDI = sm4.cbc(1,sm4.padding(idi_data,self.symmetric / 8),self.K,enN[-16:])
        K = RSA_tup(self.K,self.peermodules,self.peerexponent)

        pay = list()
        pay.append(payloads.Symmetric_key(K,next_payload=payloads.Type.Nonce))
        pay.append(payloads.Nonce(nonce = enN,next_payload=payloads.Type.ID))
        pay.append(payloads.ID(Idi_data = enIDI,next_payload=payloads.Type.CERT))
        pay.append(payloads.CERT(cert_data = open('../ca.der').read(),next_payload=payloads.Type.CERT))
        pay.append(payloads.CERT(cert_data = open('../server.der').read(),next_payload=payloads.Type.SIGNATURE))
        
        self.id_data = idi_data   ###
        message = self.K + self.Nb + self.id_data + binascii.a2b_hex("04") + open('../server.der').read()
        sig_data = RSA_sign(message,'../serverkey.pem','123456')
        pay.append(payloads.SIGNATURE(sig = sig_data))

        return self.send(pay)

    def init5(self):
        self.set_state(State.INIT5)
        packet = self.packets[0]
        t = 0
        while t < len(packet.payloads):
            payload = packet.payloads[t]
            if payload._type == 1:
                SAi_b = payload.__bytes__()[const.PAYLOAD_HEADER.size:]
            t += 1

        data = struct.pack('!Q',self.iSPI) + struct.pack('!Q',self.rSPI) + SAi_b + self.id_data
        hash_data = hmac.new(self.SKEYSEED, data, digestmod=sha1).digest()

        hashpayload = payloads.HASH(hash_data=hash_data)
        plain_text = hashpayload.__bytes__()
        padding = sm4.padding(plain_text,self.symmetric / 8)
        #padding = AES128.padding(plain_text,self.symmetric / 8)
        #Encrypted = AES128.encrypt(self.iven,self.SK_e,padding)
        Encrypted = sm4.cbc(1,padding,self.SK_e,self.iven)

        self.set_ikeflags()
        pay = list()
        pay.append(hashpayload)
        return self.send(pay)[:const.IKE_HEADER.size - 4] + struct.pack('!L',len(padding)+const.IKE_HEADER.size) + Encrypted

    def Key_cal(self):
        packet = self.packets[-1]
        iv = b'\x00' * (self.symmetric / 8)
        t = 0
        while t < len(packet.payloads):
            payload = packet.payloads[t]
            data = payload._data
            if payload._type == 128:
                Kpeer = RSA_cert(data,'../serverkey.pem',key = '123456',flag = False)
            if payload._type == 10:
                #tmp = AES128.decrypt(iv,Kpeer,data)
                tmp = sm4.cbc(0,data,Kpeer,iv)
                Npeer = tmp[0 : len(tmp) - (int(binascii.b2a_hex(tmp[len(tmp) - 1]),16) + 1)]
                iv = data[-16:]
            if payload._type == 5:
                #tmp = AES128.decrypt(iv,Kpeer,data[4:])
                tmp = sm4.cbc(0,data[4:],Kpeer,iv)
                id_data = tmp[0 : len(tmp) - (int(binascii.b2a_hex(tmp[len(tmp) - 1]),16) + 1)]
            if payload._type == 9:
                signature = data
            t += 1

        message = Kpeer + Npeer +  id_data + self.peercert
        if RSA_verify(message,self.peermodules,self.peerexponent,signature):
            print "Phase1 Signature verify successfully!"
        else:
            raise IkeError("Phase1 Signature verify failed!")
        
        key = self.Nb + Npeer
        sk = sha1(self.K + Kpeer).digest()[0:self.symmetric / 8]
        self.SKEYSEED , keymat = key_generator(sha1(key).digest(),struct.pack('!Q',self.iSPI) + struct.pack('!Q',self.rSPI))
        ( self.SK_d,
          self.SK_a,
          self.SK_e ) = unpack("20s20s16s", keymat[0:56])

        self.ivde = self.iven = sk
        self.idpeer = id_data

    def analysis(self,data):
        if int(binascii.b2a_hex(data[19]),16) == 1:
            if int(binascii.b2a_hex(data[18]),16) == 2:
                self.last_encrypted_block = data[const.IKE_HEADER.size:]
            #tmp = AES128.decrypt(self.ivde,self.SK_e,data[const.IKE_HEADER.size:])
            tmp = sm4.cbc(0,data[const.IKE_HEADER.size:],self.SK_e,self.ivde)
            self.ivde = data[-16:]

            data = data[:const.IKE_HEADER.size] + tmp
            self.parse_packet(data)

            hash_data = tmp[const.PAYLOAD_HEADER.size:struct.unpack('!H',tmp[2:4])[0]]
            if self.state == State.INIT5:
                self.Hash_verify(hash_data,self.SKEYSEED,struct.pack('!Q',self.rSPI) + struct.pack('!Q',self.iSPI) + self.sapeer + self.idpeer,'Phase1_6')
            elif self.state == State.QUICK1:
                self.Hash_verify(hash_data,self.SK_a,struct.pack('!L',self.message_id) + self.Nb + self.sa + self.Npeerb,'Phase2_2')
                print "adding outbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIout),self.address[0],self.peer[0])
                print "adding inbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIin),self.peer[0],self.address[0])
        else:
            self.parse_packet(data)

    def QUICKINIT(self):
        self.set_quick_messgeid()
        self.set_exchange_type()
        self.iven = self.ivde = sha1(self.last_encrypted_block + struct.pack('!L',self.message_id)).digest()[:self.symmetric/8]

    def QUICK1(self):
        self.QUICKINIT()
        self.set_nonce()
        self.set_state(State.QUICK1)
        sapayload = payloads.SA(proposals = [
            proposal.Proposal(None,1,const.ProtocolID.ESP , spi_len = 4,transforms = [
                (('HMAC_SHA','TUNNEL'),128,)
            ])
        ],next_payload=payloads.Type.Nonce)
        self.set_esp_SPIin(sapayload.spi)

        noncepayload = payloads.Nonce(nonce = self.Nb)
        data = struct.pack('!L',self.message_id) + self.Nb + sapayload.__bytes__()
        hash_data = hmac.new(self.SK_a, data, digestmod=sha1).digest()

        hashpayload = payloads.HASH(hash_data=hash_data,next_payload=payloads.Type.SA)
        plain_text = hashpayload.__bytes__() + sapayload.__bytes__() + noncepayload.__bytes__()
        #padding = AES128.padding(plain_text,self.symmetric / 8)
        padding = sm4.padding(plain_text,self.symmetric / 8)
        Encrypted = sm4.cbc(1,padding,self.SK_e,self.iven)
        #Encrypted = AES128.encrypt(self.iven,self.SK_e,padding)
        self.iven = Encrypted[-16:]

        pay = list()
        pay.append(hashpayload)
        pay.append(sapayload)
        pay.append(noncepayload)
        return self.send(pay)[:const.IKE_HEADER.size - 4] + struct.pack('!L',len(padding)+const.IKE_HEADER.size) + Encrypted
    
    def QUICK3(self):
        data = struct.pack('!L',self.message_id) + self.Nb + self.Npeerb
        hash_data = hmac.new(self.SK_a, data, digestmod=sha1).digest()

        hashpayload = payloads.HASH(hash_data=hash_data)
        #padding = AES128.padding(hashpayload.__bytes__(),self.symmetric / 8)
        padding = sm4.padding(hashpayload.__bytes__(),self.symmetric / 8)
        #Encrypted = AES128.encrypt(self.iven,self.SK_e,padding)
        Encrypted = sm4.cbc(1,padding,self.SK_e,self.iven)
        self.iven = Encrypted[-16:]

        pay = list()
        pay.append(hashpayload)
        return self.send(pay)[:const.IKE_HEADER.size - 4] + struct.pack('!L',len(padding)+const.IKE_HEADER.size) + Encrypted

class ike_responder(IKE):
    def __init__(self,address, peer, qdata,left = None,right = None):
        super(ike_responder, self).__init__(address, peer, left, right)
        self.q = Queue.Queue()
        self.quick_flag = True
        for i in qdata:
            self.q.put(i)

    def init2(self):
        self.set_rSPI()
        pay = list()
        pay.append(payloads.SA(proposals = [
            proposal.Proposal(None,1,const.ProtocolID.IKE , transforms = [
                (('SM1','SHA','CERT'),1,)
            ])
        ]))
        pay.append(payloads.CERT(cert_data = open('../ca.der').read()))
        pay.append(payloads.CERT(cert_data = open('../server.der').read()))

        return self.send(pay)
    
    def init4(self):
        self.set_state(State.INIT4)
        iv = b'\x00' * (self.symmetric / 8)
        address = self.address[0].split('.')

        #加密算法的使用
        idr_data = struct.pack('!B',int(address[0])) + struct.pack('!B',int(address[1])) + struct.pack('!B',int(address[2])) +struct.pack('!B',int(address[3]))
        #enN = AES128.encrypt(iv,self.K,AES128.padding(self.Nb,self.symmetric / 8))
        enN = sm4.cbc(1,sm4.padding(self.Nb,self.symmetric / 8),self.K,iv)
        enIDI = sm4.cbc(1,sm4.padding(idr_data,self.symmetric / 8),self.K,enN[-16:])
        #enIDI = AES128.encrypt(enN[-16:],self.K,AES128.padding(idr_data,self.symmetric / 8))
        K = RSA_tup(self.K,self.peermodules,self.peerexponent)

        pay = list()
        pay.append(payloads.Symmetric_key(K))
        pay.append(payloads.Nonce(nonce = enN))
        pay.append(payloads.ID(Idi_data = enIDI))
        
        self.id_data = idr_data
        message = self.K + self.Nb + self.id_data + binascii.a2b_hex("04") + open('../server.der').read()
        sig_data = RSA_sign(message,'../serverkey.pem','123456')
        pay.append(payloads.SIGNATURE(sig = sig_data))

        return self.send(pay)

    def init6(self):
        self.set_state(State.INIT6)
        packet = self.packets[1]
        t = 0
        while t < len(packet.payloads):
            payload = packet.payloads[t]
            if payload._type == 1:
                SAr_b = payload.__bytes__()[const.PAYLOAD_HEADER.size:]
            t += 1

        data = struct.pack('!Q',self.rSPI) + struct.pack('!Q',self.iSPI) + SAr_b + self.id_data
        hash_data = hmac.new(self.SKEYSEED, data, digestmod=sha1).digest()
        
        hashpayload = payloads.HASH(hash_data=hash_data)
        plain_text = hashpayload.__bytes__()
        #padding = AES128.padding(plain_text,self.symmetric / 8)
        padding = sm4.padding(plain_text,self.symmetric / 8)
        #Encrypted = AES128.encrypt(self.iven,self.SK_e,padding)
        Encrypted = sm4.cbc(1,padding,self.SK_e,self.iven)
        self.last_encrypted_block = Encrypted

        self.set_ikeflags()
        pay = list()
        pay.append(hashpayload)
        return self.send(pay)[:const.IKE_HEADER.size - 4] + struct.pack('!L',len(padding)+const.IKE_HEADER.size) + Encrypted
    
    def Key_cal(self):
        packet = self.packets[-1]
        iv = b'\x00' * (self.symmetric / 8)
        t = 0
        while t < len(packet.payloads):
            payload = packet.payloads[t]
            data = payload._data
            if payload._type == 128:
                Kpeer = RSA_cert(data,'../serverkey.pem',key = '123456',flag = False)
            if payload._type == 10:
                #tmp = AES128.decrypt(iv,Kpeer,data)
                tmp = sm4.cbc(0,data,Kpeer,iv)
                Npeer = tmp[0 : len(tmp) - (int(binascii.b2a_hex(tmp[len(tmp) - 1]),16) + 1)]
                iv = data[-16:]
            if payload._type == 5:
                #tmp = AES128.decrypt(iv,Kpeer,data[4:])
                tmp = sm4.cbc(0,data[4:],Kpeer,iv)
                id_data = tmp[0 : len(tmp) - (int(binascii.b2a_hex(tmp[len(tmp) - 1]),16) + 1)]
            if payload._type == 9:
                signature = data
            t += 1

        message = Kpeer + Npeer + id_data + self.peercert
        if RSA_verify(message,self.peermodules,self.peerexponent,signature):
            print "Phase1 Signature verify successfully!"
        else:
            raise IkeError("Phase1 Signature verify failed!")
        
        key = Npeer + self.Nb
        sk = sha1(Kpeer + self.K).digest()[0:self.symmetric / 8]
        self.SKEYSEED , keymat = key_generator(sha1(key).digest(),struct.pack('!Q',self.iSPI) + struct.pack('!Q',self.rSPI))
        ( self.SK_d,
          self.SK_a,
          self.SK_e ) = unpack("20s20s16s", keymat[0:56])

        self.ivde = self.iven = sk
        self.idpeer = id_data

        return self.init4()

    def analysis(self,data):
        if int(binascii.b2a_hex(data[19]),16) == 1:
            if int(binascii.b2a_hex(data[18]),16) == 32 and self.quick_flag:
                self.QUICKINIT(data)
                self.quick_flag = False
            #tmp = AES128.decrypt(self.ivde,self.SK_e,data[const.IKE_HEADER.size:])
            tmp = sm4.cbc(0,data[const.IKE_HEADER.size:],self.SK_e,self.ivde)
            self.ivde = data[-16:]

            data = data[:const.IKE_HEADER.size] + tmp
            self.parse_packet(data)

            hash_data = tmp[const.PAYLOAD_HEADER.size:struct.unpack('!H',tmp[2:4])[0]]
            if self.state == State.INIT4:
                self.Hash_verify(hash_data,self.SKEYSEED,struct.pack('!Q',self.iSPI) + struct.pack('!Q',self.rSPI) + self.sapeer + self.idpeer,'Phase1_5')
            elif self.state == State.INIT6:
                self.Hash_verify(hash_data,self.SK_a,struct.pack('!L',self.message_id) + self.Npeerb + self.sa,'Phase2_1')
            elif self.state == State.QUICK2:
                self.Hash_verify(hash_data,self.SK_a,struct.pack('!L',self.message_id) + self.Npeerb + self.Nb,'Phase2_3')
                print "adding outbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIout),self.address[0],self.peer[0])
                print "adding inbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIin),self.peer[0],self.address[0])
        else:
            self.parse_packet(data)
    
    def QUICKINIT(self,data):
        message_id = data[20:24]
        self.set_quick_messgeid(message_id)
        self.iven = self.ivde = sha1(self.last_encrypted_block + struct.pack('!L',self.message_id)).digest()[:self.symmetric/8]

    def QUICK2(self):
        self.set_nonce()
        self.set_state(State.QUICK2)
        sapayload = payloads.SA(proposals = [
            proposal.Proposal(None,1,const.ProtocolID.ESP , spi_len = 4,transforms = [
                (('HMAC_SHA','TUNNEL'),128,)
            ])
        ],next_payload=payloads.Type.Nonce)
        self.set_esp_SPIin(sapayload.spi)

        noncepayload = payloads.Nonce(nonce = self.Nb)
        data = struct.pack('!L',self.message_id) + self.Npeerb + sapayload.__bytes__() + self.Nb
        hash_data = hmac.new(self.SK_a, data, digestmod=sha1).digest()

        hashpayload = payloads.HASH(hash_data=hash_data,next_payload=payloads.Type.SA)
        plain_text = hashpayload.__bytes__() + sapayload.__bytes__() + noncepayload.__bytes__()
        #padding = AES128.padding(plain_text,self.symmetric / 8)
        padding = sm4.padding(plain_text,self.symmetric / 8)
        #Encrypted = AES128.encrypt(self.iven,self.SK_e,padding)
        Encrypted = sm4.cbc(1,padding,self.SK_e,self.iven)
        self.iven = Encrypted[-16:]

        pay = list()
        pay.append(hashpayload)
        pay.append(sapayload)
        pay.append(noncepayload)
        return self.send(pay)[:const.IKE_HEADER.size - 4] + struct.pack('!L',len(padding)+const.IKE_HEADER.size) + Encrypted
    
    def install_ipsec_sas(self,flag = True):
        
        print "Ipsec Vpn established successfully!"
        if flag:
            keymat = prfplus(self.SK_d, self.N + self.Nr)
        else:
            keymat = prfplus(self.SK_d, self.Ni + self.N)

        ( self.esp_ei,
          self.esp_ai,
          self.esp_er,
          self.esp_ar ) = unpack("16s20s16s20s", keymat[0:72])

        if flag:
            outbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIout),
                                key_e=binascii.b2a_hex(self.esp_ei),
                                key_a=binascii.b2a_hex(self.esp_ai),
                                ip_from=self.address[0],
                                ip_to=self.peer[0])
            inbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIin),
                                key_e=binascii.b2a_hex(self.esp_er),
                                key_a=binascii.b2a_hex(self.esp_ar),
                                ip_to=self.address[0],
                                ip_from=self.peer[0])
        else:
            outbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIout),
                                key_e=binascii.b2a_hex(self.esp_er),
                                key_a=binascii.b2a_hex(self.esp_ar),
                                ip_from=self.address[0],
                                ip_to=self.peer[0])
            inbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIin),
                                key_e=binascii.b2a_hex(self.esp_ei),
                                key_a=binascii.b2a_hex(self.esp_ai),
                                ip_to=self.address[0],
                                ip_from=self.peer[0])
        setkey_input = "flush;\nspdflush;\n{0}\n{1}\n{2}\n".format(
            ESP_ADD_SYNTAX.format( **outbound_params),
            ESP_ADD_SYNTAX.format( **inbound_params),
            SPDADD_SYNTAX.format(mysubip=self.left[0], peersubip=self.right[0],myip=self.address[0],peerip=self.peer[0]))
        print "adding outbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIout),self.address[0],self.peer[0])
        print "adding inbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIin),self.peer[0],self.address[0])
        
        file = open('/home/sjx/桌面/ipsec.conf','w')
        file.write(setkey_input)
        file.close()
        
        if os.system('setkey -f /home/sjx/桌面/ipsec.conf') == 0:
            print 'ESP established successfully'


class Packet(object):
    """
    An IKE packet.

    To generate packets:

    #. instantiate an Packet()
    #. add payloads by Packet.add_payload(<payloads.IkePayload instance>)
    #. send bytes(Packet) to other peer.

    Received packets should be generated by IKE.parse_packet().
    """
    def __init__(self, data=None, exchange_type=None, message_id=0, iSPI=0, rSPI=0,flags = const.IKE_HDR_FLAGS['N']):
        self.payloads = list()
        self.iSPI = iSPI
        self.rSPI = rSPI
        self.message_id = message_id
        self.exchange_type = exchange_type
        self.flags = flags

    def add_payload(self, payload):
        """
        Adds a payload to packet, updating last payload's next_payload field
        """
        if self.payloads:
            self.payloads[-1].next_payload = payload._type
        self.payloads.append(payload)

    def __bytes__(self):
        data = reduce(operator.add, (x.__bytes__() for x in self.payloads))
        length = len(data) + const.IKE_HEADER.size
        header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            const.IKE_VERSION,
            self.exchange_type,
            self.flags,
            self.message_id,
            length
        ))
        return bytes(header + data)





