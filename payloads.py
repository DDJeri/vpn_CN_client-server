# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#
"""
IKEv2 Payloads as specified in RFC 5996 sections 3.2 - 3.16
"""
from enum import IntEnum
from functools import reduce
import ipaddress
import logging
import operator
import os
import struct
import binascii
from hashlib import sha1
from Crypto.Util.number import long_to_bytes, bytes_to_long

import const
from proposal import Proposal
from auth import priv_sign
from binascii import b2a_hex,a2b_hex


PRIVATE_KEY_PEM = 'tests/private_key.pem'

__author__ = 'kimvais'

logger = logging.getLogger(__name__)


class Type(IntEnum):
    """
    Payload types from `IANA <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2>`_
    """
    no_next_payload = 0
    SA = 1
    ID = 5
    CERT = 6
    HASH = 8
    SIGNATURE = 9
    Nonce = 10
    Notify = 11
    Symmetric_key = 128

    def __repr__(self, *args, **kwargs):
        return '<{}: {}>'.format(self.name, self.value)


class _IkePayload(object):
    """
    Generic payload header `RFC5996 Section 3.2 <https://tools.ietf.org/html/rfc5996#section-3.2>`_
    """
    _type = None

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False):
        if data is not None:
            next_payload, self.flags, self.length = const.PAYLOAD_HEADER.unpack(
                data[:const.PAYLOAD_HEADER.size])
            self.next_payload = Type(next_payload)
            self._data = data[const.PAYLOAD_HEADER.size:self.length]
        else:
            self.next_payload = next_payload
            self.length = 0
            self._data = bytearray()
            if critical:
                self.flags = 0b10000000
            else:
                self.flags = 0

    @property
    def header(self):
        return bytearray(const.PAYLOAD_HEADER.pack(self.next_payload,
                                                   self.flags,
                                                   self.length))

    def __bytes__(self):
        return bytes(self.header + self._data)

    def __unicode__(self):
        return "IKE Payload {0!r} [{1}]".format(self._type,
                                              self.length)

    def __repr__(self):
        return '<{0}>'.format(self.__unicode__(), hex(id(self)))

    def parse(self, data):
        self._data = data


class SA(_IkePayload):
    """
    `Security Association Payload <https://tools.ietf.org/html/rfc5996#section-3.3>`_
    """
    def __init__(self, data=None, proposals=None, next_payload=Type.no_next_payload,
                 critical=False):
        super(SA, self).__init__(data, next_payload, critical)
        self._type = 1
        if data is not None:
            self.parse(self._data)
        elif proposals is None:
            self.proposals = [
                Proposal(None, 1, const.ProtocolID.IKE, transforms=[
                    (('SM1','SM3','CERT'),1,),
                    (('SM1','SHA','CERT'),1,2)
                ])
            ]
            self.spi = self.proposals[0].spi
        else:
            self.proposals = proposals
            self.spi = self.proposals[0].spi

    def __bytes__(self):
        ret = list()
        self.proposals[-1].last = True
        ret.extend(proposal.data for proposal in self.proposals)
        self.length = 4 + 4 + 4 + sum((len(x) for x in ret))
        ret.insert(0, self.header)
        ret.insert(1,struct.pack("!L",1))
        ret.insert(2,struct.pack("!L",1))
        return bytes(reduce(operator.add, ret))

    def parse(self, data):
        self.proposals = list()
        last = False
        self.spi = None
        data = data[8:len(data)]
        while not last:
            proposal = Proposal(data)
            if proposal.spi:
                logger.debug("Setting SPI to: {}".format(proposal.spi))
                self.spi = proposal.spi
            self.proposals.append(proposal)
            last = proposal.last
            data = data[proposal.len:]
        logger.debug("got {} proposals".format(len(self.proposals)))


class Nonce(_IkePayload):
    """
    `Nonce Payload <https://tools.ietf.org/html/rfc5996#section-3.9>`_
    """
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False,
                 nonce=None):
        super(Nonce, self).__init__(data, next_payload, critical)
        self._type = 10
        if data is not None:
            self.parse(data)
        else:
            if nonce:
                self._data = nonce
            else:
                self._data = os.urandom(32)
            self.length = const.PAYLOAD_HEADER.size + len(self._data)

    def __bytes__(self):
        return bytes(self.header + self._data)

class SIGNATURE(_IkePayload):
    def __init__(self,sig = None,data = None,next_payload=Type.no_next_payload,critical=False):
        super(SIGNATURE, self).__init__(data, next_payload, critical)
        self._type = 9
        if data is not None:
            self.parse(data)
        else:
            self._data = sig
            self.length = const.PAYLOAD_HEADER.size + len(self._data)
            
    def __bytes__(self):
        return bytes(self.header + self._data)
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

class HASH(_IkePayload):
    def __init__(self,hash_data = None,data = None,next_payload=Type.no_next_payload,critical=False):
        super(HASH, self).__init__(data, next_payload, critical)
        self._type = 8
        if data is not None:
            self.parse(data)
        else:
            self._data = hash_data
            self.length = const.PAYLOAD_HEADER.size + len(self._data)
    
    def __bytes__(self):
        return bytes(self.header + self._data)
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]


class Symmetric_key(_IkePayload):
    def __init__(self,key = None,data = None,next_payload=Type.no_next_payload,critical=False):
        super(Symmetric_key, self).__init__(data, next_payload, critical)
        self._type = 128
        if data is not None:
            self.parse(data)
        else:
            self._data = key
            self.length = const.PAYLOAD_HEADER.size + len(self._data)
    
    def __bytes__(self):
        return bytes(self.header + self._data)
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

class Notify(_IkePayload):
    """
    `Notify Payload <https://tools.ietf.org/html/rfc5996#section-3.10>`_
    """
    def __init__(self, data=None, next_payload=Type.no_next_payload, protocol_id = 0,critical=False,notify_type = None,notify_data = None,spi_data = 0):
        # TODO; Implement generation of notifications with data
        #assert notify_type or data
        super(Notify, self).__init__(data, next_payload, critical)
        self._type = 41
        if notify_type:
            self._data = struct.pack('!L2BH', 0, protocol_id, spi_data, notify_type)
            self.length = 8
            if notify_type == const.MessageType.NAT_DETECTION_SOURCE_IP or notify_type == const.MessageType.NAT_DETECTION_DESTINATION_IP:
               spi = notify_data[:16]
               address = notify_data[16:len(notify_data)]
               address = address.split('.')
               address = struct.pack('!4B',int(address[0]),int(address[1]),int(address[2]),int(address[3]))
               hash_data = spi + address + struct.pack('!H',500)
               hashinfo = sha1(hash_data).hexdigest()
               self._data += a2b_hex(hashinfo)
               self.length += len(a2b_hex(hashinfo))
            if notify_type == const.MessageType.SIGNATURE_HASH_ALGORITHMS:
                self._data += notify_data
                self.length += len(notify_data)

        if data is not None:
            self.parse(self._data)
    
    def __bytes__(self):
        return bytes(self.header + self._data)

    def parse(self, data):
        #self._data = data[4:self.length]
        self.protocol_id, self.spi_size, message_type = struct.unpack(
            '!2BH', data[:4])
        if self.spi_size != 0:
            self.spi = data[4:4 + self.spi_size]
        else:
            self.spi = 0
        self.message_type = const.MessageType(message_type)
        if self.message_type < 2 ** 14:
            self.level = logging.ERROR
        else:
            self.level = logging.INFO
        #logger.log(self.level, self.__unicode__())
        self.notification_data = data[4 + self.spi_size:self.length]

    def __unicode__(self):
        if self.protocol_id:
            return '<Notify payload for {0}: {1!r} (spi {2} [{3}]) [{4}]>'.format(
                const.ProtocolID(self.protocol_id),
                self.message_type, binascii.hexlify(self.spi),
                self.spi_size, self.length)
        else:
            return '<Notify payload {0!r} [{1}]>'.format(self.message_type, self.length)

class CERT(_IkePayload):
    def __init__(self,cert_data = None,data=None, next_payload=Type.no_next_payload, critical=False):
        super(CERT,self).__init__(data, next_payload, critical)
        self._type = 6
        if data is None:
            self._data = a2b_hex("04") + cert_data
            self.length = 4 + 1 + len(cert_data)
        else:
            self.parse(data)
        
    def __bytes__(self):
        return bytes(self.header + self._data)
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]
        data = self._data
        pubstart = data.find(a2b_hex("028181"))
        if data[pubstart + 3 + 129 : pubstart + 3 + 129 + 2] != a2b_hex("0203"):
            raise AssertionError("Search Failed")
        else:
            pubmodules = data[pubstart + 3 : pubstart + 3 + 129]
            pubexponent = data[pubstart + 3 + 129 + 2 : pubstart + 3 + 129 + 2 + 3]
            self.pubmodules = bytes_to_long(pubmodules)
            self.pubexponent = bytes_to_long(pubexponent)



class ID(_IkePayload):
    """
    `Identification Payload <https://tools.ietf.org/html/rfc5996#section-3.5>`_ for initiator
    """
    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False, Idi_data = None):
        super(ID,self).__init__(data, next_payload, critical)
        self._type = 5
        if data is None:
            if Idi_data:
                self.length = 8 + len(Idi_data)
                self._data = struct.pack("!B3x", 1) + Idi_data  # Ipv4 + reserved
        else:
            self.parse(data)

    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]
    def __bytes__(self):
        return bytes(self.header + self._data)

class AUTH(_IkePayload):
    """
    `Authentication Payload <https://tools.ietf.org/html/rfc5996#section-3.8>`_
    """
    def __init__(self, signed_octets=None, length = None,data=None, next_payload=Type.no_next_payload, critical=False):
        #assert signed_octets or data
        super(AUTH,self).__init__(data, next_payload, critical)
        self._type = 39
        if signed_octets:
            # Generate auth payload

            # authentication_type = const.AuthenticationType.PSK
            authentication_type = const.AuthenticationType.RESERVED_TO_IANA

            if authentication_type == const.AuthenticationType.PSK:
                PSK = b"foo"
                authentication_data = prf(prf(PSK, b"Key Pad for IKEv2"), signed_octets)[:const.AUTH_MAC_SIZE]
            elif authentication_type == const.AuthenticationType.RESERVED_TO_IANA:
                # XXX: StrongSwan can not verify SHA-256 signature, so we have to use SHA-1
                #authentication_data = pubkey.sign(signed_octets, PRIVATE_KEY_PEM, hash_alg='SHA-256')
                authentication_data,a= priv_sign(signed_octets,length)                #########测试
            else:
                authentication_data = b''
                raise AssertionError("Unsupported authentication method")
            self.length = 8 + 16 + len(authentication_data)
            self._data = struct.pack(const.AUTH_HEADER, authentication_type) + a2b_hex("0f300d06092a864886f70d01010b0500") + authentication_data

    def __bytes__(self):
        return bytes(self.header + self._data)

class SK(_IkePayload):
    """
    `Encrypted Payload <https://tools.ietf.org/html/rfc5996#section-3.14>`_
    """
    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False, iv=None, ciphertext=None):
        assert data or (iv and ciphertext)
        super(SK,self).__init__(data, next_payload, critical)
        self._type = 46
        if not data:
            self.iv = iv
            self.ciphertext = ciphertext
            self.length = len(iv) + len(ciphertext) + const.PAYLOAD_HEADER.size + 16 # MACLEN
            self._data = self.iv + self.ciphertext + b'\x00' * 16

    def mac(self, hmac):
        self._data = self._data[:-16] + hmac
    
    def __bytes__(self):
        return bytes(self.header + self._data)


# Register payloads in order to be used for get_by_type()
_payload_classes = _IkePayload.__subclasses__()
_payload_map = {x.__name__: x for x in _payload_classes if not x.__name__.startswith('_')}


def get_by_type(payload_type,data):
    """
    Returns an IkePayload (sub)class based on the RFC5996 payload_type
    :param payload_type: int() Ike Payload type
    """
    return _payload_map[Type(payload_type).name](data = data)

