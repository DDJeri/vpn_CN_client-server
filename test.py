# -*- coding: utf-8 -*-

import protocol
import payloads
from binascii import b2a_hex,a2b_hex
import socket
from Crypto.Util.number import long_to_bytes, bytes_to_long


local = ('192.168.102.137',500)
peer = ('192.167.102.119',500)

local_subnet = ('192.168.137.0','192.168.137.255')
peer_subnet = ('192.168.136.0','192.168.136.255')

UDPSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
UDPSock.bind(('',500))
ike = protocol.IKE(local,local_subnet,peer_subnet,peer)

print 'i:initiator r:responder'
if raw_input() == 'i':
    q =(protocol.State.INIT1,
        protocol.State.RECEIVING,
        protocol.State.INIT3,
        protocol.State.RECEIVING,
        protocol.State.PHASE1_KEY_CAL,
        protocol.State.INIT5,
        protocol.State.RECEIVING,
        protocol.State.QUICK1,
        protocol.State.RECEIVING,
        protocol.State.QUICK3)
    ike = protocol.ike_initiator(local,peer,q,local_subnet,peer_subnet)
else:
    q =(protocol.State.RECEIVING,
        protocol.State.INIT2,
        protocol.State.RECEIVING,
        protocol.State.PHASE1_KEY_CAL,
        protocol.State.INIT4,
        protocol.State.RECEIVING,
        protocol.State.INIT6,
        protocol.State.RECEIVING,
        protocol.State.QUICK2,
        protocol.State.RECEIVING)
    ike = protocol.ike_responder(local,peer,q,local_subnet,peer_subnet)

while not ike.q.empty():
    state = ike.q.get()

    if state == protocol.State.INIT1:
        UDPSock.sendto(ike.init1(),peer)
    elif state == protocol.State.INIT2:
        UDPSock.sendto(ike.init2(),peer)
    elif state == protocol.State.INIT3:
        UDPSock.sendto(ike.init3(),peer)
    elif state == protocol.State.INIT4:
        UDPSock.sendto(ike.init4(),peer)
    elif state == protocol.State.INIT5:
        UDPSock.sendto(ike.init5(),peer)
    elif state == protocol.State.INIT6:
        UDPSock.sendto(ike.init6(),peer)
    elif state == protocol.State.QUICKINIT:
        ike.QUICKINIT()
    elif state == protocol.State.QUICK1:
        UDPSock.sendto(ike.QUICK1(),peer)
    elif state == protocol.State.QUICK2:
        UDPSock.sendto(ike.QUICK2(),peer)
    elif state == protocol.State.QUICK3:
        UDPSock.sendto(ike.QUICK3(),peer)
    elif state == protocol.State.PHASE1_KEY_CAL:
        ike.Key_cal()
    else:
        data,address = UDPSock.recvfrom(2048)
        if address != peer:
            raise Exception("Disabled") 
        else: 
            ike.analysis(data)

