# -*- coding: utf-8 -*-

import protocol
import payloads
from binascii import b2a_hex,a2b_hex
import socket
import threading
import os

local = ('192.168.102.119',500)
local_subnet = ('192.168.136.0','192.168.136.255')

peer_subnet_pool = {('192.168.102.137',500):('192.168.137.0','192.168.137.255'),
                    ('192.167.135.1',500):('192.168.134.0','192.168.134.255')}

print "国密VPN START!"

UDPSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
UDPSock.bind(('',500))

q = (protocol.State.INIT2,
     protocol.State.PHASE1_KEY_CAL,
     protocol.State.INIT6,
     protocol.State.QUICK2)

mutex = threading.Lock()
client_pool = {}
client_current = []   

def Calculate_and_Send():
    global mutex , client_current , client_pool
    while True:
        if mutex.acquire():
            if len(client_current):
                address , data = client_current.pop(0)
                peer_sub = peer_subnet_pool[address]
                if address not in client_pool:
                    ike = protocol.ike_responder(local,address,q,local_subnet,peer_sub)
                    client_pool[address] = ike
                else:
                    ike = client_pool[address]
                ike.analysis(data)
                
                if not ike.q.empty():
                    state = ike.q.get()
                    if state == protocol.State.INIT2:
                        UDPSock.sendto(ike.init2(),address)
                    elif state == protocol.State.INIT6:
                        UDPSock.sendto(ike.init6(),address)
                    elif state == protocol.State.QUICK2:
                        UDPSock.sendto(ike.QUICK2(),address)
                    elif state == protocol.State.PHASE1_KEY_CAL:
                        UDPSock.sendto(ike.Key_cal(),address)

            mutex.release()

def Receive():
    global mutex , client_current
    while True:
        data,address = UDPSock.recvfrom(2048)
        if mutex.acquire():
            client_current.append((address,data))
            mutex.release()

if __name__ == "__main__":
    os.system('setkey -D -F')
    os.system('setkey -P -F')
    send_msg_thread = threading.Thread(target=Calculate_and_Send)
    send_msg_thread.start()
    Receive()

