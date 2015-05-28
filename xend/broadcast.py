
import socket
import sys


class BroadCastClient:

    def __init__(self, port=12345):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self.dst = ('<broadcast>', port)
    
    def send(self, msg):
        self.s.sendto(msg, self.dst)

        

class BroadCastServer:

    def __init__(self, port=12345):

        self.port = port
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.s.bind(('',self.port))

    def listen(self):
        print "Listening on the port : " + str(self.port)

        while True:
            try:
                sock,addr = self.s.recvfrom(8192)
                print "Receive data from %s : %s" % (addr, sock)
            except:
                print "Error"
                break
                
