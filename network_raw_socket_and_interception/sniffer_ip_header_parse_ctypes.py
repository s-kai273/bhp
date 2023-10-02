from ctypes import *
import socket
import struct
import sys
import os


class IP(Structure):

    _fields_ = [
        ("ihl",             c_ubyte,     4),
        ("ver",             c_ubyte,     4),
        ("tos",             c_ubyte,     8),
        ("len",             c_ushort,   16),
        ("id",              c_ushort,   16),
        ("offset",          c_ushort,   16),
        ("ttl",             c_ubyte,     8),
        ("protocol_num",    c_ubyte,     8),
        ("sum",             c_ushort,   16),
        ("src",             c_uint32,   32),
        ("dst",             c_uint32,   32),
    ]

    def __new__(cls, socket_buffer = None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer = None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        self.protocl_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocl_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET,
                            socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    try:
        while True:
             raw_buffer = sniffer.recvfrom(65535)[0]
             ip_header = IP(raw_buffer[0:20])
             print('Protocol: %s %s -> %s' % (ip_header.protocol, 
                ip_header.src_address, ip_header.dst_address))
             print(ip_header.ver)
             print(ip_header.ihl)
             print(ip_header.tos)
             print(ip_header.len)
             print(ip_header.id)
             print(ip_header.offset)
             print(ip_header.ttl)
             print(ip_header.protocol_num)
             print(ip_header.sum)
             print(ip_header.src)
             print(ip_header.dst)
             
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.203'
    sniff(host)
