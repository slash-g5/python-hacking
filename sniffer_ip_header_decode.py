import ipaddress
import os
import socket
import struct
import sys

HOST = '192.168.0.103'


class IP:
    def __init__(self, buff=None):
        header = struct.unpack("<BBHHHBBH4s4s", buff)
        self.ver = header[0] >> 4
        self.hdrlen = header[0] & 0xF
