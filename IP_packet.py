import struct
import socket
import random
IP_PROTOCOL_TCP = 6
from utils import checksum_calc

class IP_Packet():
    def __init__(self, raw_bytes=None):
        if raw_bytes:
            self.raw = raw_bytes
            self._parse()
        else:
            self.version = 4
            self.ihl = 5
            self.tos = 0
            self.total_length = 0
            self.id = random.randint(0, 65535)
            self.flags = 0
            self.frag_offset = 0
            self.ttl = 64
            self.protocol = IP_PROTOCOL_TCP
            self.checksum = 0
            self.src_ip = ""
            self.rcv_ip = ""
            self.payload = b''

    
    def _parse(self):
        # !       - Network byte order (big-endian)
        # B       - Unsigned char (1 byte)
        # H       - Unsigned short (2 bytes)
        # s       - Bytes (string)
        # 4s      - 4-byte string

        header_format = "!BBHHHBBH4s4s" #std
        header_size = struct.calcsize(header_format)

        header_tuple = struct.unpack(header_format, self.raw[:header_size])

        version_ihl = header_tuple[0]
        self.version = version_ihl >> 4 # first 4 bits

        # pings from kernel
        if self.version != 4:
            raise ValueError(f"Not ipv4: version is {self.version}")

        self.ihl = version_ihl & 0x0F    #he last 4 bits
        self.header_length = self.ihl * 4    # IHL is in 4-byte words
        self.protocol = header_tuple[6]
        self.src_ip = socket.inet_ntoa(header_tuple[8])
        self.rcv_ip = socket.inet_ntoa(header_tuple[9])
        self.payload = self.raw[self.header_length:]

    
    def _build(self):
        self.total_length = (self.ihl * 4) + len(self.payload)

        header = struct.pack(
            '!BBHHHBBH4s4s',
            (self.version << 4) | self.ihl,
            self.tos,
            self.total_length,
            self.id,
            (self.flags << 13) | self.frag_offset,
            self.ttl,
            self.protocol,
            0, # Checksum temporarily zero
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.rcv_ip)
        )

        self.checksum = checksum_calc(header)

        header = struct.pack(
            '!BBHHHBBH4s4s',
            (self.version << 4) | self.ihl,
            self.tos,
            self.total_length,
            self.id,
            (self.flags << 13) | self.frag_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.rcv_ip)
        )

        return header + self.payload

    def __str__(self):
        return f"IP Packet: {self.src_ip} -> {self.rcv_ip} (Proto: {self.protocol})"