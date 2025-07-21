import struct
import socket

class IP_Packet():
    def __init__(self, raw_bytes):
        self.raw = raw_bytes
        self._parse()
    
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

        self.tos, self.total_length, self.identification, self.flags_and_fragment_offset, self.ttl, self.protocol, self.header_checksum =  header_tuple[1], header_tuple[2],header_tuple[3],header_tuple[4],header_tuple[5],header_tuple[6], header_tuple[7]

        self.src_ip = socket.inet_ntoa(header_tuple[8])
        self.rcv_ip = socket.inet_ntoa(header_tuple[9])

        self.payload = self.raw[self.header_length:]

    def __str__(self):
        return (
            f"IP Packet:\n"
            f"  From: {self.src_ip} -> To: {self.rcv_ip}\n"
            f"  Protocol: {self.protocol}  TTL: {self.ttl}\n"
            f"  Header Length: {self.header_length} bytes  Total Length: {self.total_length} bytes"
            f"  Checksum: {self.header_checksum}"
        )