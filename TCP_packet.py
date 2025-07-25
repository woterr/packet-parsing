import struct
import socket
from utils import checksum_calc
IP_PROTOCOL_TCP = 6

class TCP_Packet():
    def __init__(self, raw_bytes=None):
        if raw_bytes:
            self.raw = raw_bytes
            self._parse()
        else:
            # Fields for building
            self.src_port = 0
            self.rcv_port = 0
            self.seq_num = 0
            self.ack_num = 0
            self.data_offset = 5 # 5 * 4 = 20 bytes
            self.flag_urg = 0
            self.flag_ack = 0
            self.flag_psh = 0
            self.flag_rst = 0
            self.flag_syn = 0
            self.flag_fin = 0
            self.window_size = 65535
            self.checksum = 0 # Will be calculated
            self.urgent_pointer = 0
            self.payload = b''

    def _parse(self):

        # the format string for a standard 20-byte TCP header.
        # H = Unsigned Short (2 bytes), I = Unsigned Int (4 bytes)
        
        header_format = '!HHIIBBHHH'
        header_size = struct.calcsize(header_format)
        header_tuple = struct.unpack(header_format, self.raw[:header_size])
        self.src_port, self.rcv_port, self.seq_num, self.ack_num = header_tuple[0:4]

        offset_and_flags = header_tuple[4]
        self.data_offset = offset_and_flags >> 4
        flags_field = header_tuple[5]

        # look for flags 
        # NOTE: the `&` here is similar to an `if` block
        # returns 0 or 1
        self.flag_urg = (flags_field & 0b00100000) >> 5
        self.flag_ack = (flags_field & 0b00010000) >> 4
        self.flag_psh = (flags_field & 0b00001000) >> 3
        self.flag_rst = (flags_field & 0b00000100) >> 2
        self.flag_syn = (flags_field & 0b00000010) >> 1
        self.flag_fin = (flags_field & 0b00000001)


    def _build(self, src_ip, rcv_ip):
        flags = (
            (self.flag_urg << 5) | (self.flag_ack < 4) | (self.flag_psh << 3) | (self.flag_rst << 2) | (self.flag_syn << 1) | self.flag_fin
        )

        header = struct.pack(
            '!HHIIBBHHH',
            self.src_port,
            self.rcv_port,
            self.seq_num,
            self.ack_num,
            (self.data_offset << 4),
            flags,
            self.window_size, 
            0,
            self.urgent_pointer
        )

        pseudo_header = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(rcv_ip),
            0, # reserved
            IP_PROTOCOL_TCP,
            len(header) + len(self.payload)
        )
        
        checksum_data = pseudo_header + header + self.payload
        self.checksum = checksum_calc(checksum_data)

        header = struct.pack(
            '!HHIIBBHHH',
            self.src_port,
            self.rcv_port,
            self.seq_num,
            self.ack_num,
            (self.data_offset << 4),
            flags,
            self.window_size, 
            self.checksum,
            self.urgent_pointer
        )

        return header + self.payload


    def __str__(self):
        flags = []
        if self.flag_syn: flags.append("SYN")
        if self.flag_ack: flags.append("ACK")
        if self.flag_fin: flags.append("FIN")
        return f"  TCP Segment: {self.src_port} -> {self.rcv_port} Flags: [{', '.join(flags)}] SEQ: {self.seq_num} ACK: {self.ack_num}"
