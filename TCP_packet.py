import struct

class TCP_Packet():
    def __init__(self, raw_bytes):
        self.raw = raw_bytes
        self._parse()

    def _parse(self):

        # the format string for a standard 20-byte TCP header.
        # H = Unsigned Short (2 bytes), I = Unsigned Int (4 bytes)
        
        header_format = '!HHIIBBHHH'
        header_size = struct.calcsize(header_format)
        header_tuple = struct.unpack(header_format, self.raw[:header_size])

        self.src_port, self.rcv_port, self.seq_num, self.ack_num = header_tuple[0], header_tuple[1], header_tuple[2], header_tuple[3]

        offset_and_flags = header_tuple[4]
        self.data_offset = offset_and_flags >> 4
        self.header_length = self.data_offset * 4

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

        # retrieve
        self.window_size, self.checksum, self.urgent_pointer, self.payload = header_tuple[6], header_tuple[7], header_tuple[8], self.raw[self.header_length:]

    def __str__(self):
        flags = []
        if self.flag_syn: flags.append("SYN")
        if self.flag_ack: flags.append("ACK")
        if self.flag_fin: flags.append("FIN")
        if self.flag_rst: flags.append("RST")
        if self.flag_psh: flags.append("PSH")
        if self.flag_urg: flags.append("URG")
        flags_str = " ".join(flags)

        return (
            f'  TCP SEGMENT: {self.src_port} -> {self.rcv_port}'
            f"    SEQ: {self.seq_num} | ACK: {self.ack_num}\n"
            f"    Flags: [{flags_str}] | Window: {self.window_size}"
        )
