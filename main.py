import os
import random
import struct
from IP_packet import IP_Packet
from TCP_packet import TCP_Packet
from utils import create_tun_interface

IP_PROTOCOL_TCP = 6
        
def main():
    tun_fd = create_tun_interface('tun0')
    print(f'TUN Interface tun0 created succesfully')
    print("Waiting for packets...")
    try:
        while True:
            packet_bytes = os.read(tun_fd, 2048)
            if not packet_bytes: continue


            try:
                ip_packet = IP_Packet(packet_bytes)
                if ip_packet.protocol != IP_PROTOCOL_TCP: continue
                
                tcp_packet = TCP_Packet(ip_packet.payload)
                
                if tcp_packet.flag_syn and not tcp_packet.flag_ack:
                    print(f"\n--- SYN Received ---\n{ip_packet}\n{tcp_packet}")
                    
                    ip_reply = IP_Packet()
                    ip_reply.src_ip = ip_packet.rcv_ip
                    ip_reply.rcv_ip = ip_packet.src_ip
                    
                    tcp_reply = TCP_Packet()
                    tcp_reply.src_port = tcp_packet.rcv_port
                    tcp_reply.rcv_port = tcp_packet.src_port
                    
                    tcp_reply.ack_num = tcp_packet.seq_num + 1
                    tcp_reply.seq_num = random.randint(0, 4294967290) #4294967295 why this number? idk
                    
                    tcp_reply.flag_syn = 1
                    tcp_reply.flag_ack = 1
                    
                    ip_reply.payload = tcp_reply._build(ip_reply.src_ip, ip_reply.rcv_ip)
                    reply_packet_bytes = ip_reply._build()
                    
                    os.write(tun_fd, reply_packet_bytes)
                    print(">>> SENDING SYN-ACK >>>")
                    print(f"{ip_reply}\n{tcp_reply}\n")

            except (ValueError, struct.error):
                continue
    finally:
        os.close(tun_fd)
        print("Interface closed.")

if __name__ == "__main__":
    main()