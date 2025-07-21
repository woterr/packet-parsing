import os
import sys
import struct
from IP_packet import IP_Packet
from TCP_packet import TCP_Packet
from utils import create_tun_interface

IP_PROTOCOL_TCP = 6
        
def main():
    tun_fd = None
    try:
        tun_fd = create_tun_interface('tun0')
        print(f'TUN Interface tun0 created succesfully')
        print("Waiting for packets...")

        while True:
            packet_bytes = os.read(tun_fd, 2048)
            if len(packet_bytes) == 0: break

            # ignore packets that claim to be tcp but are too small to be parsed
            if len(packet_bytes) < 20:
                print(f"\n--- Ignoring small packet (size: {len(packet_bytes)}) ---")
                continue
            
            try:
                ip_packet = IP_Packet(packet_bytes)
            except (struct.error, ValueError) as e:
                print(f"\n--- Ignoring invalid packet: {e} ---")
                continue

            print(f"\n--- Packet Received --- : {ip_packet}")
            if ip_packet.protocol == IP_PROTOCOL_TCP: # tcp protocol = 6
                try:
                    tcp_packet = TCP_Packet(ip_packet.payload)
                    print(tcp_packet)
                except Exception as e:
                    print(e)

            print("-----------------------")

    except OSError as e:
        print(f"No sudo permissions? {e}") # req admin for network layer creation
        sys.exit(1)

    except KeyboardInterrupt:
        print("Exiting gracefully") 

    finally:
        if tun_fd:
            os.close(tun_fd)
        print("Interface closed. Exiting")
        sys.exit(0)

if __name__ == "__main__":
    main()

    