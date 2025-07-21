import os
import sys
import fcntl
import struct


# bullsthi
TUNSETIFF = 0x400454ca 
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun_interface(name='tun0'):
    # setup virtual tun interface   
    dev_path = "/dev/net/tun"
    try:
        tun_fd = os.open(dev_path, os.O_RDWR)
    except OSError as e:
        print(f"Error opening {dev_path}: {e}", file=sys.stderr)
        print("Ensure the 'tun' module is loaded in your kernel", file=sys.stderr)
        sys.exit(1)

    ifreq = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)

    fcntl.ioctl(tun_fd, TUNSETIFF, ifreq)

    return tun_fd