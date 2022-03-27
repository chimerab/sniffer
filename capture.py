
from scapy.all import *
import sys

pktwriter = PcapWriter('save.pcap', append=True)


def handler(pkt: Packet):
    pktwriter.write(pkt)


def main():
    if len(sys.argv) < 2:
        print(f'usage: {sys.argv[0]} <interface>.')
        sys.exit(1)

    dev = sys.argv[1]
    try:
        ret = sniff(iface=dev, filter='port 6379', prn=handler)
    except KeyboardInterrupt as e:
        pass

    print('capture finished.')

if __name__ == '__main__':
    main()