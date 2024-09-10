#/usr/bin/python
from scapy.all import sniff

IP_MAC_Map = {}

def processPacket(packet):
    # Check if it's an ARP packet
    if packet.haslayer('ARP'):
        src_IP = packet['ARP'].psrc
        src_MAC = packet['Ether'].src

        # Check if the MAC address is already in the map with a different IP
        if src_MAC in IP_MAC_Map and IP_MAC_Map[src_MAC] != src_IP:
            old_IP = IP_MAC_Map.get(src_MAC, "unknown")

            message = (
                f"\n[!] Possible ARP attack detected!\n"
                f"    MAC address {src_MAC} was associated with IP {old_IP},\n"
                f"    but is now claiming to be {src_IP}.\n"
            )
            print(message)
        else:
            # Update the map with the current IP/MAC association
            IP_MAC_Map[src_MAC] = src_IP

sniff(count=0, filter="arp", store=0, prn=processPacket)
