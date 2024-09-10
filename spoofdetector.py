#!/usr/bin/env python3
from scapy.all import sniff, ARP, Ether

IP_MAC_Map = {}

def process_packet(packet):
    try:
        # Check if it's an ARP packet and contains an Ethernet layer
        if packet.haslayer(ARP) and packet.haslayer(Ether):
            src_IP = packet[ARP].psrc
            src_MAC = packet[Ether].src

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
    except Exception as e:
        print(f"Error processing packet: {e}")

try:
    print("[*] Sniffing for ARP packets... (Press Ctrl+C to stop)")
    sniff(count=0, filter="arp", store=0, prn=process_packet)
except KeyboardInterrupt:
    print("\n[*] Stopping packet sniffing.")
except Exception as e:
    print(f"Sniffing failed: {e}")
