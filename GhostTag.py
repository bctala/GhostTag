from scapy.all import * 
import random

def add_flags_to_packets(packets, user_flags):
    packets = list(packets)  
    for flag in user_flags:
        flag_bytes = flag.encode() 
        if len(packets) > 0:
            pkt_index = random.randint(0, len(packets) - 1)
            pkt = packets[pkt_index]
            if Raw in pkt: 
                pkt[Raw].load += b"|" + flag_bytes 
            else:
                pkt = pkt / Raw(load=flag_bytes)
            packets[pkt_index] = pkt  
    return packets

def analyze_packets(packets, user_flags):
    print("\nPacket Analysis Report")

    flag_packets = []
    for i, pkt in enumerate(packets):
        if Raw in pkt:
            for flag in user_flags:  
                if flag.encode() in pkt[Raw].load:
                    flag_packets.append((i, pkt))
                    break

    print(f"\nTotal flagged packets found: {len(flag_packets)}")
    for i, pkt in flag_packets:
        print(f"\nFlag Packet #{i+1}:")
        if IP in pkt:
            print(f"  Source IP: {pkt[IP].src}")
            print(f"  Destination IP: {pkt[IP].dst}")
        if TCP in pkt:
            print(f"  Protocol: TCP")
            print(f"  Destination Port: {pkt[TCP].dport}")
        elif ICMP in pkt:
            print(f"  Protocol: ICMP")
        print(f"  Payload: {pkt[Raw].load.decode(errors='ignore')}")

    print("\nProtocol Distribution:")
    protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                protocols['TCP'] += 1
            elif UDP in pkt:
                protocols['UDP'] += 1
            elif ICMP in pkt:
                protocols['ICMP'] += 1
            else:
                protocols['Other'] += 1
        elif ARP in pkt:
            protocols['ARP'] += 1
        else:
            protocols['Other'] += 1
    
    for proto, count in protocols.items():
        print(f"  {proto}: {count} packets")

    print("\nFlagged Packet Summaries:")
    for i, pkt in flag_packets:
        print(f"\nSummary for Flag Packet #{i+1}:")
        pkt.summary() 
        print("\nDetailed Information:")
        pkt.show()  

def main():
    ghost_banner = r"""
  ⠀⠀⠀⢀⣴⣿⣿⣿⣦⠀
⠀⠀⠀⠀⣰⣿⡟⢻⣿⡟⢻⣧
⠀⠀⠀⣰⣿⣿⣇⣸⣿⣇⣸⣿
⠀⠀⣴⣿⣿⣿⣿⠟⢻⣿⣿⣿
⣠⣾⣿⣿⣿⣿⣿⣤⣼⣿⣿⠇
⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀
⠀⠀⠈⠿⠿⠋⠙⢿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """
    print(ghost_banner)
    print("Welcome to GhostTag: The Phantom Packet Flagger")

    try:
        num_flags = int(input("How many flags would you like to add? "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    print("\nPlease write each flag with its format, Ex: FlagX{your_flag_here}")
    user_flags = []
    for i in range(num_flags):
        flag = input(f"Enter flag #{i+1}: ").strip()
        user_flags.append(flag)

    print("\nSniffing network traffic for 30 seconds...")
    packets = sniff(timeout=30, filter="ip or arp")
    print(f"Captured {len(packets)} packets")

    packets = add_flags_to_packets(packets, user_flags)

    pcap_file = "traffic_with_flags.pcap"
    wrpcap(pcap_file, packets)
    print(f"Saved flagged traffic to {pcap_file}")

    analyze_packets(packets, user_flags)  
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()
