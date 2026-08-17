from scapy.all import sniff, IP, TCP, UDP
import time

tracker = {}

def process_packet(packet):
	# Check if the packet has an IP layer
	if packet.haslayer(IP):
		src_ip = packet[IP].src
		dst_ip = packet[IP].dst
		# Determine the protocol
		if packet.haslayer(TCP):
			protocol = "TCP"
		elif packet.haslayer(UDP):
			protocol = "UDP"
		else:
			protocol = "Other"
		print(f'[+] [{protocol}] {src_ip} -> {dst_ip}')
		
		if packet.haslayer(TCP):
			dst_port = packet[TCP].dport
			if src_ip not in tracker:
				tracker[src_ip] = {"ports": {dst_port}, "first_seen": time.time()}  
			else:
				tracker[src_ip]["ports"].add(dst_port)
				

print("[*] Starting Python Packet Sniffer... Press Ctrl+C to stop.")
# Sniff traffic on all interfaces; adjust 'count' to capture more/fewer packets
sniff(prn = process_packet, timeout = 30, iface = "tailscale0")
