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
				# Situation 1: brand new IP
				tracker[src_ip] = {"ports": {dst_port}, "first_seen": time.time()} 
			else:
				# Seen this IP before, figure out which situation we're in
				elapsed_time = time.time() - tracker[src_ip]["first_seen"] 

				if elapsed_time > 5:
					# Situation 2: too much time passed, reset
					tracker[src_ip] = {"ports": {dst_port}, "first_seen": time.time()}
				else:
					# Situation 3: still within the window, just add the port
					tracker[src_ip]["ports"].add(dst_port)

			# Alert check - runs after every packet, regardless of which situation happened
			if len(tracker[src_ip]["ports"]) >= 20:
				print(f"[!] ALERT: Potential port scan detected from {src_ip} - {len(tracker[src_ip]['ports'])} distinct ports hit") 

print("[*] Starting Python Packet Sniffer... Press Ctrl+C to stop.")
# Sniff traffic on all interfaces; adjust 'count' to capture more/fewer packets
sniff(prn = process_packet, timeout = 30, iface = "tailscale0")
