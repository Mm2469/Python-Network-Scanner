import scapy.all as scapy

def scan(ip):
	# Ask "Who has this IP?"
	arp_request = scapy.ARP(pdst=ip)
	# Send to everyone (broadcast)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	# Combine them
	arp_request_broadcast = broadcast/arp_request
	# Catch the responses
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

	print("\nIP Address\t\tMAC Address")
	print("-----------------------------------------")
	for element in answered_list:
		print(element[1].psrc + "\t\t" + element[1].hwsrc)

# Scanning your local network (192.168.1.1/24 is most common)
scan("192.168.4.1/24")

