import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def sendeth(eth_frame, interface = "eth0"):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
		s = s + w

	s = (s >> 16) + (s & 0xffff);
	s = ~s & 0xffff

	return s
 

if __name__ == "__main__":
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xa4, 0x1f, 0x72, 0xf5, 0x90, 0x83]
	src_mac = [0xa4, 0x1f, 0x72, 0xf5, 0x90, 0x8e]

	source_ip = '10.32.143.10'
	dest_ip = '10.32.143.14'
	split_src_ip = source_ip.split('.')
	split_dest_ip = dest_ip.split('.')
 
	data = "Hello, World!"
	data_size = len(data.encode('utf-8'))
	data_header = [hex(ord(c)) for c in data]
 
 	# udp header fields
	# source port, destination port, length, checksum 
	## source port = 49156
    ## destination port = 49157
    ## length =  256 bytes
    
    
	udp_header = pack('!HHHH', hex(49156), hex(49157), hex(256), 0x00) + data_header
	ip_header = pack(0x45,0x00, total_length, ip_id, flags, frag_offset, ttl, protocol, header_checksum,
		  hex(split_src_ip[0]), hex(split_src_ip[1]), hex(split_src_ip[2]), hex(split_src_ip[3]), 
		  hex(split_dest_ip[0]), hex(split_dest_ip[1]), hex(split_dest_ip[2]), hex(split_dest_ip[3]))		# or socket.gethostbyname('www.google.com')
	 
	# ip header fields
 
	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)
	
	# the ! in the pack format string means network order
	
	# build the final ip header (with checksum)
	 
	
 
   
	# the ! in the pack format string means network order
	  
	# final full packet - syn packets dont have any data
	packet = eth_header + udp_header + data_header
	r = sendeth(packet, "eth0")
	
	print("Sent %d bytes" % r)