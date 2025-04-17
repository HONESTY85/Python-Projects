#python port scanning scritp
import socket
target = input("Enter IP or URL:")
for port in range (1, 1024):
	s = socket.socket()
	s.settimeout(2)
	result = s.connect_ex((target, port))
	if result == 0:
		print(f"Port {port} is open")
	s.close()
