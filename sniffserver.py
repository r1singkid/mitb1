from scapy.all import *
from socket import *
import re
import requests

host = "192.168.88.128"
port = 1234

serversock = socket(AF_INET,SOCK_DGRAM)
serversock.bind((host,port))

print("Server UP")

while True:
	msg,adr = serversock.recvfrom(1024)
	print (msg)
