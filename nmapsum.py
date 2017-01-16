#!/usr/bin/python


import sys
import os
import pprint
import time
from datetime import datetime
from bs4 import BeautifulSoup


count = 0

directory = str(os.getcwd())
xFile = str(sys.argv[1]) 		# python nmapsum.py {outputfile}
xmlFile = directory+"/"+xFile

upHosts = []
downHosts = []

hostInfo = {}

def xmlParser(xmlFile):

	xml = open(xmlFile, 'r').read()
	bs = BeautifulSoup(xml, "xml")
	if bs.find_all("nmaprun"):
		# Call functions here
		findHostStatus(bs)
		getUpHostInfo(upHosts,bs)
	else: 
		sys.exit('[!] Invalid nmap file')


def findHostStatus (bs):

	for host in bs.find_all("host"):
		if host.status['state'] == "up":
			upHosts.append(host.address['addr'])
		if host.status['state'] == "down":
			downHosts.append(host.address['addr'])

def getUpHostInfo (upHosts, bs):

		for host in bs.find_all("host"):
			if host.status['state'] == "up":
				#print host.address['addr'] 
				addr = host.address['addr'] 
				for i in host.find_all("port"):
					#print i
					if i.state['state'] == "open":
						if i['protocol'] == "tcp":
							prt = str(i['portid'])
							newPort = addr+":"+prt
							#print i['portid'], "\t", i.state['state'], "\t", i.service['name']
							try:
								if i.service['product']:
									hostInfo[newPort] = i['portid'], i['protocol'], i.state['state'], i.service['name'], i.service['product']
							except:
								hostInfo[newPort] = i['portid'], i['protocol'], i.state['state'], i.service['name']





print "[!] File parsed: ", xmlFile
xmlParser(xmlFile);

print "\n[+] Scanned Host Status: \n"
print "[+] Up Hosts"
for host in upHosts:
	print str(host)

print "\nFor Scan and tool usage:"
for host in upHosts:
	print str(host)+",",
#print "\n[-] Down Hosts"
#for hosts in downHosts:
#	print str(host)+",",

#pprint.pprint(hostInfo)
