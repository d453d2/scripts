#!/usr/bin/python

# host locator - physical location of IP
# pip install requests - if needed.

import sys
import requests
import json
import os
import argparse

parser = argparse.ArgumentParser(description="Queries online records to geolocate the an IP address.\nUses ipinfodb.com - register free for API Key.\n")
parser.add_argument("ip", default="", help="ip address you wish to query {./IPLocator.py 127.0.0.1}")
parser.add_argument("-o", default=False, action='store_true', dest='output', help="writes results to json file {./IPLocator.py 127.0.0.1 -o}")
parser.add_argument('--version', action='version', version="%(prog)s 1.0 written by Sedz 2016")
args = parser.parse_args()

# Check ip was provided
if args.ip == "":
	sys.exit("[-] FATAL: Please provide IP Address to look up")
else:
	ip = args.ip
	api_key = 'b8ab341fca3a81884f2909c794401f4c5d91007048f5dabb55fc63ec0fbe5698'
	url = 'http://api.ipinfodb.com/v3/ip-city/?key=%s&ip=%s&format=json' % (api_key,ip)

# request
r = requests.get(url)


# Handle response
if r.status_code == 200:

	data = json.loads(r.text)

	print "-" * 40
	print "[!] Queried IP Address: ", data['ipAddress']
	print "[!] Returned Response: ", r.status_code
	print "-" * 40
	if data['statusCode'] != "":
		print "[+] 	Status Code:", data['statusCode']
	if data['statusMessage'] != "":
		print "[+] 	Status Message:", data['statusMessage']
	if data['countryCode'] != "":
		print "[+] 	Country Code:", data['countryCode']
	if data['countryName'] != "":
		print "[+] 	Country Name:", data['countryName']
	if data['regionName'] != "":
		print "[+] 	Region Name:", data['regionName']
	if data['cityName'] != "":
		print "[+] 	City Name:", data['cityName']
	if data['zipCode'] != "":
		print "[+] 	Zip Code:", data['zipCode']
	if data['latitude'] != "":
		print "[+] 	Latitude:", data['latitude']
	if data['longitude'] != "":
		print "[+] 	Longitude:", data['longitude']
	if data['timeZone'] != "":
		print "[+] 	Time Zone:", data['timeZone']
	print "-" * 40

	if args.output is True:

		# wite out file - scripts function
		dire = os.getcwd() 
		fname = dire+"/"+"%s_iplocationdata.txt" % ip
		print "[+] Writing out to file: %s" % fname

		with open(fname, 'w') as f:
			f.write(json.dumps(data))

	print "[!] Done"
	print "-" * 40

else:
	print "[-] Reponse Received Fatal: %s" % str(r.status_code)
	print "[!] Exited"



