#!/usr/bin/python
#
# Nessus parser
# groups by finding
# uses Beautiful Soap to handler .nessus files
# everything else is default mods.
#
# outputs one CSV by host
# outputs one CSV by finding
#
# Can include a previous CSV into the run as well as nessus files, see "-h"
#
#
# written by DAS 2015
# 


import 	csv
import 	sys
import	os
from 	bs4 	import BeautifulSoup
import 	pprint	

exedirectory 		= os.getcwd()
reportingFolder		= exedirectory+"/reporting"
nessusFiles 		= []
entry 				= []
count 				= 0
findings_section 	= []
data_imported 		= []


print "[--------------------------------------------------------------------------------------------------]"
print "[i] NMAP XML PARSER"
print "[i] DAS 2015"

def findDotNessus():

	print "[--------------------------------------------------------------------------------------------------]"
	print "[+] Looking for nessus output..."
	if exedirectory.endswith("nessus"):
		for checkfile in os.listdir(os.getcwd()) :
			directory = os.getcwd()
			if checkfile.endswith(".nessus") :
				nessusFiles.append((directory+"/"+checkfile))	
			else:
				try:
					os.chdir(checkfile)	
					for cfile in os.listdir(os.getcwd()) :
						directory = os.getcwd()
						if cfile.endswith(".nessus") :
							nessusFiles.append((directory+"/"+cfile))	
					os.chdir("../")
				except:
					pass

		if len(nessusFiles) == 0 :
				sys.exit("[!] Sorry, no nessus output files can be found")

		print "[!] Done"


	else:
		for directory in os.listdir(os.getcwd()) :	
			if directory == 'nessus':
				os.chdir(directory)
				for checkfile in os.listdir(os.getcwd()) :
					directory = os.getcwd()
					if checkfile.endswith(".nessus") :
						nessusFiles.append((directory+"/"+checkfile))	
					else:
						try:
							os.chdir(checkfile)	
							for cfile in os.listdir(os.getcwd()) :
								if cfile.endswith(".nessus") :
									nessusFiles.append((directory+"/"+cfile))		
							os.chdir("../")
						except:
							pass

				if len(nessusFiles) == 0 :
						sys.exit("[!] Sorry, no nessus output files can be found")

				print "[!] Done"

				break # no need to look for more directories!


#create ouput folder
if not os.path.exists(reportingFolder):
    os.makedirs(reportingFolder)


def processNessusFiles ():

	print "[*] Processing Nessus Files. "
	for n in nessusFiles:
		
		nessusFile = n
		nessusParser(nessusFile)
		global count
		count = count + 1	
		
	print "[+] " +str(count)+ " Nmap files processed."
	print "[--------------------------------------------------------------------------------------------------]"

def nessusParser(xmlFile):

	xml = open(xmlFile, 'r')
	xfile = xml.read()
	bs = BeautifulSoup(xfile, "xml")
	if bs.find_all("Report"):
		global conts
		conts = bs
		# Call functions here
		parseAway(conts)
		print "[+] %s : Done!" % xmlFile 
	else: 
		exit_string = '[!] no report tags found in file' + xmlFile
		sys.exit(exit_string)

	xml.close()


def parseAway(conts):


	target 	= ""
	fqdn 	= ""
	ipaddr 	= ""
	cpe 	= ""
	cpe0 	= ""
	cpe1 	= ""
	os 		= ""

	findingID 		= ""
	findingName 	= ""
	findingSeverity = ""
	findingRisk 	= ""
	findingPort 	= ""
	findingProto	= ""
	findingServ		= ""
	findingSynop	= ""
	findingDesc		= ""
	findingEvid		= ""
	findingLink		= ""
	findingSol		= ""
	findingCVE		= ""
	findingCWE		= ""


	# scan 
	try:
		scanName 	= conts.Report['name']
	except: pass


	# for each target...
	for host in conts.find_all('ReportHost'):
		try:
			target 		= host['name']
		except: pass


		# cycle through tags for sys info...
		for tag in host.HostProperties.find_all('tag'):
			try:
				if tag['name'] == "host-fqdn":
					fqdn   		= tag.getText()
			except: pass

			try:
				if tag['name'] == "host-ip":
					ipaddr 		= tag.getText()
			except: pass
			try:
				if tag['name'] == "cpe":	
					cpe 		= tag.getText() 
			except: pass
			try:
				if tag['name'] == "cpe-0":	
					cpe0 		= tag.getText()
			except: pass
			try:
				if tag['name'] == "cpe-1":	
					cpe1 		= tag.getText()
			except: pass
			try:
				if tag['name'] == "operating-system":
					os 			= tag.getText()
			except: pass		
	

		# for each reported item per above target....
		for contents in host.find_all('ReportItem'):

			try:
				findingID 		= contents['pluginID']
			except: pass
			try:
				findingName 	= contents['pluginName']
			except: pass
			try:
				findingSeverity = contents['severity']
			except: pass
			try:
				findingRisk		= contents.risk_factor.getText()
			except: pass
			try:
				findingPort		= contents['port']
			except: pass
			try:
				findingProto	= contents['protocol']
			except: pass
			try:
				findingServ		= contents['svc_name']
			except: pass
			
			try:
				findingSynop	= contents.synopsis.getText()
			except: pass
			try:
				findingDesc		= contents.description.getText()
			except: pass
			try:
				findingEvid		= contents.plugin_output.getText()
			except: pass
			try:
				findingLink		= contents.see_also.getText()
			except: pass
			try:
				findingSol		= contents.solution.getText()
			except: pass
			try:
				findingCVE		= contents.cve.getText()
			except: pass
			try:
				findingCWE		= contents.cwe.getText()
			except: pass

			# Add to list for a row
			global entry
			entry = [scanName, \
					target, \
					fqdn, \
					ipaddr, \
					cpe, \
					cpe0, \
					cpe1, \
					os, \
					findingID, \
					findingName, \
					findingSeverity, \
					findingRisk, \
					findingPort, \
					findingProto, \
					findingServ, \
					findingSynop, \
					findingDesc, \
					findingEvid, \
					findingLink, \
					findingSol, \
					findingCVE, \
					findingCWE]	

			# check entry / row is not empty...
			emptyEntry = False
			emptyCount = 0

			for item in entry:
				if item != "":
					pass
				else: 
					emptyCount = emptyCount + 1

			if emptyCount != 22:
				# Add to findings db
				findings_db(entry)
				output(entry)



def findings_db(results):
	
	# check for imported data, if exists add to findings db
	if len(data_imported) >= 1:
		for data_item in data_imported: 
			if data_item not in findings_section:
				findings_section.append(data_item)

	# Add results / finding to findings db
	if len(findings_section) == 0 :
		findings_section.append(results)
	else:
		if results not in findings_section:
			findings_section.append(results)
									

def group_by_findings():

	print "[*] Grouping findings..."
	# 1. make a unique list of findings
	vul_title = []
	global temp_grouped_findings_db
	temp_grouped_findings_db = []

	#pprint.pprint(findings_section)
	for finding in findings_section:
		vul_title.append(finding[9])
		temp = [finding[9]]
		if temp not in temp_grouped_findings_db:
			temp_grouped_findings_db.append(temp)


	print "[*] Total findings:", len(vul_title)	
	#count before dedupe: 7472
	vul_title = sorted(set(vul_title)) # list of unique findings from assessment
	print "[+] Grouped findings:", len(vul_title)
	#count after dedupe: 82

	for issue in temp_grouped_findings_db: # list of lists
			for finding in findings_section: # finding data

				if finding[9] == issue[0]: # if finding descriptions match
					if len(issue) <= 1: # target # if no data is in the row, i.e. no entries...
						sorted_finding = process_findings(finding)
						issue.append(sorted_finding[1])
						issue.append(sorted_finding[2])
						issue.append(sorted_finding[3])
						issue.append(sorted_finding[4])
						issue.append(sorted_finding[5])

					else: 
						merged_finds = Merge_finding_entries(finding, issue)
						issue[1] = merged_finds[1]
						issue[2] = merged_finds[2]
						issue[3] = merged_finds[3]
						issue[4] = merged_finds[4]
						issue[5] = merged_finds[5]
						
	print "[--------------------------------------------------------------------------------------------------]"
	# arrange findings into risk order
	results = risk_order(temp_grouped_findings_db)
	# remove reporting chaff - ('Nessus Scan information' and 'TCP Scanner' etc..)
	results = dechaff(results)
	# report the grouped findings
	output_grouped_findings(results)




def process_findings(finding):
	
	name 	= finding[9]
	target  = target_info(finding[1],finding[12],finding[13])
	risk 	= severity_risk(finding[10],finding[11])
	desc 	= description(finding[15], finding[16])
	sol 	= solution(finding[19], finding[18])
	evid 	= finding[17] 

	sorted_finding = [name, target, risk, desc, sol, evid]
	return sorted_finding


def target_info(target, port, service):

	global target_string
	target_string = str(target + ":" + port + "/" + service + "\n")
	return target_string


def severity_risk(severity, risk):

	global risk_score
	risk_score = str(severity + " | " + risk)
	return risk_score


def description(synopsis, descript):

	global description_string
	description_string = str(synopsis + "\n" + descript)
	return description_string


def solution(solu, links):

	global solution_string
	solution_string = str(solu + "\n" + links)
	return solution_string


def Merge_finding_entries(finding, issue):

	name 	= issue[0]
	target  = issue[1] + "\n" + target_info(finding[1],finding[12],finding[13])

	old_risk = issue[2].split("|")
	
	if int(finding[10]) > int(old_risk[0]):
		risk = severity_risk(finding[10],finding[11])
	else:
		risk = issue[2]

	desc 	= issue[3]
	sol 	= issue[4]
	if finding[16] not in issue[5]:
		evid 	= issue[5] + finding[16]
	else:
		evid 	= issue[5]
	merged_finding = [name, target, risk, desc, sol, evid]
	return merged_finding


def risk_order(findingsdb):

	global organised_findings
	organised_findings = []

	# re arrange findings into risk order:
	for subfinding in findingsdb:
		f = subfinding[2].split("|")
		if f[0] == "4 ":
			organised_findings.append(subfinding)

	for subfinding in findingsdb:
		f = subfinding[2].split("|")
		if f[0] == "3 ":
			organised_findings.append(subfinding)

	for subfinding in findingsdb:
		f = subfinding[2].split("|")
		if f[0] == "2 ":
			organised_findings.append(subfinding)

	for subfinding in findingsdb:
		f = subfinding[2].split("|")
		if f[0] == "1 ":
			organised_findings.append(subfinding)

	for subfinding in findingsdb:
		f = subfinding[2].split("|")
		if f[0] == "0 ":
			organised_findings.append(subfinding)

	return organised_findings


def dechaff(results):
# removes findings which wouldnt normally be reported on from Nessus, or collect and verified via different means.

	chaff = ["Nessus UDP Scanner", \
				"Nessus Scan Information" , \
				"Nessus TCP scanner", \
				"Nessus SYN scanner", \
				"OS Identification Failed", \
				"Ethernet Card Manufacturer Detection", \
				"Traceroute Information" \
				"ICMP Timestamp Request Remote Date Disclosure" \
				"Network Time Protocol (NTP) Server Detection" \
				"mDNS Detection (Local Network)" \
				"OS Identification" \
				"Device Type"]
	
	for finding in results:
		if finding[0] in chaff:
			results.remove(finding)
			for finding in results: # extra loop to catch items the shuffle when an item is purged - need a better fix!
				if finding[0] in chaff:
					print "Deleting finding:" , "[",finding[0],"]"
					results.remove(finding)

	return results

def output_grouped_findings(findings_list):

	global reporting
	reporting = reportingFolder+"/"+sys.argv[1]+"_byVulnerability.csv"

	gpf 	= csv.writer(open(reporting , "wb"))

	gpf_headers = ["Title","Target","Risk","Description","Solution","Supporting_Data"]
	gpf.writerow(gpf_headers)

	print "[*] Findings Summary (Risk Ordered):"
	for finding in findings_list:
		print "[+] : ", finding[0]
		gpf.writerow(finding)


def output(results):
	
		c.writerow(results)


# -------------------------------------------------------------------------------------

# main


usage = "[?] Usage: nessusParser.py [outputfile] \
			\n\n\t-i\t[import_file.csv] \
			\n\n:: DotNessusXML Parser to CSV by DAS 2015 ::"

# Handle args...
if len(sys.argv) < 2:
	sys.exit(usage)

if len(sys.argv) > 1 :
	if sys.argv[1] != "-h":
		if not sys.argv[1].startswith("-"):
			outfile = reportingFolder+"/"+sys.argv[1] + "_byTarget.csv" 
			c 		= csv.writer(open(outfile , "wb"))
			# write out a new cache file...
			c_headers		= ["Scan Name", \
							  	"Target", \
								"FQDN", \
								"IP address", \
								"cpe_Data", \
								"cpe0_Data", \
								"cpe1_Data", \
								"Operating System", \
								"Nessus ID", \
								"Title", \
								"Severity", \
								"Risk", \
								"Port", \
								"Protocol", \
								"Service Type", \
								"Synopsis", \
								"Description", \
								"Scan Data", \
								"Links", \
								"Solution", \
								"CVE", \
								"CWE"]
			c.writerow(c_headers)
		else:
			sys.exit(usage)	
	else:
		sys.exit(usage)

try:
	if len(sys.argv) > 2 :
		if sys.argv[2] == "-i":
			if sys.argv[3]:
				if sys.argv[3].endswith(".csv"):
					t = raw_input("[*] Would you like to import previous results file: %s? (y/n)" % sys.argv[3])
					try:
						if t == "y":
							filepath = reportingFolder+"/"+sys.argv[3]
							imported_data = csv.reader(sys.argv[3])
							print "[+] Data imported!"
					except:
						pass
						print "[!] Data not imported"

		else:
			sys.exit(usage)	



except:
	sys.exit(usage)



# write out imported data
try:
	if len(imported_data) > 0:
		for row in imported_data:
			c.writerow(row)
			data_imported.append(row)
except:
	pass


findDotNessus()
processNessusFiles()
group_by_findings()
print "[*] Finished!"
print "[--------------------------------------------------------------------------------------------------]"
print "[+] Results 'All, by Target' saved: \t", outfile	
print "[+] Results 'Tidied, by Vulnerability' saved: \t", reporting	
print "[--------------------------------------------------------------------------------------------------]"
#pprint.pprint(findings_section)
		


		


