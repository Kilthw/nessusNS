import json
import sys
import os
import subprocess
import argparse

usage = """
$ python ./%(prog)s -d <path to .nessus files> -o <output file> -p

Example: ./%(prog)s -d ./ -o output.txt -p

"""
parser = argparse.ArgumentParser(usage=usage)
parser.add_argument('-a', help='Create nessus dictionary and enter analysis mode.', dest='analyze', action='store_true', default=False)
parser.add_argument('-d', help='Path to .nessus files. Default: \'./\'', dest='nessusDir', action='store', default="./")
parser.add_argument('-o', help='Output name. Default: \'output.tsv\'', dest='outName', action='store', default="output.tsv")
parser.add_argument('-p', help='Try \'ping -a\' to resolve hostname (Note: Only works in Windows).', dest='ping', action='store_true', default=False)
parser.add_argument('-f', help='Flush previous results.', dest='flush', action='store_true', default=False)
if len(sys.argv)==1:
	parser.print_help()
	sys.exit(1)
opts = parser.parse_args()

nessus = {}
resolves = []

if opts.flush:
	os.remove("nessus.json")
	print("[!] Previous results flushed.\n")

def collectData():
	global nessus
	print()
	print("[*] Checking for existing nessus.json...")
	try:
		with open("nessus.json", "r") as f:
			nessus = json.load(f)
		f.close()
	except FileNotFoundError:
		print("[!] Previous results not found.")
		print("[*] Parsing Nessus Files for Host Reports...")
		for nessusFile in os.listdir(opts.nessusDir):
			if ".nessus" in nessusFile:
				with open(os.path.join(opts.nessusDir,nessusFile)) as f:
					currentHost = ""
					complete = True
					extline = ""
					for line in f:
						if "<ReportHost name" in line:
							currentHost = line.replace('<ReportHost name="','').replace('"><HostProperties>\n','').rstrip()
							nessus[currentHost] = {}
						if '<tag name="host-fqdn">' in line:
							nessus[currentHost]["hostfqdn"] = line.replace('<tag name="host-fqdn">','').replace('</tag>\n','').rstrip()
						if '<tag name="host-ip">' in line:
							nessus[currentHost]["hostip"] = line.replace('<tag name="host-ip">','').replace('</tag>\n','').rstrip()
						if '<tag name="netbios-name">' in line:
							nessus[currentHost]["netbiosname"] = line.replace('<tag name="netbios-name">','').replace('</tag>\n','').rstrip()
						if '<tag name="operating-system">' in line:
							if complete:
								if '</tag>' not in line:
									extline = line.replace('<tag name="operating-system">','').rstrip().lstrip()
									complete = False
								else:
									nessus[currentHost]["operatingsystem"] = line.replace('<tag name="operating-system">','').replace('</tag>\n','').rstrip()
						if not complete:
							if '</tag>' in line:
								extline += "; " + line.replace("</tag>",'').lstrip().rstrip()
								nessus[currentHost]["operatingsystem"] = extline
								complete = True
							elif line.replace('<tag name="operating-system">','').rstrip().lstrip() != extline:
								extline += "; " + line.lstrip().rstrip()
						if '<tag name="HOST_START">' in line:
							nessus[currentHost]["hoststart"] = line.replace('<tag name="HOST_START">','').replace('</tag>\n','').rstrip()
						if '<tag name="HOST_END">' in line:
							nessus[currentHost]["hostend"] = line.replace('<tag name="HOST_END">','').replace('</tag>\n','').rstrip()
						if '<tag name="os">' in line:
							nessus[currentHost]["os"] = line.replace('<tag name="os">','').replace('</tag>\n','').rstrip()
						if '<tag name="patch-summary-total-cves">' in line:
							nessus[currentHost]["patchsummarytotalcves"] = line.replace('<tag name="patch-summary-total-cves">','').replace('</tag>\n','').rstrip()
						if 'resolves as' in line:
							resolves.append(line.replace('.\n','').rstrip())
		print("[*] Parsing for FQDN Resolution plugin results...")
		for line in resolves:
			try:
				l = line.split()
				nessus[l[3]]["hostip"] = l[0]
			except KeyError:
				try:
					nessus[l[3].split(".")[0]]["hostip"] = l[0]
				except KeyError:
					try:
						nessus[l[0]]["hostfqdn"] = l[3]
					except KeyError:
						nessus[l[3].lower()] = {}
						nessus[l[3].lower()]["hostip"] = l[0]
		print("[*] Writing JSON data...")
		with open("nessus.json", 'w') as j:
			json.dump(nessus, j)
		j.close()
	print("[!] Done.")

def outputData():
	print("[*] Writing Excel formatted nslookup data...")
	if not opts.ping:
		p = open("ping.bat", "w")
	with open(opts.outName, "w") as f:
		for l in nessus:
			if l.startswith("10.") or l.startswith("159."):
				try:
					f.write(nessus[l]["hostfqdn"] + "\t" + l + "\n")
				except KeyError:
					try:
						f.write(nessus[l]["netbiosname"] + "\t" + l + "\n")
					except KeyError:
						if opts.ping:
							print("Checking ping -a results for " + l +"...")
							try:
								r = subprocess.check_output(["ping", "-a", l, "-n", "1"]).decode().lstrip()
							except subprocess.CalledProcessError as pingErr:
								r = pingErr.output.decode().lstrip()
								#p.write("ping -a " + l + " -n 1 >> temp\r\n")
							if "["+l+"]" in r:
								s = r.split(']',1)[0].replace('Pinging ','').replace('[','')
								results = s.rsplit(' ',1)
								print("    fqdn: " + results[0])
								print("    ip:   " + results[1])
								nessus[l]["hostfqdn"] = results[0]
								f.write(results[0] + "\t" + results[1] + "\n")
							else:
								try:
									f.write(l + "\t" + nessus[l]["hostip"] + "\n")
								except KeyError:
									f.write(l + "\t" + l + "\n")
						else:
							p.write("ping -a " + l + " -n 1 >> temp\r\n")
							try:
								f.write(l + "\t" + nessus[l]["hostip"] + "\n")
							except KeyError:
								f.write(l + "\t" + l + "\n")
			else:
				f.write(l + "\t" + nessus[l]["hostip"] + "\n")
	f.close()
	if not opts.ping:
		p.close()

collectData()

def analyzeMenu():
	print("\n"
		  "Select operation:\n"
		  "  [H]ost Query\n"
		  "  [O]perating System Query\n"
		  "  [T]op CVE counts\n"
		  "  [Q]uit\n"
		 )
	return input("Selection: ")

def hostquery():
	print()
	query = input("Query Hostname or IP address (or 'quit' to return to main menu): ").lower()
	clear = os.system("cls")
	if not query:
		hostquery()
	if query.lower() == "quit":
		go()
	for l in nessus:
		if query == l.lower():
			print()
			print(l, json.dumps(nessus[l], indent=4, sort_keys=True))
			break
		elif query in l.lower():
			print()
			print(l, json.dumps(nessus[l], indent=4, sort_keys=True))
		else:
			for i in l:
				if query == i.lower():
					print()
					print(l, json.dumps(nessus[l], indent=4, sort_keys=True))
					break
				if query in i.lower():
					print()
					print(l, json.dumps(nessus[l], indent=4, sort_keys=True))
	hostquery()

def osquery():
	oslist = []
	for l in nessus:
		try:
			if nessus[l]["os"] not in oslist:
				oslist.append(nessus[l]["os"])
		except KeyError:
			pass
	oslist.append("all")
	print()
	print("OS Types:")
	for x,i in enumerate(oslist): 
		print("  [" + str(x) + "] " + i)
	print()
	query = input("[?] Select OS type (or 'quit' to return to main menu): ")
	clear = os.system("cls")
	if query.lower() == "quit":
		go()
	try:
		selection = oslist[int(query)]
		toprint = input("\n[" + selection + "] Output File Name (or leave blank for STDOUT): ")
		if toprint:
			f = open(toprint, "w")
		else:
			print()
		for l in nessus:
			try:
				if nessus[l]["os"] == selection or selection == "all":
					if l.startswith("10.") or l.startswith("159."):
						try:
							result = nessus[l]["hostfqdn"] + "\t" + l + "\t" + nessus[l]["operatingsystem"]
						except KeyError:
							try:
								result = nessus[l]["netbiosname"] + "\t" + l + "\t" + nessus[l]["operatingsystem"]
							except KeyError:
								try:
									result = l + "\t" + nessus[l]["hostip"] + "\t" + nessus[l]["operatingsystem"]
								except KeyError:
									result = l + "\t" + l + "\t" + nessus[l]["operatingsystem"]
					else:
						result = l + "\t" + nessus[l]["hostip"] + "\t" + nessus[l]["operatingsystem"]
					if toprint:
						f.write(result + "\n")
					else:
						print(result)
			except KeyError:
				pass
		if toprint:
			f.close()
	except (IndexError, ValueError):
		print("[!] Please select a valid option.")
	osquery()
	
	
def go():
	action = analyzeMenu().lower()
	if action in ["h", "o", "t", "q"]:
		if action == "h":
			clear = os.system("cls")
			hostquery()
		if action == "q":
			sys.exit()
		if action == "o":
			osquery()
	clear = os.system("cls")
	go()
	
if opts.analyze:
	go()
			
	
	print("operating-system\n"
		  "HOST_START\n"
		  "HOST_END\n"
		  "os\n"
		  "patch-summary-total-cves\n")
	input()
	
print("Done!\n")