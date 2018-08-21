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
parser.add_argument('-d', help='Path to .nessus files. Default: \'./\'', dest='nessusDir', action='store', default="./")
parser.add_argument('-o', help='Output name. Default: \'output.tsv\'', dest='outName', action='store', default="output.txt")
parser.add_argument('-p', help='Try \'ping -a\' to resolve hostname (Note: Only works in Windows).', dest='ping', action='store_true', default=False)
if len(sys.argv)==1:
	parser.print_help()
	sys.exit(1)
opts = parser.parse_args()

nessus = {}
resolves = []

print("Parsing Nessus Files for Host Reports...")
for nessusFile in os.listdir(opts.nessusDir):
	if ".nessus" in nessusFile:
		with open(os.path.join(opts.nessusDir,nessusFile)) as f:
			currentHost = ""
			for line in f:
				if "<ReportHost name" in line:
					currentHost = line.replace('<ReportHost name="','').replace('"><HostProperties>\n','')
					nessus[currentHost] = {}
				if '<tag name="host-fqdn">' in line:
					nessus[currentHost]["hostfqdn"] = line.replace('<tag name="host-fqdn">','').replace('</tag>\n','')
				if '<tag name="host-ip">' in line:
					nessus[currentHost]["hostip"] = line.replace('<tag name="host-ip">','').replace('</tag>\n','')
				if '<tag name="netbios-name">' in line:
					nessus[currentHost]["netbiosname"] = line.replace('<tag name="netbios-name">','').replace('</tag>\n','')
				if 'resolves as' in line:
					resolves.append(line.replace('.\n',''))
print("Parsing for FQDN Resolution plugin results...")
for line in resolves:
	try:
		l = line.split()
		nessus[l[3]]["hostip"] = l[0]
	except KeyError:
		nessus[l[0]]["hostfqdn"] = l[3]

print("Writing Excel formatted nslookup data...")
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
						except subprocess.CalledProcessError:
							print("    [!] " + l + " ping attempt errored out...")
							p.write("ping -a " + l + " -n 1 >> temp\r\n")
						if "["+l+"]" in r:
							s = r.split(']',1)[0].replace('Pinging ','').replace('[','')
							results = s.rsplit(' ',1)
							print("    fqdn: " + results[0])
							print("    ip:   " + results[1])
							nessus[l]["hostfqdn"] = results[0]
							f.write(results[0] + "\t" + results[1])
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
p.close()
print("Writing JSON nslookup data...")
with open("nslookup.json", 'w') as j:
	json.dump(nessus, j)
j.close()

print("Done!\n")