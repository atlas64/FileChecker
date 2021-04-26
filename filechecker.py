#!/usr/bin/python3
#title           :filechecker.py
#description     :Pulls MD5 checksum from file and then runs check against virus total and kaspersky
#author          :atl4s
#date            :4/26/21
#python_version  :3.7.9   
#==============================================================================

import json
import os
import requests 
import hashlib
import sys
import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi 

vt_result = ""
kasp_result = ""

#pull MD5 checksum from file passed in argument 
def filetohash(file):
	return hashlib.md5(open(file,'rb').read()).hexdigest()

def virustotalapi(hash):
	api_key = 'VIRUS TOTAL API KEY'
	vt = VirusTotalPublicApi(api_key)
	response = vt.get_file_report(hash)
	return json.dumps(response, sort_keys=False, indent=4)

def kasperskyapi(hash):
	r = requests.get("https://opentip.kaspersky.com/api/v1/search/hash?request={}".format(hash), headers={"x-api-key":"KASPERSKY API KEY"})
	return json.dumps(r.json(), sort_keys=False, indent=4)

#pass hash from scanned file into both APIs
def hashscan(hash):
	global vt_result
	global kasp_result

	vt_result = virustotalapi(hash)
	kasp_result = kasperskyapi(hash)

#save scans into a file
def savetofile():
	now = datetime.datetime.now()
	time = now.strftime("%H-%M-%S-%Y_%m_%d")
	file = open("FileScanReport-{}.txt".format(time),"w")
	lines = ["{}".format(vt_result),"{}".format(kasp_result)]
	file.writelines(lines)
	file.close
	print("Results saved to {}-FileScanReport.txt".format(time))

def main():
	h = filetohash(sys.argv[1])
	print("->Scanning file...")
	print("->File's MD5 Hash: {}".format(h))
	print("->Sending file to APIs...")
	hashscan(h)
	print("-" * 50)
	print("| Virus Total Results |")
	print("-" * 50)
	print(vt_result)
	print("-" * 50)
	print("| Kaspersky Threat Intel Results |")
	print("-" * 50)
	print(kasp_result)
	savetofile()
	
if __name__ == "__main__":
	main()







