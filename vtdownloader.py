#! /usr/bin/env/python3
# License:
# Title: VTDownloader.py
#
# This tool can be used to download files from VirusTotal using the v3 API

import os, sys, re, time, json, datetime
from io import BytesIO
import requests
import argparse
import logging
import threading
import queue
import urllib.parse

__author__= 'Michael Ibeh'
__version__= '0.1'

VT_API_KEY = os.environ['VT_API_KEY']

logging.basicConfig(level=logging.INFO, stream=sys.stdout, 
					format='%(asctime)s - %(levelname)s: %(message)s', 
					datefmt='%m/%d/%Y %I:%M:%S')

def get_results(search, numfiles):

	url = 'https://www.virustotal.com/api/v3/intelligence/search?'
	headers = {'X-apikey':VT_API_KEY}
	params = urllib.parse.urlencode({'query':search, 'limit':numfiles, 'descriptors_only':'true'})
	url += params
	s = requests.Session()

	logging.info('[*] Sending search request to VirusTotal.')
	response = s.get(url, headers=headers)
	
	responseJSON = json.loads(response.text)

	hashes = []
	for file in responseJSON['data']:
		hashes.append(file['id'])

	logging.info('[*] Requesting download url for Zip of files from hashes.')
	download_files(hashes)

	return 

def download_files(hash_list):

	url = 'https://www.virustotal.com/api/v3/intelligence/zip_files'
	headers = {'X-apikey':VT_API_KEY}
	data = json.dumps({"data":{"hashes":hash_list,"password":"infected"}})
	s = requests.Session()

	response = s.post(url=url, headers=headers, data=data)

	responseJSON = json.loads(response.text)

	download_id = responseJSON['data']['id']

	s.close()
	id_url = 'https://www.virustotal.com/api/v3/intelligence/zip_files/'+download_id
	download_url = 'https://www.virustotal.com/api/v3/intelligence/zip_files/'+download_id+'/download_url'
	
	while True:
		dl_s = requests.Session()
		dl_response = dl_s.get(url=id_url, headers=headers)
		dl_responseJSON = json.loads(dl_response.text)
		status = dl_responseJSON['data']['attributes']['status']
		dl_s.close()

		if status == 'finished':
			break

		logging.info('[-] Zip file not yet ready to download...Attempting again in 5 sec.')
		time.sleep(5)

	logging.info('[+] Now downloading Zip file. Password will be \'infected\'.')
	response = s.get(url=download_url, headers=headers)
	responseJSON = json.loads(response.content)
	s.close()
	zip_url = responseJSON['data']
	response = s.get(url=zip_url, headers=headers)
	if response.status_code == 200:
		download_zip = open('{}.zip'.format(datetime.datetime.now()), 'wb')
		download_zip.write(bytes(response.content))
		download_zip.close()
	
	return

def main():

	parser = argparse.ArgumentParser(description='Downloads files from VirustTotal. Specify the type of files desired using the standard VirustTotal query syntax.',
		formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-f', '--hashfile', dest='hashfile', help='A file of hashes to download.', required=False)
	parser.add_argument('-n', '--number', help='The number of files to downlaod that match the search query', 
		dest='numfiles', default=50)
	parser.add_argument('-q', '--query', help='', dest='query', action='store', nargs='+', required=False)
	parser.add_argument('-v', '--version', action='version',version='%(prog)s {version}'.format(version=__version__))
	
	args = parser.parse_args()

	numfiles = int(args.numfiles)
	query= args.query
	query = (' ').join(query)
	query = query.strip().strip('\'')
	hashfile = args.hashfile

	if hashfile:
		try:
			if os.path.exists(hashfile):
				with open(hashfile, 'rt') as inputfile:
					logging.info('[*] Now reading hashes from file.')
					hash_list = re.findall('([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})', inputfile.read())
					hash_query = ','.join(set(hash_list))
		except:
			logging.info("[-] Error: {} not found".format(hashfile))

		download_files(hash_query)

	if query:
		logging.info('[*] Now getting results for query.')
		get_results(query, numfiles)

	requests.packages.urllib3.disable_warnings()

if __name__ == '__main__':
	main()
