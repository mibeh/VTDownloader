#! /usr/bin/env/python3
# License:
# Title: VTDownloader.py
#
# This tool can be used to download files from VirusTotal using the v3 API

import os, sys, re, time, json, datetime
import requests
import argparse
import logging
import urllib.parse

__author__= 'Michael Ibeh'
__version__= '0.1'

VT_API_KEY = os.environ['VT_API_KEY']

logging.basicConfig(level=logging.INFO, stream=sys.stdout, 
					format='%(asctime)s - %(levelname)s: %(message)s', 
					datefmt='%m/%d/%Y %I:%M:%S')

# Retrieve hashes for files from search query
def get_results(search, numfiles):

	url = 'https://www.virustotal.com/api/v3/intelligence/search?'
	headers = {'X-apikey':VT_API_KEY}
	params = urllib.parse.urlencode({'query':search, 'limit':numfiles, 'descriptors_only':'true'})
	url += params

	logging.info('[*] Sending search request to VirusTotal.')
	s = requests.Session()
	response = s.get(url, headers=headers)
	responseJSON = json.loads(response.text)

	logging.info('[*] Gathering hashes of files returned from search.')
	hashes = []
	for file in responseJSON['data']:
		hashes.append(file['id'])
	
	download_files(hashes)

	return 

# Download files based on the hashes provided, downloaded files will be in a password protected Zip
def download_files(hash_list):

	logging.info('[*] Requesting download url for Zip of files from hashes.')

	url = 'https://www.virustotal.com/api/v3/intelligence/zip_files'
	headers = {'X-apikey':VT_API_KEY}
	# Sets Zip file password
	data = json.dumps({"data":{"hashes":hash_list,"password":"infected"}})
	
	logging.info('[*] Requesting download url for files from VirusTotal.')
	s = requests.Session()
	response = s.post(url=url, headers=headers, data=data)
	responseJSON = json.loads(response.text)
	s.close()

	download_id = responseJSON['data']['id']
	id_url = 'https://www.virustotal.com/api/v3/intelligence/zip_files/'+download_id
	download_url = 'https://www.virustotal.com/api/v3/intelligence/zip_files/'+download_id+'/download_url'
	
	# Short pause to allow download to be ready
	time.sleep(2)

	while True:
		s = requests.Session()
		response = s.get(url=id_url, headers=headers)
		responseJSON = json.loads(response.text)
		s.close()

		status = responseJSON['data']['attributes']['status']
		if status == 'finished':
			break

		logging.info('[-] Zip file not yet ready to download...Attempting again in 5 sec.')
		time.sleep(5)

	dl_filename = os.path.join('downloads','{}.zip'.format(datetime.datetime.now()))
	logging.info('[+] Now downloading file {}. Password will be \'infected\'.'.format(dl_filename))
	response = s.get(url=download_url, headers=headers)
	responseJSON = json.loads(response.content)
	s.close()
	# Conatains actual download url
	zip_url = responseJSON['data']
	response = s.get(url=zip_url, headers=headers)

	if response.status_code == 200:
		# Make subdirectory if needed
		try:
			os.mkdir('downloads')
		except:
			pass

		download_zip = open(dl_filename, 'wb')
		download_zip.write(bytes(response.content))
		download_zip.close()
	
	s.close()
	
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
	hashfile = args.hashfile
	query= args.query
	if query:
		query = (' ').join(query)
		query = query.strip().strip('\'')

	requests.packages.urllib3.disable_warnings()

	if hashfile:
		try:
			if os.path.exists(hashfile):
				with open(hashfile, 'rt') as inputfile:
					logging.info('[*] Now reading hashes to download from file.')
					hashes = re.findall('([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})', inputfile.read())
					hash_list = list(hashes)
		except:
			logging.info("[-] Error: {} not found".format(hashfile))

		download_files(hash_list)

	if query:
		logging.info('[*] Now getting results for the query \'{}\'.'.format(query))
		get_results(query, numfiles)

if __name__ == '__main__':
	main()
