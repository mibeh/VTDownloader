#! /usr/bin/env/python3
# 
# Title: vtdownloader.py
#
# This tool can be used to download files from VirusTotal using the v3 API
# given either a search query or a file with a list of hashes.
#
# Copyright (C) 2019 Michael Ibeh
'''
	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import os, sys, re, time, json
import requests
import argparse
import logging
import urllib.parse

__author__= 'Michael Ibeh'
__version__= '0.2'

VT_API_KEY = os.environ['VT_API_KEY']

logging.basicConfig(level=logging.INFO, stream=sys.stdout, 
					format='%(asctime)s - %(levelname)s: %(message)s', 
					datefmt='%m/%d/%Y %I:%M:%S')

# Retrieve only the SHA-256 of the matching files
def get_results(search, numfiles):

	url = 'https://www.virustotal.com/api/v3/intelligence/search?'
	headers = {'X-apikey':VT_API_KEY}
	params = urllib.parse.urlencode({'query':search, 'limit':numfiles, 'descriptors_only':'true'})
	url += params

	logging.info('[*] Sending search request to VirusTotal.')
	s = requests.Session()
	response = s.get(url, headers=headers)
	responseJSON = json.loads(response.text)

	if 'error' in responseJSON:
		logging.info("[-] Error:{} Message: {}".format(responseJSON['error']['code'], responseJSON['error']['message']))
		return
	else:
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

	if 'error' in responseJSON:
		logging.info("[-] Error: {} Message: {}".format(responseJSON['error']['code'], responseJSON['error']['message']))
		return
	else:
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

			if 'error' in responseJSON:
				logging.info("[-] Error: {} Message: {}".format(responseJSON['error']['code'], responseJSON['error']['message']))
				return
			else:
				status = responseJSON['data']['attributes']['status']
				if status == 'finished':
					break

				logging.info('[-] Zip file not yet ready to download...Attempting again in 5 sec.')
				time.sleep(5)

		dl_filename = os.path.join('downloads','{}.zip'.format(time.strftime('%Y-%m-%dT%H:%M:%S')))
		logging.info('[+] Now downloading file {}. Password will be \'infected\'.'.format(dl_filename))
		response = s.get(url=download_url, headers=headers)
		responseJSON = json.loads(response.content)
		s.close()
		# Returns a signed URL from where you can download the specified ZIP file. The URL expires after 1 hour.
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
		elif 'error' in responseJSON:
			logging.info("[-] Error: {} Message: {}".format(responseJSON['error']['code'], responseJSON['error']['message']))
			return
		
		s.close()
	
	return

def main():

	parser = argparse.ArgumentParser(description='Downloads files from VirustTotal. Specify the type of files desired using the standard VirustTotal query syntax.',
		formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-f', '--hashfile', dest='hashfile', help='A file of hashes to download. Can be any combination of SHA-256, SHA-1, or MD5.', required=False)
	parser.add_argument('-n', '--number', help='The number of files to downlaod that match the search query. Default is 50', 
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
		if os.path.exists(hashfile):
			with open(hashfile, 'rt') as inputfile:
				logging.info('[*] Now reading hashes to download from file.')
				hashes = re.findall('([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})', inputfile.read())
				hash_list = list(hashes)
				download_files(hash_list)
		else:
			logging.info("[-] Error: {} not found".format(hashfile))

	if query:
		logging.info('[*] Now getting results for the query \'{}\'.'.format(query))
		get_results(query, numfiles)

if __name__ == '__main__':
	main()
