# VTDownloader

This tool can be used to download files from VirusTotal using their [v3 API](https://developers.virustotal.com/v3.0/reference). It is written in Python 3 for maintainability. This project was inspired by the [VirusTotal Intelligence downloader.](https://www.virustotal.com/intelligence/downloader/) 

VTDownloader works by fist searching based on the query provided to retrieve the hashes for the matching files, up to `n` results. The files corresponding to those hashes will then be downloaded in a password protected Zip archive. Alternatively, if a file of hashes is specified, those files will be downloaded in the same fashion without performing a search, provided those files exist on VirusTotal.

An API key is needed for this to work. It does not need to be a premium API key nor does it need 'private' API access.

## Installation:

```
$ git clone <clone url>
$ cd VTDownloader
$ pip3 install -r requirements.txt
$ export VT_API_KEY='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
```

## Usage:

The search query syntax is that of the [VirusTotal Intelligence Search](https://www.virustotal.com/intelligence/help/file-search/)
```
$ python3 vtdownloader.py -h
usage: vtdownloader.py [-h] [-f HASHFILE] [-n NUMFILES] [-q QUERY [QUERY ...]]
                       [-v]

Downloads files from VirustTotal. Specify the type of files desired using the standard VirustTotal query syntax.

optional arguments:
  -h, --help            show this help message and exit
  -f HASHFILE, --hashfile HASHFILE
                        A file of hashes to download. Can be any combination
                        of SHA-256, SHA-1, or MD5.
  -n NUMFILES, --number NUMFILES
                        The number of files to downlaod that match the search
                        query. Default is 50
  -q QUERY [QUERY ...], --query QUERY [QUERY ...]
  -v, --version         show program's version number and exit

```
To extract the downloaded files, 7zip can be used. The default password is 'infected':
```
$ 7z e downloads/YYYY-MM-DDTHH:mm:SS.zip
```
