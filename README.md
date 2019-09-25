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

Sample output:
```
$ python3 vtdownloader.py -q submitter:BR submitter:web fs:2019-08-25+ fs:2019-09-25- -n 5
09/24/2019 11:08:01 - INFO: [*] Now getting results for the query 'submitter:BR submitter:web fs:2019-08-25+ fs:2019-09-25-'.
09/24/2019 11:08:01 - INFO: [*] Sending search request to VirusTotal.
09/24/2019 11:08:05 - INFO: [*] Gathering hashes of files returned from search.
09/24/2019 11:08:11 - INFO: [*] Requesting download url for Zip of files from hashes.
09/24/2019 11:08:11 - INFO: [*] Requesting download url for files from VirusTotal.
09/24/2019 11:08:15 - INFO: [-] Zip file not yet ready to download...Attempting again in 5 sec.09/24/2019 11:08:20 - INFO: [+] Now downloading file downloads/2019-09-24T23:08:20.zip. Password will be 'infected'.

Files downloaded:

+----+------------------------------------------------------------------+--------------------+---------------+----------------------+ 
|    | SHA-256                                                          | Filename           | Size          | Latest Submission    |
+====+==================================================================+====================+===============+======================+
|  0 | 43607474f4870c5a6df7944b803d9384ac951365bcba27355d59d4bde4303cd2 | RCH89929003112.001 | 1441832 bytes | 2019-09-25T00:51:46Z |
+----+------------------------------------------------------------------+--------------------+---------------+----------------------+
|  1 | 48fc7246502a44a48d68e1b5731ea9958d30226e5bae719445f53840f661c919 | sprite.rar         | 5836579 bytes | 2019-09-24T23:59:36Z |
+----+------------------------------------------------------------------+--------------------+---------------+----------------------+
|  2 | 2fe66785e4337fc5dd666c32822d29b3a2dc8012c2b7466bada1719a35a8e38f | myShell.php        | 111695 bytes  | 2019-09-24T23:58:41Z |
+----+------------------------------------------------------------------+--------------------+---------------+----------------------+
|  3 | 415b12101c067a0126f4aa57932175a78c7aafc3e439a66ca20c1e9c87d9119b | teste.php          | 111695 bytes  | 2019-09-24T23:57:49Z |
+----+------------------------------------------------------------------+--------------------+---------------+----------------------+
|  4 | 3b8748d616880a4aec19beda9a3c38e9cb3fcd4ab0c7acfa87a8df9acc5cc178 | DHJcheats.exe      | 893952 bytes  | 2019-09-24T23:57:24Z |
+----+------------------------------------------------------------------+--------------------+---------------+----------------------+

```

To extract the downloaded files, 7zip can be used. The default password is 'infected':
```
$ 7z e downloads/YYYY-MM-DDTHH:mm:SS.zip
```
