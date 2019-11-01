# Silent_IIS_Shortname

A simple python script to exploit the Windows IIS 8.3 short file names information disclosure 

## Usage
        usage: silent_iis_shortname.py [-h] (-u URL | -w WORDLIST) [-v]

        optional arguments:
          -h, --help            show this help message and exit
          -u URL, --url URL     Target URL
          -w WORDLIST, --wordlist WORDLIST
                                List with the paths to scan, for each line specify
                                http://target.com/path_to_examine
          -v, --verbose         Verbose output
