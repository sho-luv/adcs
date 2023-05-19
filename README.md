# Active Directory Certificate Services (ADCS) Auto Exploit Tool

This tool is developed by Leon Johnson (twitter: @sho_luv) and is a Python wrapper for `certipy` and `ntlmrelayx` to automate escalation of privileges (esc8) in an environment where Active Directory Certificate Services (ADCS) is used. I will add other ADCS attacks as I get time. 

The tool automates the process of authenticating to a web enrollment server, potentially identifying and exploiting vulnerabilities in the ADCS setup to gain higher privileges in the system.

## Installation

Before running the script, make sure that `certipy`, `ntlmrelayx`, and `PetitPotam` are installed and properly set up in your Python environment. `certipy` and `PetitPotam` are external dependencies that need to be installed separately.

## Usage

This is a command line tool which can be executed as follows:
```
./esc8.py 

               #▒     ║▒▒╗╗,      é▒╗╖,   ╓╗#▒▒
             ╒╣╣╙╣    ╠╬╜^╬╬╬    ╬╬▌^╣╣  ╣╬╬ ╙╝
            ]╬╬,,╬▓-  ╠╬  ║╬╛    ║╬b      ╙╬▒
            ║╬╣╙ ╟╬µ  ╬╬  ╣╩     ╣╬▌     ╔, ╟╬▒
            ║╩  ,╬╬▒  ╙╣▒╣╙       ╙╝╣Å   └╬╬╝╜
      
           Active Directory Certificate Services
     AD CS Auto Exploit Tool by Leon Johnson aka @sho_luv
       
usage: esc8.py [-h] [-v] [-p PASSWORD] [-hashes [LMHASH]:NTHASH] target

positional arguments:
  target                domain/username[:password]

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -p PASSWORD, --password PASSWORD
                        Domain Password
  -hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
```



## Arguments

- `domain`: Domain to authenticate against.
- `username`: Username for the account you want to authenticate with.
- `password`: Password for the account you want to authenticate with. Not needed if using `nthash`.
- `nthash`: NT hash for the account you want to authenticate with. Not needed if using `password`.
- `verbose`: (Optional) Prints additional debug information.

## Features

- Automatically detects web enrollment servers and attempts to authenticate to them.
- Identifies if the user is unauthorized to access the web enrollment server.
- Uses `certipy` and `ntlmrelayx` to exploit the ADCS setup and escalate privileges, if possible.
- Prints detailed status and error messages.

## Contributing

Contributions are welcome. Please open an issue to discuss your ideas or initiate a Pull Request with your changes.

## Disclaimer

This tool is intended for security research purposes and should only be used with the proper permissions.

