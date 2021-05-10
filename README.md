# Reecon

Reelix's Recon - A small program for network recon. This program is still in early stages of development and should probably not be used by anyone.
* Version: 0.26c
* Build Status: <img src = "https://travis-ci.com/Reelix/Reecon.svg?branch=master" valign="middle" />
* Requirements: [NMap 7.80+](https://nmap.org/download.html), [.NET 5.0](https://dotnet.microsoft.com/download/dotnet/5.0)
* Recommended:
  * HTTP/S Enumeration: [Gobuster](https://github.com/OJ/gobuster)
  * SMB Enumeration: [smbclient](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)
  * Kerberos Enumeration: [Kerbrute](https://github.com/ropnop/kerbrute), [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py), [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
  * Printer Enumeration: [PRET](https://github.com/RUB-NDS/PRET)

## Installation Instructions
### Linux
1.) Install the .NET 5 SDK if you don't have it: `sudo apt install dotnet-sdk-5.0`  
2.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
3.) Run the build file: `chmod +x ./Reecon/build && ./Reecon/build`  
4.) Run: `./reecon`  
5.) Optional: Copy `./reecon` into `/bin/reecon` to be able to run `reecon` from anywhere  
6.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone

### Windows  
1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `.\Reecon\build.bat`  
3.) Run `.\Reecon\build\Reecon.exe`  
4.) Optional: Move the `Reecon.exe` file to wherever you want  
5.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone
