# Reecon

Reelix's Recon - A small program for network recon. This program is still in early stages of development and should probably not be used by anyone.
* Version: 0.27c
* Build Status: <img src = "https://travis-ci.com/Reelix/Reecon.svg?branch=master" valign="middle" />
* Requirements: [NMap 7.92+](https://nmap.org/download.html), [.NET 5.0](https://dotnet.microsoft.com/download/dotnet/5.0)
* Recommended:
  * HTTP/S Enumeration: [Gobuster](https://github.com/OJ/gobuster)
  * SMB Enumeration: [smbclient](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)
  * Kerberos Enumeration: [Kerbrute](https://github.com/ropnop/kerbrute), [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py), [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
  * Printer Enumeration: [PRET](https://github.com/RUB-NDS/PRET)

## Installation Instructions (No Building)
### Linux (x64)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-x64
### Windows (x64)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/Reecon-windows.exe
### Linux (musl - x64 - Probably Alpine)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-musl-x64

## Build Instructions
### Linux (Ubuntu)
1.) Install the .NET 5 SDK if you don't have it: `sudo apt install dotnet-sdk-5.0`  
2.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
3.) Run the build file: `chmod +x ./Reecon/build && ./Reecon/build`  
4.) Run: `./reecon`  
5.) Optional: Move `./reecon` into `/usr/local/bin/reecon` to be able to run `reecon` from anywhere  
6.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone

### Windows  
1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `.\Reecon\build.bat`  
3.) Run `.\Reecon\build\Reecon.exe`  
4.) Optional: Move the `Reecon.exe` file to wherever you want  
5.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone
