# Reecon

Reelix's Recon - A small program for network recon.  
This program is still in early stages of development and should probably not be used by anyone.
* Version: 0.34g
* Build Status: <img src="https://img.shields.io/github/actions/workflow/status/Reelix/Reecon/dotnet-publish.yml" valign="middle" />
* Requirements: [NMap 7.95+](https://nmap.org/download.html)
  * LDAP Enumeration on Ubuntu 22.04: Download + dpkg -i [this](https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download)
* Recommended (It won't run these, but it will suggest that you do):
  * Manual HTTP/S Enumeration: [Gobuster](https://github.com/OJ/gobuster)
  * SMB Enumeration: [smbclient](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)
  * Kerberos Enumeration: [Kerbrute](https://github.com/ropnop/kerbrute), [GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py), [secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
  * Multiple Enumerations: [NetExec](https://github.com/Pennyw0rth/NetExec)
  * Printer Enumeration: [PRET](https://github.com/RUB-NDS/PRET)

## Frequently Asked Questions
### WTF - Why is it 30MB? That's huge!
It's standalone with parts of the .NET Framework built in. It runs on the device without any other requirements. No additional Framework is required if you're not self-compiling.
That said, I'm always trying to make it smaller (Working on cross-OS trimming and reducing third-party libraries)
### It broke
It is still in the early stages of development. Tell me how it broke, and I'll see if I can fix it.
### You should add XYZ
If it sounds cool, I'll try :)

## Installation Instructions
### Linux (x64)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-x64
### Windows (x64)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/Reecon-windows.exe
### Linux (musl - x64 - Probably Alpine)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-musl-x64
### Linux (armx64 / aarch64 - Is this the future?)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-arm64

## Build Setup
### Linux (Ubuntu 22.10 and above)
sudo apt update  
sudo apt upgrade  
sudo apt install dotnet-sdk-8.0 -y
### Linux (Other)
If you're running this, you probably know how to get the dotnet SDK installed. If not, start [here](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) (SDK 8.0.100)

## Build Instructions
1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `chmod +x ./Reecon/build && ./Reecon/build`  
3.) Run: `./reecon`  
4.) Optional: Move `./reecon` into `/usr/local/bin/reecon` to be able to run `reecon` from anywhere  
5.) Optional: You can remove the `./Reecon` folder if you want - The binary is standalone

### Windows  
1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `.\Reecon\build.bat`  
3.) Run `.\Reecon\build\Reecon.exe`  
4.) Optional: Move the `Reecon.exe` file to wherever you want  
5.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone

## To Do (No specific order)
- Fix the usage of WebClient in WinRM.cs to remove obsoletion errors
- Raw nslookup in DNS.cs (Better cross platform / How does it work on a lower level?)
- Raw RPC info (rpcinfo on for port 111, find service / version on ports) - https://svn.nmap.org/nmap/scripts/rpcinfo.nse - Oh gawd
- Remove reliance on OS-specific tooling (showmount, smbclient, rpcinfo (111) / rpcclient (lol), etc.)
- Fix rare instances of accessing broken https:// pages (Invalid cert?)
- Fix broken OSINT scripts (Twitter?)
- Split OSINT into more files for cleaner code
- Raw MySQL connection to replace reliance on the MySqlConnector Lib (Only basic auth is fine for now - Don't need the entire framework!)
- MSSQL handshake for version retrieval
- Retrieve RDP Info (See nmap -sC -sV output)
- Implement basic MQTT handlers (Enough to get enough info to solve https://tryhackme.com/room/bugged)
- Custom multi-threaded SYN Scan port scanner to remove nmap reliance (Won't happen any time soon)
- Split Web into more files for cleaner code
- Make the README.md file a bit more legible
- Fix Pwn.cs to be slightly usable (On Windows?)
