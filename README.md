# Reecon

Reelix's Recon - A small program for network recon. This program is still in early stages of development and should probably not be used by anyone.
* Version: 0.30
* Build Status: <img src = "https://travis-ci.com/Reelix/Reecon.svg?branch=master" valign="middle" />
* Requirements: [NMap 7.92+](https://nmap.org/download.html), [.NET 6.0](https://dotnet.microsoft.com/download/dotnet/6.0)
  * LDAP Enumeration on Ubuntu 22.04: Download + dpkg -i [this](https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download)
* Recommended:
  * HTTP/S Enumeration: [Gobuster](https://github.com/OJ/gobuster)
  * SMB Enumeration: [smbclient](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)
  * Kerberos Enumeration: [Kerbrute](https://github.com/ropnop/kerbrute), [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py), [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
  * Printer Enumeration: [PRET](https://github.com/RUB-NDS/PRET)

## Installation Instructions (No Building)
### Linux (x64 - Requires the .NET 6 Runtime)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-x64
### Windows (x64)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/Reecon-windows.exe
### Linux (musl - x64 - Probably Alpine)
- Download + Run https://github.com/Reelix/Reecon/releases/download/latest/reecon-linux-musl-x64

## Build Instructions
### Linux (Ubuntu 22.04)
sudo apt update
sudo apt install dotnet-runtime-6.0

### Linux (Ubuntu < 22.04)
#### Install repository configuration
curl -sSL https://packages.microsoft.com/config/ubuntu/22.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft-prod.list

#### Install Microsoft GPG public key
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc

#### Update package index files
sudo apt-get update

### Install the dotnet runtime
sudo apt install dotnet-runtime-6.0  

1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `chmod +x ./Reecon/build && ./Reecon/build`  
3.) Run: `./reecon`  
4.) Optional: Move `./reecon` into `/usr/local/bin/reecon` to be able to run `reecon` from anywhere  
5.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone

### Windows  
1.) Clone the repo: `git clone https://github.com/Reelix/Reecon.git`  
2.) Run the build file: `.\Reecon\build.bat`  
3.) Run `.\Reecon\build\Reecon.exe`  
4.) Optional: Move the `Reecon.exe` file to wherever you want  
5.) Optional: You can remove the `Reecon` folder if you want - The binary is standalone
