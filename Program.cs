using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace Reecon
{
    class Program
    {
        static readonly List<int> portList = new List<int>();
        static string ip = ""; // For Dev
        static readonly List<Thread> threadList = new List<Thread>();
        static void Main(string[] args)
        {
            DateTime startDate = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Reecon - Version 0.11 ( https://github.com/reelix/reecon )");
            Console.ForegroundColor = ConsoleColor.White;
            if (args.Length == 0 && ip.Length == 0)
            {
                Console.WriteLine("Usage");
                Console.WriteLine("-----");
                Console.WriteLine("Basic Scan:\tReecon IPHere (Optional: -noping to skip the ping - Not recommended!)");
                Console.WriteLine("NMap:\t\tReecon -nmap IP FileName");
                Console.WriteLine("NMap-Load Scan:\tReecon outfile.nmap (Requires a -nmap scan or -oG on regular nmap");
                Console.WriteLine("SMB Brute:\tReecon -smb-brute (Linux Only)");
                Console.WriteLine("WinRM Brute:\tReecon -winrm-brute (Windows Only - Requires an Administrative Console)");
                Console.WriteLine("LFI Test:\tReecon -lfi (Does not work)");
                Console.ResetColor();
                return;
            }
            if (args.Contains("-lfi"))
            {
                if (args.Length != 2)
                {
                    Console.WriteLine("LFI Usage: reecon -lfi PossibleLFIPath");
                }
                Console.WriteLine("Starting LFI Scan - This feature is still in Alpha");
                LFI.Scan(args[1]);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-smb-brute"))
            {
                SMB.SMBBrute(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-winrm-brute"))
            {
                // TODO: gpedit.msc to add the host for winrm to allow Windows to scan
                // Local Computer Policy -> Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> Trusted Hosts
                WinRM.WinRMBrute(args);
                Console.ResetColor();
                return;
            }
            bool mustPing = true;
            if (args.Contains("-noping"))
            {
                mustPing = false;
            }
            else if (ip.Length == 0 && args.Length > 0)
            {
                if (args[0].Trim().Length == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Needs an IP!");
                    return;
                }
                ip = args[0];
                if (ip.EndsWith(".nmap"))
                {
                    ParsePorts(ip, false);
                }
                if (args.Length > 1)
                {
                    portList.AddRange(args[1].Split(',').ToList().Select(x => int.Parse(x)));
                }
                Console.Write("Scanning: " + ip);
                if (portList.Count != 0)
                {
                    Console.Write(" (Port");
                    if (portList.Count > 1)
                    {
                        Console.Write("s");
                    }
                    Console.WriteLine(": " + string.Join(",", portList) + ")");
                }
                else
                {
                    Console.WriteLine();
                }
            }
            else
            {
                Console.WriteLine("Hard Coded IP - Dev Mode!");
                Console.WriteLine("Scanning: " + ip);
            }
            if (mustPing)
            {
                Console.WriteLine("Checking if host is online...");
                bool isHostOnline = General.IsUp(ip);
                General.ClearPreviousConsoleLine();

                if (!isHostOnline)
                {
                    Console.WriteLine("Host is not responding to pings :(");
                    Console.WriteLine("If you are sure it's up and are specifying ports, you can use -noping");
                    return;
                }
            }

            if (portList.Count == 0)
            {
                // Cleanup from any previous runs
                if (File.Exists("nmap-fast.txt"))
                {
                    File.Delete("nmap-fast.txt");
                }
                if (File.Exists("nmap-normal.txt"))
                {
                    File.Delete("nmap-normal.txt");
                }
                /*
                if (File.Exists("nmap-slow.txt"))
                {
                    File.Delete("nmap-slow.txt");
                }
                if (File.Exists("nmap-all.txt"))
                {
                    File.Delete("nmap-all.txt");
                }*/

                // After each list is parsed, the file gets deleted.
                RunNMap(1);
                ParsePorts("nmap-fast.txt");
                RunNMap(2);
                ParsePorts("nmap-normal.txt");
                /*
                Console.WriteLine("Running a Level 3 NMap - This could take awhile");
                RunNMap(3);
                // This generates 2 files 
                ParsePorts("nmap-slow.txt");
                */
            }

            // All files and params parsed - Scanning time!
            if (portList.Count == 0)
            {
                Console.WriteLine("No open ports found to scan :<");
                return;
            }
            else
            {
                ScanPorts(portList);
            }

            // Wait for the ScanPorts thread list to finish
            foreach (Thread theThread in threadList)
            {
                theThread.Join();
            }

            // Everything done - Now for some helpful info!
            Console.WriteLine("Finished - Some things you probably want to do: ");
            if (portList.Count == 0)
            {
                Console.WriteLine("- nmap -sC -sV -p- " + ip + " -oN nmap.txt");
            }
            else
            {
                Console.WriteLine("- nmap -sC -sV -p" + string.Join(",", portList) + " " + ip + " -oN nmap.txt");
                if (portList.Contains(21))
                {
                    Console.WriteLine("- Check out Port 21 for things I missed");
                }
                if (portList.Contains(53))
                {
                    Console.WriteLine("- Try a zone transfer (Linux): dig axfr domain.com @" + ip);
                }
                if (portList.Contains(80))
                {
                    Console.WriteLine("- gobuster dir -u=http://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-http.txt -x.php,.txt");
                }
                if (portList.Contains(139))
                {
                    // https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions

                    Console.WriteLine("- rpcclient -U \"\" " + ip);
                    Console.WriteLine("-> enumdomusers");
                    Console.WriteLine("--> queryuser usernameHere");
                }
                if (portList.Contains(443))
                {
                    Console.WriteLine("- gobuster dir -u=https://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-https.txt -x.php,.txt");
                }
                if (portList.Contains(445))
                {
                    Console.WriteLine("- smbclient -L " + ip);
                    Console.WriteLine("- nmap --script smb-enum-shares.nse -p445 " + ip);
                }
                if (portList.Contains(2049))
                {
                    Console.WriteLine("- rpcinfo -p " + ip);
                    Console.WriteLine("- showmount -e " + ip);
                    Console.WriteLine("-> mount -t nfs -o vers=2 " + ip + ":/mountNameHere /mnt");
                }
            }
            DateTime endDate = DateTime.Now;
            TimeSpan t = endDate - startDate;
            Console.WriteLine("Done in " + string.Format("{0:0.00}s", t.TotalSeconds) + " - Have fun :)");
            Console.ResetColor();
        }

        static void RunNMap(int level)
        {
            Console.WriteLine($"Starting a Level {level} Nmap on IP {ip}");
            if (level == 1)
            {
                // -F = Fast (100 Most Common Ports)
                General.RunProcess("nmap", $"{ip} -sS -F --min-rate=100 -oG nmap-fast.txt");
            }
            else if (level == 2)
            {
                // Top 1,000 Ports (Excl. Top 100?)
                General.RunProcess("nmap", $"{ip} -sS --min-rate=500 -oG nmap-normal.txt");
            }
            else if (level == 3)
            {
                // -p- = All Ports
                General.RunProcess("nmap", $"{ip} -sS -p- --min-rate=5000 -oG nmap-slow.txt");
            }
        }

        // Parses an -oG nmap file for ports
        static void ParsePorts(string fileName, bool deleteFile = true)
        {
            // Console.WriteLine("Parsing: " + fileName);
            StreamReader sr1 = new StreamReader(fileName);
            string[] fileLines = sr1.ReadToEnd().Split(new[] { Environment.NewLine }, StringSplitOptions.None);
            sr1.Close();
            if (deleteFile)
            {
                File.Delete(fileName);
            }
            // fileLines[1]: Host: 10.10.10.175 ()   Status: Up
            ip = fileLines[1].Split(' ')[1];
            if (fileLines[1].Contains("0 hosts up"))
            {
                Console.WriteLine("Error - Host is down :(");
                Environment.Exit(0);
            }
            if (!fileLines[2].Contains("/open/"))
            {
                Console.WriteLine("No open ports found");
                return;
            }
            string portLine = fileLines[2];
            string portSection = portLine.Split('\t')[1];
            portSection = portSection.Replace("Ports: ", "");
            foreach (var item in portSection.Split(new[] { ", " }, StringSplitOptions.None))
            {
                int port = int.Parse(item.Split('/')[0]);
                string status = item.Split('/')[1];
                if (status == "open")
                {
                    if (!portList.Contains(port))
                    {
                        portList.Add(port);
                    }
                }
                else
                {
                    if (!portList.Contains(port))
                    {
                        portList.Add(port);
                        Console.WriteLine("Unknown Status: " + port + " -> " + status);
                    }
                }
            }
        }

        // Multithreaded port scan
        static void ScanPorts(List<int> portList)
        {
            foreach (int port in portList)
            {
                Thread myThread = new Thread(() => ScanPort(port));
                threadList.Add(myThread);
                myThread.Start();
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0042:Deconstruct variable declaration")]
        static void ScanPort(int port)
        {
            // Console.WriteLine("Found Port: " + port);
            if (port == 21)
            {
                string ftpUsername = "";
                string ftpLoginInfo = FTP.FtpLogin(ip, ftpUsername);
                if (ftpLoginInfo.Contains("Unable to login: This FTP server is anonymous only.") || ftpLoginInfo.Contains("Unable to login: USER: command requires a parameter") || ftpLoginInfo.Contains("Unable to login: Login with USER first.") || ftpLoginInfo.Contains("530 This FTP server is anonymous only."))
                {
                    ftpUsername = "anonymous";
                    ftpLoginInfo = FTP.FtpLogin(ip, ftpUsername, "");
                }
                if (ftpLoginInfo.Contains("Anonymous login allowed"))
                {
                    string fileListInfo = FTP.TryListFiles(ip, true, ftpUsername, "");
                    if (fileListInfo.Contains("invalid pasv_address"))
                    {
                        fileListInfo = FTP.TryListFiles(ip, false, ftpUsername, "");

                    }
                    if (!fileListInfo.StartsWith(Environment.NewLine))
                    {
                        fileListInfo = Environment.NewLine + fileListInfo;
                    }
                    ftpLoginInfo += fileListInfo;
                }
                Console.WriteLine("Port 21 - FTP" + ftpLoginInfo + Environment.NewLine);
            }
            else if (port == 22)
            {
                string port22Result = "Port 22 - SSH";
                string sshVersion = SSH.GetVersion(ip);
                string authMethods = SSH.GetAuthMethods(ip, port);
                Console.WriteLine(port22Result + Environment.NewLine + "- SSH Version: " + (sshVersion ?? "Unknown") + Environment.NewLine + "- Authentication Methods: " + (authMethods ?? "Unknown") + Environment.NewLine);

            }
            else if (port == 25)
            {
                string port25Result = "Port 25 - SMTP";
                string smtpInfo = SMTP.GetInfo(ip, 25);
                Console.WriteLine(port25Result + Environment.NewLine + smtpInfo + Environment.NewLine);

            }
            else if (port == 53)
            {
                // TODO: https://svn.nmap.org/nmap/scripts/dns-nsid.nse
                string port53result = "Port 53 - DNS";// + Environment.NewLine + " - Reecon currently lacks DNS Support :(" + Environment.NewLine;
                string dnsInfo = DNS.GetInfo(ip);
                Console.WriteLine(port53result + Environment.NewLine + dnsInfo + Environment.NewLine);
            }
            else if (port == 80)
            {
                string port80result = "Port 80 - HTTP";
                // RunGoBuster()
                var httpInfo = HTTP.GetHTTPInfo(ip, 80, false);
                string portData = HTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                if (portData != null)
                {
                    string robotsFile = HTTP.CheckRobots(ip, 80, false);
                    portData = robotsFile + portData;
                    Console.WriteLine(port80result + Environment.NewLine + portData + Environment.NewLine);
                }
                else
                {
                    Console.WriteLine(port + " -- Woof!" + Environment.NewLine);
                }
            }
            else if (port == 88)
            {
                Console.WriteLine("Port 88 - Microsoft Windows Kerberos" + Environment.NewLine + "- Reecon currently lacks Microsoft Windows Kerberos support" + Environment.NewLine);
            }
            else if (port == 110)
            {
                string port110result = "Port 110 - pop3" + Environment.NewLine;
                port110result += POP3.GetInfo(ip);
                Console.WriteLine(port110result + Environment.NewLine);

            }
            else if (port == 135)
            {
                Console.WriteLine("Port 135 - Microsoft Windows RPC" + Environment.NewLine + "- Reecon currently lacks Microsoft Windows RPC support" + Environment.NewLine);
            }
            else if (port == 139)
            {
                string port139result = "Port 139 - Microsoft Windows netbios-ssn" + Environment.NewLine;
                // TODO: https://dzone.com/articles/practical-fun-with-netbios-name-service-and-comput
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(ip);
                    if (entry != null)
                    {
                        if (!string.IsNullOrEmpty(entry.HostName))
                        {
                            port139result += "- HostName: " + entry.HostName + Environment.NewLine;
                        }
                    }
                }
                catch (Exception ex)
                {
                    port139result += "- Unable to get GNSHostEntry: " + ex.Message + Environment.NewLine;
                }
                port139result += "- nmap -sC -sV has far more info for this port" + Environment.NewLine;
                Console.WriteLine(port139result);
            }
            else if (port == 143)
            {
                string port143result = "Port 143 - imap (Internet Message Access Protocol)" + Environment.NewLine;
                string banner = General.BannerGrab(ip, 143);
                Console.WriteLine(port143result + "- Banner: " + banner + Environment.NewLine);
            }
            else if (port == 389)
            {
                // https://github.com/mono/mono/blob/master/mcs/class/System.DirectoryServices.Protocols/System.DirectoryServices.Protocols/SearchRequest.cs
                // Wow Mono - Just Wow...
                string port389Result = "Port 389 - LDAP";
                try
                {
                    port389Result += LDAP.GetDefaultNamingContext(ip);
                }
                catch (NotImplementedException)
                {
                    port389Result += Environment.NewLine + " - Reecon can get the DefaultNamingContext, but Mono doesn't support it - Try run it on Windows";
                }
                try
                {
                    port389Result += LDAP.GetAccountInfo(ip);
                }
                catch
                {
                    port389Result += Environment.NewLine + " - Reecon can get some account information, but Mono doesn't support it - Try run it on Windows";
                }
                Console.WriteLine(port389Result + Environment.NewLine);
            }
            else if (port == 443)
            {
                string port443Result = "Port 443 - HTTPS";
                // Get SSL Detauls
                var httpsInfo = HTTP.GetHTTPInfo(ip, 443, true);
                string portData = HTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);
                string robotsFile = HTTP.CheckRobots(ip, 443, true);
                portData = robotsFile + portData;
                Console.WriteLine(port443Result + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 445)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string port445Result = "Port 445 - Microsoft SMB";
                    string portData = SMB.TestAnonymousAccess(ip);
                    string morePortData = SMB.TestAnonymousAccess(ip, "anonymous");
                    string evenMorePortData = SMB.TestAnonymousAccess(ip, "anonymous", "anonymous");
                    Console.WriteLine(port445Result + portData + morePortData + ",,, " + evenMorePortData + Environment.NewLine);
                }
                else
                {
                    // TODO: See if I can run smbclient -L \\ip and get the output ?
                    Console.WriteLine("Port 445 - Microsoft SMB " + Environment.NewLine + "- Reecon currently lacks Microsoft SMB support outside Windows" + Environment.NewLine);
                }
            }
            else if (port == 593)
            {
                Console.WriteLine("Port 539 - Microsoft Windows RPC over HTTP" + Environment.NewLine + "- Reecon currently lacks Microsoft Windows RPC over HTTP support" + Environment.NewLine);
            }
            else if (port == 2049)
            {
                string fileList = NFS.GetFileList(ip);
                Console.WriteLine("Port 2049 - NFS (Network File System)" + Environment.NewLine + fileList + Environment.NewLine);
            }
            else if (port == 27017)
            {
                // MonogoDB
                Console.WriteLine("Port 27017 - MongoDB" + Environment.NewLine + "- Reecon currently lacks MongoDB support" + Environment.NewLine);
                // Nmap can get the version - What else can we get?
            }
            else if (port == 3268)
            {
                Console.WriteLine("Port 3268 - Global Catalog" + Environment.NewLine + "- Reecon currently lacks Global Catalog (LDAP) support" + Environment.NewLine);
            }
            else if (port == 3306)
            {
                //MySql 
                string theBanner = General.BannerGrab(ip, port);
                Console.WriteLine("Port 3306 - MySQL" + Environment.NewLine + "- Reecon currently lacks MySQL support" + Environment.NewLine + "- Banner: " + theBanner + Environment.NewLine);
                // https://svn.nmap.org/nmap/scripts/mysql-info.nse
                // --> https://svn.nmap.org/nmap/nselib/mysql.lua -> receiveGreeting
            }
            else if (port == 3389)
            {
                Console.WriteLine("Port 3389 - Windows Remote Desktop" + Environment.NewLine + "- Reecon currently lacks Windows Remote Desktop support" + Environment.NewLine);
            }
            else if (port == 5985)
            {
                // TODO: Figure out how to do basic evil-winrm.rb connections
                // evil-winrm.rb -i 10.10.10.161
                Console.WriteLine("Port 5985 - WinRM" + Environment.NewLine + "- Reecon currently lacks WinRM support" + Environment.NewLine);
            }
            else if (port == 6379)
            {
                string port6379Result = "Port 6379 - Redis";
                port6379Result += Redis.GetInfo("10.10.10.160");
                Console.WriteLine(port6379Result);
            }
            else if (port == 9418)
            {
                Console.WriteLine("Port 9418 - Git" + Environment.NewLine + "- Reecon currently lacks Git support" + Environment.NewLine);
            }
            else if (port == 9200)
            {
                string port9200Result = "Port 9200 - Elasticsearch HTTP Interface" + Environment.NewLine;
                port9200Result += Elasticsearch.GetInfo(ip);
                Console.WriteLine(port9200Result + Environment.NewLine);

            }
            else if (port == 9300)
            {
                Console.WriteLine("Port 9300 - Elasticsearch Communication Port" + Environment.NewLine + "- Check out Port 9200 (Elasticsearch HTTP Interface) - Reecon has info on that" + Environment.NewLine);
            }
            else
            {
                // Try parse the banner
                string theBanner = General.BannerGrab(ip, port);

                string unknownPortResult = "Port " + port;

                // 220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 19 Oct 2019 16:02:49 +0200
                if (theBanner.StartsWith("220") && theBanner.Contains("ESMTP"))
                {
                    unknownPortResult += " - SMTP";
                    string smtpInfo = SMTP.ParseBanner(theBanner);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + smtpInfo + Environment.NewLine);

                }
                else if (theBanner.Contains("SSH-2.0-OpenSSH") || theBanner == "SSH-2.0-Go") // Probably SSH
                {
                    unknownPortResult += " - SSH";
                    if (theBanner.Contains("\r\nProtocol mismatch."))
                    {
                        theBanner = theBanner.Replace("\r\nProtocol mismatch.", "");
                        unknownPortResult += Environment.NewLine + "- TCP Protocol Mismatch";
                    }
                    unknownPortResult += Environment.NewLine + "- SSH Version: " + theBanner;
                    string authMethods = SSH.GetAuthMethods(ip, port);
                    unknownPortResult += Environment.NewLine + "- Auth Methods: " + authMethods;
                    Console.WriteLine(unknownPortResult);
                }
                else if (
                    theBanner.Contains("Server: Apache") // Apache Web Server
                    || theBanner.Contains("Server: cloudflare") // Cloudflare Server
                    || theBanner.StartsWith("HTTP/1.1")
                    || theBanner.StartsWith("HTTP/1.0")
                    || theBanner.Contains("Error code explanation: 400 = Bad request syntax or unsupported method.") // BaseHTTP/0.3 Python/2.7.12
                    || theBanner.Contains("<p>Error code: 400</p>") // TryHackMe - Task 12 Day 7
                    ) // Probably HTTP or HTTPS
                {
                    string portData = "";
                    // Try HTTP
                    string httpData = "";
                    string httpsData = "";
                    string robotsFile = "";
                    var httpInfo = HTTP.GetHTTPInfo(ip, port, false);
                    if (httpInfo != (new HttpStatusCode(), null, null, null, null))
                    {
                        robotsFile = HTTP.CheckRobots(ip, port, false);
                        httpData = unknownPortResult + " - HTTP" + Environment.NewLine;
                        if (robotsFile != "")
                        {
                            httpData += robotsFile + Environment.NewLine;
                        }
                        httpData += HTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                    }
                    // Try HTTPS
                    var httpsInfo = HTTP.GetHTTPInfo(ip, port, true);
                    if (httpsInfo != (new HttpStatusCode(), null, null, null, null))
                    {
                        robotsFile = HTTP.CheckRobots(ip, port, true);
                        httpsData = unknownPortResult + " - HTTPS" + Environment.NewLine;
                        if (robotsFile != "")
                        {
                            httpsData += robotsFile + Environment.NewLine;
                        }
                        httpsData += HTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);
                    }

                    if (!string.IsNullOrEmpty(httpData))
                    {
                        portData += portData + httpData + Environment.NewLine;
                    }
                    if (!string.IsNullOrEmpty(httpsData))
                    {
                        portData += httpsData + httpsData + Environment.NewLine;
                    }
                    Console.WriteLine(portData); // Newlines and title are already included 
                }
                else if (theBanner == "-ERR unknown command 'Woof'") // Probably Redis
                {
                    unknownPortResult += " - Redis";
                    string portData = Redis.GetInfo(ip);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portData + Environment.NewLine);
                }
                else if (theBanner == "+OK Dovecot ready.")
                {
                    unknownPortResult += " - pop3 (Dovecot)" + Environment.NewLine;
                    unknownPortResult += POP3.GetInfo(ip);
                    Console.WriteLine(unknownPortResult);
                }
                else if (theBanner == "ncacn_http/1.0")
                {
                    // Woof
                    unknownPortResult += " - Microsoft Windows RPC over HTTP" + Environment.NewLine;
                    unknownPortResult += " - Reecon currently lacks Microsoft Windows RPC over HTTP support" + Environment.NewLine;
                    Console.WriteLine(unknownPortResult);
                }
                else if (theBanner == "Reecon - Connection reset by peer")
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Connection reset by peer (No Useful response)" + Environment.NewLine);
                }
                else if (theBanner == "Reecon - Closed")
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Port is closed" + Environment.NewLine);
                }
                else if (theBanner.Length == 0)
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- No Banner Response" + Environment.NewLine);
                }
                else
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Unknown Banner Response: -->" + theBanner + "<--");
                }
            }
        }


    }
}
