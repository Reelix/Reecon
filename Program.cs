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
        static string ip = "";
        static readonly List<Thread> threadList = new List<Thread>();
        static void Main(string[] args)
        {
            DateTime startDate = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Reecon - Version 0.07a ( https://github.com/reelix/reecon )");
            Console.ForegroundColor = ConsoleColor.White;
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: reecon IP");
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

                return;
            }
            if (args.Length == 0 && ip.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Needs an IP!");
                return;
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
            Console.WriteLine("Checking if host is online...");
            bool isHostOnline = General.IsUp(ip);
            General.ClearPreviousConsoleLine();
            if (!isHostOnline)
            {
                Console.WriteLine("Host is not responding to pings :(");
                return;
            }

            if (portList.Count != 0)
            {
                ParsePorts("portlist");
            }
            else
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
            foreach (Thread theThread in threadList)
            {
                theThread.Join();
            }
            Console.WriteLine("Finished - Some things you probably want to do: ");
            Console.WriteLine("- nmap -sC -sV -p" + string.Join(",", portList) + " " + ip + " -oN nmap.txt");
            if (portList.Contains(21))
            {
                Console.WriteLine("- Check out Port 21 for things I missed");
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
            }
            DateTime endDate = DateTime.Now;
            TimeSpan t = endDate - startDate;
            Console.WriteLine("Done in " + string.Format("{0:0.00}s", t.TotalSeconds) + " - Have fun :)");
            Console.ResetColor();
        }

        static void RunNMap(int level)
        {
            Console.WriteLine($"Starting a Level {level} Nmap on IP {ip}");
            using (Process p = new Process())
            {
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.FileName = "nmap";
                if (level == 1)
                {
                    p.StartInfo.Arguments = $"{ip} -F -oG nmap-fast.txt";
                }
                else if (level == 2)
                {
                    p.StartInfo.Arguments = $"{ip} -oG nmap-normal.txt";
                }
                else if (level == 3)
                {
                    p.StartInfo.Arguments = $"{ip} -p- -oG nmap-slow.txt -oN nmap-all.txt";
                }
                p.Start();
                p.WaitForExit();
            }
        }

        static void ParsePorts(string fileName)
        {
            if (fileName == "portlist")
            {
                foreach (int port in portList)
                {
                    Thread myThread = new Thread(() => ScanPort(port));
                    threadList.Add(myThread);
                    myThread.Start();
                }
                return;
            }

            StreamReader sr1 = new StreamReader(fileName);
            string[] fileLines = sr1.ReadToEnd().Split(new[] { Environment.NewLine }, StringSplitOptions.None);
            sr1.Close();
            File.Delete(fileName);
            if (fileLines[1].Contains("0 hosts up"))
            {
                Console.WriteLine("Error - Host is down :(");
                Environment.Exit(0);
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
                        Thread myThread = new Thread(() => ScanPort(port));
                        threadList.Add(myThread);
                        myThread.Start();
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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0042:Deconstruct variable declaration")]
        static void ScanPort(int port)
        {
            // Console.WriteLine("Found Port: " + port);
            if (port == 21)
            {
                string ftpLoginInfo = FTP.FtpLogin2(ip);
                if (ftpLoginInfo.Contains("Unable to login: This FTP server is anonymous only.") || ftpLoginInfo.Contains("Unable to login: USER: command requires a parameter") || ftpLoginInfo.Contains("Unable to login: Login with USER first.") || ftpLoginInfo.Contains("530 This FTP server is anonymous only."))
                {
                    ftpLoginInfo = FTP.FtpLogin2(ip, "anonymous", "");
                }
                Console.WriteLine("Port 21 - FTP" + ftpLoginInfo);
            }
            else if (port == 22)
            {
                string port22Result = "Port 22 - SSH";
                string sshVersion = SSH.GetVersion(ip);
                string authMethods = SSH.GetAuthMethods(ip, port);
                Console.WriteLine(port22Result + Environment.NewLine + "- SSH Version: " + (sshVersion ?? "Unknown") + Environment.NewLine + "- Authentication Methods: " + (authMethods ?? "Unknown"));

            }
            else if (port == 25)
            {
                string port22Result = "Port 25 - SMTP";

                string theBanner = General.BannerGrab(ip, port);
                // 220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 19 Oct 2019 16:02:49 +0200
                if (theBanner.StartsWith("220") && theBanner.Contains("ESMTP"))
                {
                    theBanner = theBanner.Remove(0, 4);
                    string serverName = theBanner.Substring(0, theBanner.IndexOf(" ESMTP"));
                    string nameAndDate = theBanner.Remove(0, theBanner.IndexOf(" ESMTP") + 7); // Remove the space afterwards
                    Console.WriteLine(port22Result + Environment.NewLine + "- Server: " + serverName + Environment.NewLine + "- Name And Date: " + nameAndDate);
                }
                else
                {
                    Console.WriteLine("- Unknown Banner: " + theBanner);
                }

            }
            else if (port == 53)
            {
                string port53result = "Port 53 - DNS" + Environment.NewLine + " - Reecon currently lacks DNS Support :(" + Environment.NewLine;
                Console.WriteLine(port53result);
            }
            else if (port == 80)
            {
                string port80result = "Port 80 - HTTP";
                // RunGoBuster()
                HTTP myHTTP = new HTTP();
                var httpInfo = myHTTP.GetHTTPInfo(ip, 80, false);
                string portData = myHTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                if (portData != null)
                {
                    Console.WriteLine(port80result + portData + Environment.NewLine);
                    // Console.WriteLine(port80result + portData);
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
                IPHostEntry entry = Dns.GetHostEntry(ip);
                if (entry != null)
                {
                    if (!string.IsNullOrEmpty(entry.HostName))
                    {
                        port139result += "- HostName: " + entry.HostName + Environment.NewLine;
                    }
                }
                port139result += "- nmap -sC -sV has far more info for this port" + Environment.NewLine;
                Console.WriteLine(port139result);
            }
            else if (port == 143)
            {
                string port143result = "Port 143 - imap (Internet Message Access Protocol)" + Environment.NewLine;
                string banner = General.BannerGrab(ip, 143);
                Console.WriteLine(port143result + "- " + banner + Environment.NewLine);
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
                HTTP myHTTP = new HTTP();
                var httpsInfo = myHTTP.GetHTTPInfo(ip, 443, true);
                string portData = myHTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);
                Console.WriteLine(port443Result + portData + Environment.NewLine);
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
            else if (port == 2049)
            {
                Console.WriteLine("Port 2049 - nfs" + Environment.NewLine + "- Reecon currently lacks nfs (Network File System) support - Check the output at the bottom" + Environment.NewLine);
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
            else
            {
                // Try parse the banner
                string theBanner = General.BannerGrab(ip, port);

                string unknownPortResult = "Port " + port;

                // 220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 19 Oct 2019 16:02:49 +0200
                if (theBanner.StartsWith("220") && theBanner.Contains("ESMTP"))
                {
                    unknownPortResult += " - SMTP";
                    string  smtpHost = theBanner.Remove(0, 4); // Split host and version name - How with the date though?
                    unknownPortResult += Environment.NewLine + smtpHost;
                    Console.WriteLine(unknownPortResult);

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
                    || theBanner.StartsWith("HTTP/1.1 400 Bad Request") // Unknown but valid request
                    || theBanner.StartsWith("HTTP/1.0 200 Document follows") // Silly HTTP/1.0
                    || theBanner.Contains("Error code explanation: 400 = Bad request syntax or unsupported method.") // BaseHTTP/0.3 Python/2.7.12
                    ) // Probably HTTP or HTTPS
                {
                    string portData = "";
                    // Try HTTP
                    string httpData = "";
                    string httpsData = "";
                    HTTP myHTTP = new HTTP();
                    var httpInfo = myHTTP.GetHTTPInfo(ip, port, false);
                    if (httpInfo != (new HttpStatusCode(), null, null, null, null))
                    {
                        httpData = unknownPortResult + " - HTTP" + myHTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                    }
                    // Try HTTPS
                    var httpsInfo = myHTTP.GetHTTPInfo(ip, port, true);
                    httpsData = unknownPortResult + " - HTTPS" + myHTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);

                    portData = (string.IsNullOrEmpty(httpData) ? "" : httpData + Environment.NewLine + Environment.NewLine) + httpsData + Environment.NewLine;
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
                else if (theBanner == "Reecon - Connection reset by peer")
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Connection reset by peer (No Useful response)");
                }
                else if (theBanner == "Reecon - Closed")
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Port is closed");
                }
                else if (theBanner.Length == 0)
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- No Banner Response");
                }
                else
                {
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Unknown Banner Response: -->" + theBanner + "<--");
                }
            }
        }


    }
}
