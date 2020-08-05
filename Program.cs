using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Reecon
{
    class Program
    {
        static readonly List<int> portList = new List<int>();
        static string ip = ""; // For Dev
        static readonly List<Thread> threadList = new List<Thread>();
        public static string postScanActions = "";
        static void Main(string[] args)
        {
            DateTime startDate = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Reecon - Version 0.18 ( https://github.com/Reelix/Reecon )");
            Console.ForegroundColor = ConsoleColor.White;
            if (args.Length == 0 && ip.Length == 0)
            {
                Console.WriteLine("Usage");
                Console.WriteLine("-----");
                Console.WriteLine("Basic Scan:\tReecon IPHere (Optional: -noping to skip the ping - Not recommended!)");
                Console.WriteLine("Display IP:\tReecon -ip");
                Console.WriteLine("NMap:\t\tReecon -nmap IP FileName");
                Console.WriteLine("NMap-Load Scan:\tReecon outfile.nmap (Requires a -nmap scan or -oG on regular nmap)");
                Console.WriteLine("ROPCheck:\tReecon -rop FileName (Very buggy)");
                Console.WriteLine("Searchsploit:\tReecon -searchsploit nameHere (Beta)");
                Console.WriteLine("Shell Gen:\tReecon -shell");
                Console.WriteLine("SMB Brute:\tReecon -smb-brute (Linux Only)");
                Console.WriteLine("SMB Auth Test:\tReecon -smb IP User Pass (Windows Only - Very buggy)");
                Console.WriteLine("WinRM Brute:\tReecon -winrm-brute IP UserList PassList");
                Console.WriteLine("LFI Test:\tReecon -lfi (Very buggy)");
                Console.WriteLine("Web Spider:\tReecon -web url (Very buggy)");
                Console.ResetColor();
                return;
            }
            if (args.Contains("-ip") || args.Contains("--ip"))
            {
                General.GetIP();
                Console.ResetColor();
                return;
            }
            if (args.Contains("-lfi") || args.Contains("--lfi"))
            {
                LFI.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-rop") || args.Contains("--rop"))
            {
                Pwn.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-searchsploit") || args.Contains("--searchsploit"))
            {
                Searchsploit.Search(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-shell") || args.Contains("--shell"))
            {
                Shell.GetInfo(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-smb-brute"))
            {
                SMB.SMBBrute(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-smb"))
            {
                if (args.Length != 4)
                {
                    Console.WriteLine("Usage: -smb ip user pass");
                }
                string ip = args[1];
                string user = args[2];
                string pass = args[3];
                Console.WriteLine(SMB.TestAnonymousAccess(ip, user, pass));
                return;
            }
            else if (args.Contains("-winrm-brute"))
            {
                WinRM.WinRMBrute(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-web") || args.Contains("--web"))
            {
                Web.GetInfo(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-nmap") || args.Contains("--nmap"))
            {
                ip = args[1];
                string fileName = args[2];
                DateTime beforeNmapDate = DateTime.Now;
                Console.WriteLine("Doing an optimized Nmap scan on " + ip + " - This may take awhile...");
                General.RunProcess("nmap", "-sS -p- --min-rate=5000 " + ip + " -oG " + fileName + ".nmap -oN " + fileName + ".txt");
                DateTime afterNmapDate = DateTime.Now;
                TimeSpan nmapScanDuration = afterNmapDate - beforeNmapDate;
                Console.WriteLine("Scan complete in " + string.Format("{0:0.00}s", nmapScanDuration.TotalSeconds) + " - " + fileName + ".nmap for reecon and " + fileName + ".txt for reading");
                return;
            }
            bool mustPing = true;
            if (args.Contains("-noping") || args.Contains("--noping"))
            {
                mustPing = false;
            }
            if (ip.Length == 0 && args.Length > 0)
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
                else if (args.Length > 1)
                {
                    portList.AddRange(args[1].Split(',').ToList().Select(x => int.Parse(x)));
                }
            }
            else
            {
                Console.WriteLine("Hard Coded IP - Dev Mode!");
                Console.WriteLine("Scanning: " + ip);
                if (ip.EndsWith(".nmap"))
                {
                    ParsePorts(ip, false);
                }
            }

            // First check if it's actually up
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

            // Everything parsed - Down to the scanning!
            if (portList.Count != 0)
            {
                Console.Write("Scanning: " + ip);
                // User defined ports - Only scan them
                Console.Write(" (Port");
                if (portList.Count > 1)
                {
                    Console.Write("s");
                }
                Console.WriteLine(": " + string.Join(",", portList) + ")");
                ScanPorts(portList);
            }
            else
            {
                // No user defined ports - Default scan
                Console.WriteLine("Scanning: " + ip);

                // Cleanup from any previous broken runs
                if (File.Exists("nmap-fast.txt"))
                {
                    File.Delete("nmap-fast.txt");
                }
                if (File.Exists("nmap-normal.txt"))
                {
                    File.Delete("nmap-normal.txt");
                }

                // After each list is parsed, the file gets deleted.
                // Except for 3, which leaves a human-readable nmap-all.txt
                RunNMap(1);
                List<int> newPorts = ParsePorts("nmap-fast.txt");
                ScanPorts(newPorts);

                RunNMap(2);
                newPorts = ParsePorts("nmap-normal.txt");
                ScanPorts(newPorts);

                RunNMap(3);
                newPorts = ParsePorts("nmap-slow.txt");
                ScanPorts(newPorts);
            }

            if (portList.Count == 0)
            {
                // All scans done - But still no ports
                Console.WriteLine("No open ports found to scan :<");
                return;
            }

            // Everything done - Now for some helpful info!
            Console.WriteLine("Finished - Some things you probably want to do: ");
            if (portList.Count == 0)
            {
                Console.WriteLine("- nmap -sC -sV -p- " + ip + " -oN nmap.txt");
            }
            else
            {
                postScanActions += "- nmap -sC -sV -p" + string.Join(",", portList) + " " + ip + " -oN nmap.txt";
                if (portList.Contains(21))
                {
                    Console.WriteLine("- Check out Port 21 for things I missed");
                }
                if (portList.Contains(2049))
                {
                    Console.WriteLine("- rpcinfo -p " + ip);
                    Console.WriteLine("- showmount -e " + ip);
                    Console.WriteLine("-> mount -t nfs -o vers=2 " + ip + ":/mountNameHere /mnt");
                }
                Console.WriteLine(postScanActions);
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
                General.RunProcess("sudo", $"nmap {ip} -sS -F --min-rate=50 -oG nmap-fast.txt");
            }
            else if (level == 2)
            {
                // Top 1,000 Ports (Excl. Top 100?)
                General.RunProcess("sudo", $"nmap {ip} -sS --min-rate=500 -oG nmap-normal.txt");
            }
            else if (level == 3)
            {
                // -p- = All Ports
                General.RunProcess("sudo", $"nmap {ip} -sS -p- --min-rate=5000 -oG nmap-slow.txt -oN nmap-all.txt");
            }
        }

        // Parses an -oG nmap file for ports and scans the results
        static List<int> ParsePorts(string fileName, bool deleteFile = true)
        {
            List<int> returnList = new List<int>();
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
                return returnList;
            }
            string portLine = fileLines[2];
            string[] portItems = portLine.Split('\t');
            string portSection = portItems[1];
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
                        returnList.Add(port);
                    }
                }
                else
                {
                    if (status == "closed")
                    {
                        // Closed - Add it to the found list, but skip it
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
            return returnList;
        }

        static void ScanPorts(List<int> portList)
        {
            // Multi-threaded scan
            foreach (int port in portList)
            {
                Thread myThread = new Thread(() => ScanPort(port));
                threadList.Add(myThread);
                myThread.Start();
            }

            // Wait for the scans to finish
            foreach (Thread theThread in threadList)
            {
                theThread.Join();
            }

            // And clear the thread list
            threadList.Clear();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0042:Deconstruct variable declaration")]
        static void ScanPort(int port)
        {
            // Console.WriteLine("Found Port: " + port);
            if (port == 21)
            {
                string portHeader = "Port 21 - FTP";
                string portData = FTP.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 22)
            {
                string portHeader = "Port 22 - SSH";
                string portData = SSH.GetInfo(ip, 22);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

            }
            else if (port == 23)
            {
                string portHeader = "Port 23 - Telnet";
                string portData = "- Just telnet in - Bug Reelix to update this though...";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 25)
            {
                string portHeader = "Port 25 - SMTP";
                string portData = SMTP.GetInfo(ip, 25);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

            }
            else if (port == 53)
            {
                // TODO: https://svn.nmap.org/nmap/scripts/dns-nsid.nse
                string portHeader = "Port 53 - DNS";
                string portData = DNS.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += "- Try a reverse lookup (Linux): dig @" + ip + " -x " + ip + Environment.NewLine;
                postScanActions += "- Try a zone transfer (Linux): dig axfr domain.com @" + ip + Environment.NewLine;
            }
            else if (port == 80)
            {
                string port80result = "Port 80 - HTTP";
                string portData = HTTP.GetInfo(ip, 80, false);
                // Can't do it in the class since it's also used for non-standard HTTP ports
                // Might need to refactor
                if (portData == "")
                {
                    portData = "- Are you sure the port is open?";
                }
                Console.WriteLine(port80result + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += "- gobuster dir -u=http://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-http-medium.txt -x.php,.txt" + Environment.NewLine;
                postScanActions += "- gobuster dir -u=http://" + ip + "/ -w ~/wordlists/common.txt -t 25 -o gobuster-http-common.txt -x.php,.txt" + Environment.NewLine;

            }
            else if (port == 88)
            {
                string portHeader = "Port 88 - Microsoft Windows Kerberos";
                string portData = "- Reecon currently lacks Microsoft Windows Kerberos support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

                // Post Scan
                string defaultNamingContext = LDAP.GetDefaultNamingContext(ip, true);
                defaultNamingContext = defaultNamingContext.Replace("DC=", "").Replace(",", ".");

                // Username enum
                postScanActions += "- Kerberos Username Enum: kerbrute userenum --dc " + defaultNamingContext + "/ -d " + ip + " users.txt" + Environment.NewLine;

                // Requests TGT (Ticket Granting Tickets) for users
                postScanActions += "- Kerberos TGT Request: sudo GetNPUsers.py " + defaultNamingContext + "/" + " -dc-ip " + ip + " -request" + Environment.NewLine;

                // Test for users with 'Do not require Kerberos preauthentication'
                postScanActions += "- Kerberos non-preauth: sudo GetNPUsers.py " + defaultNamingContext + "/ -usersfile sampleUsersHere.txt -dc-ip " + ip + Environment.NewLine;

                // Post exploitation
                postScanActions += "- If you get details: python3 secretsdump.py usernameHere:\"passwordHere\"@" + ip + " | grep :" + Environment.NewLine;
            }
            else if (port == 110)
            {
                string portHeader = "Port 110 - pop3";
                string portData = POP3.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

            }
            else if (port == 111)
            {
                // TODO: Refactor
                string port111result = "Port 111 - rpcbind";
                List<string> processOutput = General.GetProcessOutput("rpcinfo", "-p " + ip);
                string rpcOutput = "";
                foreach (string item in processOutput)
                {
                    rpcOutput += "- " + item + Environment.NewLine;
                }
                Console.WriteLine(port111result + Environment.NewLine + rpcOutput + Environment.NewLine);
            }
            else if (port == 135)
            {
                string portHeader = "Port 135 - Microsoft Windows RPC";
                string portData = "- Reecon currently lacks Microsoft Windows RPC support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 139)
            {
                string portHeader = "Port 139 - NETBIOS Session Service (netbios-ssn)";
                string portData = NETBIOS.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 143)
            {
                string portHeader = "Port 143 - IMAP (Internet Message Access Protocol)";
                string portData = IMAP.GetInfo(ip, 143);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 389)
            {
                // https://github.com/mono/mono/blob/master/mcs/class/System.DirectoryServices.Protocols/System.DirectoryServices.Protocols/SearchRequest.cs
                // Wow Mono - Just Wow...
                string portHeader = "Port 389 - LDAP (Plain Text)";
                string portData = LDAP.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 443)
            {
                string portHeader = "Port 443 - HTTPS";
                string portData = HTTP.GetInfo(ip, 443, true);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += "- gobuster dir -u=https://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-https-medium.txt -x.php,.txt" + Environment.NewLine;
                postScanActions += "- gobuster dir -u=https://" + ip + "/ -w ~/wordlists/common -t 25 -o gobuster-https-common.txt -x.php,.txt" + Environment.NewLine;
            }
            else if (port == 445)
            {
                string portHeader = "Port 445 - Microsoft SMB";
                string portData = SMB.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                if (General.GetOS() == General.OS.Windows)
                {
                    postScanActions = "- Port 445 - Linux (SMBClient) has better info on this: smbclient -L " + ip + " --no-pass" + Environment.NewLine;
                }
            }
            else if (port == 464)
            {
                string portHeader = "Port 464 - Kerberos (kpasswd)";
                string portData = "- Reecon currently lacks Kerberos support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 593)
            {
                string portHeader = "Port 539 - Microsoft Windows RPC over HTTP";
                string portData = "- Reecon currently lacks Microsoft Windows RPC over HTTP support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 636)
            {
                string portHeader = "Port 636 - LDAP over SSL";
                string portData = "- Reecon currently lacks LDAP over SSL support - Check port 389";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 873)
            {
                // Yes - A lower case s in sync
                string portHeader = "Port 873 - Rsync (Remote Sync)";
                string portData = Rsync.GetInfo(ip, port);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += "- Rsync: rsync -av --list-only rsync://" + ip + "/folderNameHere/ (Remove --list-only and add a . at the end to download)" + Environment.NewLine;
            }
            else if (port == 993)
            {
                string portHeader = "Port 993 - IMAPS (IMAP over SSL)";
                string portData = "- Reecon currently lacks IMAPS support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 995)
            {
                string portHeader = "Port 995 - pop3s (pop3 over SSL)";
                string portData = "- Reecon currently lacks pop3s support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 2049)
            {
                string portHeader = "Port 2049 - NFS (Network File System)";
                string portData = NFS.GetFileList(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 3128)
            {
                string portHeader = "Port 3128 - Squid";
                string portData = Squid.GetInfo(ip, 3128);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += $"- Squid: If you get a password, run: squidclient -v -h {ip} -w 'passwordHere' mgr:menu" + Environment.NewLine;
            }
            else if (port == 3268)
            {
                string portHeader = "Port 3268 - LDAP (Global Catalog)";
                string portData = "- Reecon currently lacks LDAP (Global Catalog) support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 3269)
            {
                string portHeader = "Port 3269 - LDAP (Global Catalog) over SSL";
                string portData = "- Reecon currently lacks LDAP (Global Catalog) over SSL support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 3306)
            {
                //MySql 
                // Console.WriteLine("Port 3306 - MySQL" + Environment.NewLine + "- Reecon currently lacks MySQL support" + Environment.NewLine + "- Banner: " + theBanner + Environment.NewLine);
                // TODO: Refactor
                string port3306Result = "Port 3306 - MySQL" + Environment.NewLine;
                string version = MySQL.GetVersion(ip);
                port3306Result += version;
                if (!version.Contains("Access Denied"))
                {
                    port3306Result += "- Try: hydra -L users.txt -P passwords.txt " + ip + " mysql" + Environment.NewLine;
                }
                // string greeting = MySQL.ReceiveGreeting(ip);
                // port3306Result += greeting + Environment.NewLine;
                /*
                if (!greeting.StartsWith("- Unauthorized") && !greeting.StartsWith("- Unable to connect: An existing connection was forcibly closed by the remote host"))
                {
                    port3306Result += MySQL.TestDefaults(ip); // Does not work - Do not re-enable
                }*/
                Console.WriteLine(port3306Result + Environment.NewLine);

                // https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
                // https://svn.nmap.org/nmap/scripts/mysql-info.nse
                // --> https://svn.nmap.org/nmap/nselib/mysql.lua -> receiveGreeting
            }
            else if (port == 3389)
            {
                string portHeader = "Port 3389 - Windows Remote Desktop";
                string portData = "- Reecon currently lacks Windows Remote Desktop support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

                // TODO: https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html
                // https://svn.nmap.org/nmap/scripts/rdp-ntlm-info.nse
                /*
                string NTLM_NEGOTIATE_BLOB =  "30 37 A0 03 02 01 60 A1 30 30 2E 30 2C A0 2A 04 28"
                                            + "4e 54 4c 4d 53 53 50 00" // Identifier - NTLMSSP
                                            + "01 00 00 00" //Type: NTLMSSP Negotiate -01
                                            + "B7 82 08 E2 " // Flags(NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
                                            + "00 00 " // DomainNameLen
                                            + "00 00" // DomainNameMaxLen
                                            + "00 00 00 00" // DomainNameBufferOffset
                                            + "00 00 " // WorkstationLen
                                            + "00 00" // WorkstationMaxLen
                                            + "00 00 00 00" // WorkstationBufferOffset
                                            + "0A" // ProductMajorVersion = 10
                                            + "00 " // ProductMinorVersion = 0
                                            + "63 45 " // ProductBuild = 0x4563 = 17763
                                            + "00 00 00" // Reserved
                                            + "0F"; // NTLMRevision = 5 = NTLMSSP_REVISION_W2K3


                byte[] byteData = General.StringToByteArray(NTLM_NEGOTIATE_BLOB);
                string result = General.BannerGrabBytes(ip, port, byteData);
                Console.WriteLine("Result: " + result);
                */
            }
            else if (port == 4369)
            {
                // TODO: https://svn.nmap.org/nmap/scripts/epmd-info.nse
                string portHeader = "Port 4369 - Erlang Port Mapper Daemon (EPMD)";
                string portData = "- Reecon currently lacks EPMD support" + Environment.NewLine + "- Check NMap";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                postScanActions += "- EPMD: nmap " + ip + " -p4369 --script=epmd-info -sV" + Environment.NewLine;
            }
            else if (port == 5222)
            {
                // TODO: Jabber
                // 5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
            }
            else if (port == 5269)
            {
                // japper / xmpp-server
                // nmap --script=xmpp-info 10.10.245.198 -p5269
            }
            // 5269/tcp open  xmpp                Wildfire XMPP Client ???
            else if (port == 5672)
            {
                string portHeader = "Port 5672 - Advanced Message Queuing Protocol (AMQP)";
                string portData = General.BannerGrab(ip, 5672, "Woof" + Environment.NewLine + Environment.NewLine);
                if (portData.StartsWith("AMQP"))
                {
                    if (portData[4] == 0 && portData[5] == 0 && portData[6] == 9 && portData[7] == 1)
                    {
                        portData = "- Version 0-9-1";
                        // theBanner = General.BannerGrab(ip, port, theBanner); // Need to send the bytes of AMQP0091

                        // Oh gawd....
                        // \u0001\0\0\0\0\u0001?\0\n\0\n\0\t\0\0\u0001?\fcapabilitiesF\0\0\0?\u0012publisher_confirmst\u0001\u001aexchange_exchange_bindingst\u0001\nbasic.nackt\u0001\u0016consumer_cancel_notifyt\u0001\u0012connection.blockedt\u0001\u0013consumer_prioritiest\u0001\u001cauthentication_failure_closet\u0001\u0010per_consumer_qost\u0001\u000fdirect_reply_tot\u0001\fcluster_nameS\0\0\0\u0010rabbit@dyplesher\tcopyrightS\0\0\0.Copyright (C) 2007-2018 Pivotal Software, Inc.\vinformationS\0\0\05Licensed under the MPL.  See http://www.rabbitmq.com/\bplatformS\0\0\0\u0011Erlang/OTP 22.0.7\aproductS\0\0\0\bRabbitMQ\aversionS\0\0\0\u00053.7.8\0\0\0\u000ePLAIN AMQPLAIN\0\0\0\u0005en_US?
                        // https://svn.nmap.org/nmap/nselib/amqp.lua
                        postScanActions += "- AMQP is up and nmap knows more: nmap --script amqp-info -p" + port + " " + ip + Environment.NewLine;
                    }
                    else
                    {
                        portData = "- 5672.Unknown Version - Bug Reelix";
                    }
                }
                else
                {
                    portData = "- 5672.Unknown - Bug Reelix";
                }
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 5985)
            {
                // TODO: Figure out how to do basic evil-winrm.rb connections
                // evil-winrm.rb -i 10.10.10.161
                string portHeader = "Port 5985 - WinRM"; // WSMAN (WBEM WS-Management HTTP) ?
                string portData = WinRM.GetInfo(ip, 5985);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 5986)
            {
                string portHeader = "Port 5986 - Secure WinRM"; // WSMANS (WBEM WS-Management HTTP over TLS/SSL) ?
                string portData = WinRM.GetInfo(ip, 5986);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 6379)
            {
                string portHeader = "Port 6379 - Redis";
                string portData = Redis.GetInfo(ip, port);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 6881)
            {
                string portHeader = "Port 6881 - BitTorrent";
                string portData = "- Reecon currently lacks BitTorrent support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 9389)
            {
                string portHeader = "Port 9389 - ADWS (Active Directory Web Services)";
                string portData = "- Reecon currently lacks ADWS support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 9418)
            {
                string portHeader = "Port 9418 - Git";
                string portData = "- Reecon currently lacks Git support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 9200)
            {
                string portHeader = "Port 9200 - Elasticsearch HTTP Interface";
                string portData = Elasticsearch.GetInfo(ip);
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);

            }
            else if (port == 9300)
            {
                string portHeader = "Port 9300 - Elasticsearch Communication Port";
                string portData = "- Check out Port 9200 (Elasticsearch HTTP Interface) - Reecon has info on that";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 11211)
            {
                string portHeader = "Port 11211 - Memcache";
                string portData = "- Reecon currently lacks Memcache support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 25565)
            {
                string portHeader = "Port 25565 - Minecraft";
                string portData = "- Reecon currently lacks Minecraft support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 27017)
            {
                // MongoDB
                string portHeader = "Port 27017 - MongoDB";
                string portData = "- Reecon currently lacks MongoDB support" + Environment.NewLine;
                portData += "- NMap can get the version";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
                // Nmap can get the version - What else can we get?
            }
            else if (port == 49666 || port == 49667 || port == 49670 || port == 49672 || port == 49690)
            {
                string portHeader = "Port " + port + " - Microsoft Windows RPC";
                string portData = "- Reecon currently lacks Microsoft Windows RPC support";
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else
            {
                // A port I'm not familiar with - Try parse the banner
                string theBanner = General.BannerGrab(ip, port);
                byte[] theBannerBytes = General.GetBytes(theBanner);
                string unknownPortResult = "Port " + port;

                // 220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 19 Oct 2019 16:02:49 +0200
                if (theBanner.StartsWith("220") && theBanner.Contains("ESMTP"))
                {
                    unknownPortResult += " - SMTP";
                    string smtpInfo = SMTP.GetInfo(ip, port); // Can't just parse the banner directly since there could be other useful stuff
                    Console.WriteLine(unknownPortResult + Environment.NewLine + smtpInfo + Environment.NewLine);

                }
                // SSH
                else if (theBanner.Contains("SSH-2.0-OpenSSH") || theBanner == "SSH-2.0-Go")
                {
                    unknownPortResult += " - SSH" + Environment.NewLine;
                    if (theBanner.Contains("\r\nProtocol mismatch."))
                    {
                        unknownPortResult += Environment.NewLine + "- TCP Protocol Mismatch";
                    }
                    unknownPortResult += SSH.GetInfo(ip, port);
                    Console.WriteLine(unknownPortResult + Environment.NewLine);
                }
                // WinRM - HTTP with special stuff
                else if (theBanner.Contains("Server: Microsoft-HTTPAPI/2.0"))
                {
                    unknownPortResult += " - WinRM";
                    string portData = WinRM.GetInfo(ip, port);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portData + Environment.NewLine);
                }
                // Squid - HTTP with different special stuff
                else if (theBanner.Contains("Server: squid"))
                {
                    unknownPortResult += " - Squid";
                    string portData = Squid.GetInfo(ip, port);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portData + Environment.NewLine);
                }
                // Probably a general HTTP or HTTPS web server
                else if (
                    theBanner.Contains("Server: Apache") // Apache Web Server
                    || theBanner.Contains("Server: cloudflare") // Cloudflare Server
                    || theBanner.StartsWith("HTTP/1.1")
                    || theBanner.StartsWith("HTTP/1.0")
                    || theBanner.Contains("Error code explanation: 400 = Bad request syntax or unsupported method.") // BaseHTTP/0.3 Python/2.7.12
                    || theBanner.Contains("<p>Error code: 400</p>") // TryHackMe - Task 12 Day 7
                    || theBanner.Contains("<h1>Bad Request (400)</h1>")
                    )
                {
                    string httpData = HTTP.GetInfo(ip, port, false);
                    if (httpData != "")
                    {
                        Console.WriteLine(unknownPortResult + " - HTTP" + Environment.NewLine + httpData + Environment.NewLine);
                        postScanActions += "- gobuster dir -u=http://" + ip + ":" + port + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-" + port + "-medium.txt -x.php,.txt" + Environment.NewLine;
                        postScanActions += "- gobuster dir -u=http://" + ip + ":" + port + "/ -w ~/wordlists/common.txt -t 25 -o gobuster-" + port + "-common.txt -x.php,.txt" + Environment.NewLine;
                    }
                    string httpsData = HTTP.GetInfo(ip, port, true);
                    if (httpsData != "")
                    {
                        Console.WriteLine(unknownPortResult + " - HTTPS" + Environment.NewLine + httpsData + Environment.NewLine);
                        postScanActions += "- gobuster dir -u=https://" + ip + ":" + port + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-" + port + "-medium.txt -x.php,.txt" + Environment.NewLine;
                        postScanActions += "- gobuster dir -u=https://" + ip + ":" + port + "/ -w ~/wordlists/common.txt -t 25 -o gobuster-" + port + "-common.txt -x.php,.txt" + Environment.NewLine;
                    }
                }
                else if (theBanner == "-ERR unknown command 'Woof'") // Probably Redis
                {
                    unknownPortResult += " - Redis";
                    string portData = Redis.GetInfo(ip, port);
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
                else if (theBanner.StartsWith("AMQP") && theBannerBytes.Length == 8)
                {
                    // First 0-3: AMQP
                    // 4-7: Version
                    if (theBannerBytes[4] == 0 && theBannerBytes[5] == 0 && theBannerBytes[6] == 9 && theBannerBytes[7] == 1)
                    {
                        Console.WriteLine("Port " + port + " - AMQP" + Environment.NewLine + "- Version 0-9-1" + Environment.NewLine + "- Bug Reelix to finish AMQP decoding..." + Environment.NewLine);
                        // theBanner = General.BannerGrab(ip, port, theBanner); // Need to send the bytes of AMQP0091

                        // Oh gawd....
                        // \u0001\0\0\0\0\u0001?\0\n\0\n\0\t\0\0\u0001?\fcapabilitiesF\0\0\0?\u0012publisher_confirmst\u0001\u001aexchange_exchange_bindingst\u0001\nbasic.nackt\u0001\u0016consumer_cancel_notifyt\u0001\u0012connection.blockedt\u0001\u0013consumer_prioritiest\u0001\u001cauthentication_failure_closet\u0001\u0010per_consumer_qost\u0001\u000fdirect_reply_tot\u0001\fcluster_nameS\0\0\0\u0010rabbit@dyplesher\tcopyrightS\0\0\0.Copyright (C) 2007-2018 Pivotal Software, Inc.\vinformationS\0\0\05Licensed under the MPL.  See http://www.rabbitmq.com/\bplatformS\0\0\0\u0011Erlang/OTP 22.0.7\aproductS\0\0\0\bRabbitMQ\aversionS\0\0\0\u00053.7.8\0\0\0\u000ePLAIN AMQPLAIN\0\0\0\u0005en_US?
                        // https://svn.nmap.org/nmap/nselib/amqp.lua
                        postScanActions += "- AMQP is up and nmap knows more: nmap --script amqp-info -p" + port + " " + ip + Environment.NewLine;
                    }
                    else
                    {
                        Console.WriteLine("Port " + port + "- AMQP" + Environment.NewLine + "- Unknown AMQP Version: " + (int)theBannerBytes[4] + (int)theBannerBytes[5] + (int)theBannerBytes[6] + (int)theBannerBytes[7] + Environment.NewLine);
                    }
                }
                else if (theBanner == "</stream:stream>")
                {
                    unknownPortResult += " - xmpp" + Environment.NewLine;
                    unknownPortResult += " - Client Name: Wildfire XMPP Client" + Environment.NewLine;
                    Console.WriteLine(unknownPortResult);
                }
                else if (theBanner.StartsWith("@RSYNCD"))
                {
                    unknownPortResult += " - Rsync" + Environment.NewLine;
                    unknownPortResult += Rsync.GetInfo(ip, port);
                    Console.WriteLine(unknownPortResult);
                }
                // 47538/tcp open  socks-proxy Socks4A
                // -> [?? _ ??
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
                    Console.WriteLine(unknownPortResult + Environment.NewLine + "- Unknown Banner Response: -->" + theBanner + "<--" + Environment.NewLine);
                }
            }
        }
    }
}
