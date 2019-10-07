using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
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
            Console.WriteLine("Reecon - Version 0.04a ( https://github.com/reelix/reecon )");
            Console.ForegroundColor = ConsoleColor.White;
            if (args.Length == 0 && ip == "")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Needs an IP!");
                return;
            }
            else if (ip == "" && args.Length > 0)
            {
                if (args[0].Trim() == "")
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
                // Cleanup
                if (File.Exists("nmap-fast.txt"))
                {
                    File.Delete("nmap-fast.txt");
                }
                if (File.Exists("nmap-normal.txt"))
                {
                    File.Delete("nmap-normal.txt");
                }
                RunNMap(1);
                ParsePorts("nmap-fast.txt");
                RunNMap(2);
                ParsePorts("nmap-normal.txt");
            }
            foreach (Thread theThread in threadList)
            {
                theThread.Join();
            }

            Console.WriteLine(Environment.NewLine + "Finished - Some things you probably want to do: ");
            Console.WriteLine("- nmap -sC -sV -p" + string.Join(",", portList) + " " + ip + " -oN nmap.txt");
            Console.WriteLine("- nmap -p- " + ip + " -oN nmap-all.txt (Note: This is slow)");
            if (portList.Contains(21))
            {
                Console.WriteLine("- Check out Port 21 for things I missed");
            }
            if (portList.Contains(80))
            {
                Console.WriteLine("- gobuster dir -u=http://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-http.txt");
            }
            if (portList.Contains(443))
            {
                Console.WriteLine("- gobuster dir -u=https://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-https.txt");
            }
            if (portList.Contains(445))
            {
                Console.WriteLine("- nmap --script smb-enum-shares.nse -p445 " + ip);
            }
            DateTime endDate = DateTime.Now;
            TimeSpan t = endDate - startDate;
            Console.WriteLine("Done in " + string.Format("{0:0.00}s", t.TotalSeconds) + " - Have fun :)");
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

        static void ScanPort(int port)
        {
            Console.WriteLine("Found Port: " + port);
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
            else if (port == 80)
            {
                string port80result = "Port 80 - HTTP";
                // RunGoBuster()
                HTTP myHTTP = new HTTP();
                var httpInfo = myHTTP.GetHTTPInfo(ip, 80, false);
                string portData = myHTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                if (portData != null)
                {
                    Console.WriteLine(port80result + portData);
                    // Console.WriteLine(port80result + portData);
                }
                else
                {
                    Console.WriteLine(port + " -- Woof!");
                }
            }
            else if (port == 443)
            {
                string port443Result = "Port 443 - HTTPS";
                // Get SSL Detauls
                HTTP myHTTP = new HTTP();
                var httpsInfo = myHTTP.GetHTTPInfo(ip, 443, true);
                string portData = myHTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);
                Console.WriteLine(port443Result + portData);
            }
            else if (port == 445)
            {
                Console.WriteLine("Port 445 - Microsoft SMB" + Environment.NewLine + "- Reecon currently lacks SMB support");
            }
            else if (port == 3306)
            {
                //MySql 
                string theBanner = General.BannerGrab(ip, port);
                Console.WriteLine("Port 3306 - MySQL    " + Environment.NewLine + "- Reecon currently lacks MySQL support" + Environment.NewLine + "- Banner: " + theBanner);
                // https://svn.nmap.org/nmap/scripts/mysql-info.nse
            }
            else
            {
                // Try parse the banner
                string theBanner = General.BannerGrab(ip, port);

                string unknownPortResult = "Port " + port;
                if (theBanner.Contains("SSH-2.0-OpenSSH")) // Probably SSH
                {
                    unknownPortResult += " - ssh";
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
                else if (theBanner.Contains("Server: Apache") || theBanner.Contains("Server: cloudflare") || theBanner.StartsWith("HTTP/1.1 400 Bad Request")) // Probably HTTP or HTTPS
                {
                    string portData;
                    // Try HTTP
                    HTTP myHTTP = new HTTP();
                    var httpInfo = myHTTP.GetHTTPInfo(ip, port, false);
                    if (httpInfo != (new HttpStatusCode(), null, null, null, null))
                    {
                        unknownPortResult += " - http";
                        portData = myHTTP.FormatResponse(httpInfo.StatusCode, httpInfo.Title, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                        Console.WriteLine(unknownPortResult += portData);
                        return;
                    }
                    // Try HTTPS
                    var httpsInfo = myHTTP.GetHTTPInfo(ip, port, true);
                    unknownPortResult += " - https";
                    portData = myHTTP.FormatResponse(httpsInfo.StatusCode, httpsInfo.Title, httpsInfo.DNS, httpsInfo.Headers, httpsInfo.SSLCert);
                    Console.WriteLine(unknownPortResult += portData);
                }
                else if (theBanner == "")
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
