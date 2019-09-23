using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace ReeRecon
{
    class Program
    {
        static List<int> portList = new List<int>();
        static string ip = "";
        static List<Thread> threadList = new List<Thread>();
        static void Main(string[] args)
        {
            /*
            For Debugging
            
            ip = "github.com";
            UsePort(443);
            Console.WriteLine("done!");
            Console.ReadLine();
            */

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("ReeRecon - Version 0.01a");
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
                Console.WriteLine("Scanning: " + ip);
                if (portList.Count != 0)
                {
                    Console.WriteLine("Ports: " + string.Join(",", portList));
                }
            }
            else
            {
                Console.WriteLine("Hard Coded IP - Dev Mode!");
                Console.WriteLine("Scanning: " + ip);
            }
            if (portList.Count != 0)
            {
                ParsePorts("portlist");
            }
            else
            {
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
            if (portList.Contains(21))
            {
                Console.WriteLine("- Check out Port 21 for things I missed");
            }
            if (portList.Contains(80))
            {
                Console.WriteLine("- gobuster -u http://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-http.txt");
            }
            if (portList.Contains(443))
            {
                Console.WriteLine("- gobuster -u https://" + ip + "/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-https.txt");
            }
            Console.WriteLine("Done - Have fun :)");
        }

        static void RunNMap(int level)
        {
            Console.WriteLine($"Starting a Level {level} Nmap on IP " + ip);
            Process p = new Process();
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

        static void ParsePorts(string fileName)
        {
            if (fileName == "portlist")
            {
                foreach (int port in portList)
                {
                    Thread myThread = new Thread(() => UsePort(port));
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
                        Thread myThread = new Thread(() => UsePort(port));
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

        static void UsePort(int port)
        {
            Console.WriteLine("Found Port: " + port);
            string theBanner = General.BannerGrab(ip, port);

            if (port == 21)
            {
                FTP myFTP = new FTP();
                string ftpLoginInfo = myFTP.FtpLogin(ip);
                if (ftpLoginInfo.Contains("Unable to login: This FTP server is anonymous only."))
                {
                    myFTP = new FTP();
                    ftpLoginInfo = myFTP.FtpLogin(ip, "anonymous", "");
                }
                else if (ftpLoginInfo.Contains("Unable to login: USER: command requires a parameter"))
                {
                    myFTP = new FTP();
                    ftpLoginInfo = myFTP.FtpLogin(ip, "test", "test");
                }
                Console.WriteLine("Port 21" + Environment.NewLine + ftpLoginInfo);
            }
            else if (port == 22)
            {
                string port22Result = "Port 22";
                string sshVersion = SSH.GetVersion(ip);
                string authMethods = SSH.GetAuthMethods(ip);
                Console.WriteLine(port22Result + Environment.NewLine + "- SSH Version: " + (sshVersion == null ? "Unknown" : sshVersion) + Environment.NewLine + "- Authentication Methods: " + (authMethods == null ? "Unknown" : authMethods));

            }
            else if (port == 80)
            {
                string port80result = "Port 80";
                // RunGoBuster()
                HTTP myHTTP = new HTTP();
                string header = myHTTP.GetHeader(ip).Get("Server");
                if (header != null)
                {
                    port80result += Environment.NewLine + "- Server: " + header;
                }
                string pageTitle = myHTTP.GetTitle(ip, port, false);
                if (pageTitle != "")
                {
                    port80result += Environment.NewLine + "- Page Title: " + pageTitle;
                }
                Console.WriteLine(port80result);
            }
            else if (port == 443)
            {
                string port443Result = "Port 443";
                // Get SSL Detauls
                HTTP myHTTP = new HTTP();
                var result = myHTTP.GetSSLCertAndHeaders(ip);
                if (result.cert != null)
                {
                    string certIssuer = result.cert.Issuer;
                    port443Result += Environment.NewLine + "- SSL Cert Issuer: " + certIssuer;
                }
                string serverHeader = result.headers.Get("Server");
                if (serverHeader != null)
                {
                    port443Result += Environment.NewLine + "- Server: " + serverHeader;
                }
                string pageTitle = myHTTP.GetTitle(ip, port, true);
                if (pageTitle != "")
                {
                    port443Result += Environment.NewLine + "- Page Title: " + pageTitle;
                }
                Console.WriteLine(port443Result);
            }
            else if (port == 445)
            {
                Console.WriteLine("Port 445" + Environment.NewLine + "- Microsoft SMB - Nothing Yet");
            }
            else
            {
                // Try parse the banner
                string unknownPortResult = "Port " + port;
                if (theBanner.Contains("SSH-2.0-OpenSSH")) // Probably SSH
                {
                    unknownPortResult += Environment.NewLine + "- SSH Version: " + theBanner;
                    string authMethods = SSH.GetAuthMethods(ip);
                    unknownPortResult += Environment.NewLine + "- Auth Methods: " + authMethods;
                    Console.WriteLine(unknownPortResult);
                }
                else if (theBanner.Contains("Server: Apache")) // Probably HTTP or HTTPS
                {
                    // Try HTTP
                    HTTP myHTTP = new HTTP();
                    var httpResult = myHTTP.GetHeader(ip, port);
                    string pageTitle = "";
                    if (httpResult != null)
                    {
                        if (httpResult.Get("Server") != null)
                        {
                            unknownPortResult += Environment.NewLine + "- Server: " + httpResult.Get("Server");
                        }
                        if (httpResult.Get("WWW-Authenticate") != null)
                        {
                            unknownPortResult += Environment.NewLine + "- WWW-Authenticate: " + httpResult.Get("WWW-Authenticate");
                        }
                        pageTitle = myHTTP.GetTitle(ip, port, false);
                        if (pageTitle != "")
                        {
                            unknownPortResult += Environment.NewLine + "- Page Title: " + pageTitle;
                        }
                        Console.WriteLine(unknownPortResult);
                        return;
                    }
                    // Try HTTPS
                    var httpsResult = myHTTP.GetSSLCertAndHeaders(ip, port);
                    unknownPortResult += Environment.NewLine + "- Probably https";
                    if (httpsResult.headers != null && httpsResult.headers.Get("Server") != null)
                    {
                        unknownPortResult += Environment.NewLine + "- Server: " + httpsResult.headers.Get("Server");
                    }
                    if (httpsResult.cert != null)
                    {
                        unknownPortResult += Environment.NewLine + "- SSL Cert Issuer: " + httpsResult.cert.Issuer;
                    }
                    pageTitle = myHTTP.GetTitle(ip, port, true);
                    if (pageTitle != "")
                    {
                        unknownPortResult += Environment.NewLine + "- Page Title: " + pageTitle;
                    }
                    Console.WriteLine(unknownPortResult);
                }
                else
                {
                    Console.WriteLine(Environment.NewLine + "- Unknown Banner Response: " + theBanner);
                }
            }
        }

        static void RunGoBuster()
        {
            /*
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            gobuster - u https://superuser.com/ -w ~/wordlists/directory-list-2.3-medium.txt
            */
        }
    }
}
