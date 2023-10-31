﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Reecon
{
    class Program
    {
        static string target = "";
        static readonly List<int> portList = new();
        static readonly List<Thread> threadList = new();
        static readonly List<string> postScanList = new();
        static void Main(string[] args)
        {
            DateTime startDate = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Yellow; // .Pastel has a weirder yellow to the one I want
            Console.WriteLine("Reecon - Version 0.33a ( https://github.com/Reelix/Reecon )");
            Console.ForegroundColor = ConsoleColor.White;
            if (args.Length == 0)
            {
                General.ShowHelp();
                Console.ResetColor();
                return;
            }

            // Check if it's anything custom
            if (args.Contains("-h") || args.Contains("--help") || args.Contains("--version"))
            {
                General.ShowHelp();
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-ip") || args.Contains("--ip"))
            {
                General.PrintIPList();
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-ldap") || args.Contains("--ldap"))
            {
                string ip = args[1];
                string username = args[2];
                string password = args[3];
                string accountInfo = LDAP.GetAccountInfo(ip, username, password);
                Console.WriteLine(accountInfo);
                return;
            }
            else if (args.Contains("-lfi") || args.Contains("--lfi"))
            {
                LFI.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-osint") || args.Contains("--osint"))
            {
                OSINT.GetInfo(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-pwn") || args.Contains("--pwn"))
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

            // Check if you should check if the target is up
            bool mustPing = true;
            if (args.Contains("-noping") || args.Contains("--noping"))
            {
                mustPing = false;
                args = args.Where(x => !x.Contains("-noping")).ToArray();
            }
            // A common typo
            if (args.Contains("-nopign"))
            {
                Console.WriteLine("You probably typo'd -noping");
                Console.ResetColor();
                return;
            }

            // Everything below here has a maximum of 2 args
            if (args.Length > 2)
            {
                Console.WriteLine("You probably typo'd something");
                Console.ResetColor();
                return;
            }

            // Target
            if (args[0].EndsWith(".nmap"))
            {
                Console.WriteLine("Parsing file...");
                string fileName = args[0];
                var (Target, Ports) = Nmap.ParseFile(fileName);
                target = Target;
                if (!Ports.Any())
                {
                    Console.WriteLine("Error: Empty file - Bug Reelix!");
                }
                else
                {
                    portList.AddRange(Ports);
                }
            }
            else
            {
                target = args[0];
            }

            if (target.StartsWith("http"))
            {
                Console.WriteLine("Cannot do a standard scan on a URL - Try a -web scan");
                Console.ResetColor();
                return;
            }

            // Custom ports
            if (args.Length == 2)
            {
                string portArg = args[1];
                try
                {
                    portList.AddRange(portArg.Split(',').ToList().Select(x => int.Parse(x)));
                }
                catch
                {
                    // Not a list of ports - Probably a name
                }
            }

            // First check if it's actually up
            if (mustPing)
            {
                Console.WriteLine("Checking if target is online...");
                bool? isHostOnline = General.IsUp(target);
                General.ClearPreviousConsoleLine();

                if (isHostOnline == null)
                {
                    Console.WriteLine("Invalid target: " + target);
                    return;
                }
                if (!isHostOnline.Value)
                {
                    Console.WriteLine("Host is not responding to pings :(");
                    Console.WriteLine("If you are sure it's up and are specifying ports, you can use -noping");
                    return;
                }
            }

            if (portList.Count == 0)
            {
                // Scan the target
                string fileName = Nmap.DefaultScan(args, mustPing);
                fileName += ".nmap";

                // Parse the ports
                var (Target, Ports) = Nmap.ParseFile(fileName);
                target = Target;
                portList.AddRange(Ports);
            }

            // Everything parsed - Down to the scanning!
            PortInfo.LoadPortInfo();

            // Ports have been defined (Either nmap or custom)
            if (portList.Count != 0)
            {
                Console.Write("Scanning: " + target);
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
                // All parsing and scans done - But still no ports
                Console.WriteLine("No open ports found to scan :<");
                return;
            }

            // Everything done - Now for some helpful info!
            Console.WriteLine("Finished - Some things you probably want to do: ");
            if (portList.Count == 0)
            {
                // Something broke, or there are only UDP Ports :|
                Console.WriteLine("- nmap -sC -sV -p- " + target + " -oN nmap.txt");
                Console.WriteLine("- nmap -sU " + target + " -oN nmap-UDP.txt");
            }
            else
            {
                postScanList.Add($"- Nmap Script+Version Scan: sudo nmap -sC -sV -p{string.Join(",", portList)} {target} -oN nmap.txt" + Environment.NewLine);
                postScanList.Add($"- Nmap UDP Scan: sudo nmap -sU {target} (-F for top 100)" + Environment.NewLine);
                foreach (string item in postScanList)
                {
                    // They already have newlines in them
                    Console.Write(item);
                }
            }
            DateTime endDate = DateTime.Now;
            TimeSpan t = endDate - startDate;
            Console.WriteLine("Done in " + string.Format("{0:0.00}s", t.TotalSeconds) + " - Have fun :)");
            Console.ResetColor();
        }

        static void ScanPorts(List<int> portList)
        {
            // Multi-threaded scan
            foreach (int port in portList)
            {
                Thread myThread = new(() => ScanPort(port));
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

        static void ScanPort(int port)
        {
            string toDo = PortInfo.ScanPort(target, port);
            if (toDo != "")
            {
                postScanList.Add(toDo);
            }
        }
    }
}
