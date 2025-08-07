using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;

namespace Reecon
{
    internal class Program
    {
        private static readonly List<int> PortList = [];
        private static string target = "";
        private static readonly List<Thread> ThreadList = [];
        private static readonly List<string> PostScanList = [];

        public static void Main(string[] args)
        {
            // For timing
            DateTime startDate = DateTime.Now;
            
            // Stands out a bit more
            Console.ForegroundColor = ConsoleColor.White;
            
            // And begin!
            Console.WriteLine("Reecon - Version 0.39 ( https://github.com/Reelix/Reecon )".Recolor(Color.Yellow));
            if (args.Length == 0)
            {
                General.ShowHelp();
                Console.ResetColor();
                return;
            }

            // Check if it's anything custom

            if (args.Contains("-h") || args.Contains("--help") || args.Contains("--version") || args.Contains("-v") ||
                args.Contains("-V") || args.Contains("--v")) // Any others? :p
            {
                General.ShowHelp();
                Console.ResetColor();
                return;
            }
            else if (args[0].Contains("-ip"))
            {
                General.PrintIPList();
                Console.ResetColor();
                return;
            }
            else if (args[0].Contains("-bloodhound"))
            {
                Bloodhound.Run(args);
                Console.ResetColor();
                return;
            }
            else if (args[0].Contains("-ldap"))
            {
                Ldap.Run(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-lfi") || args.Contains("--lfi"))
            {
                Lfi.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-lookup") || args.Contains("--lookup"))
            {
                Lookup.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-osint") || args.Contains("--osint"))
            {
                Osint.GetInfo(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-pwn") || args.Contains("--pwn"))
            {
                Pwn.Scan(args);
                Console.ResetColor();
                return;
            }
            else if (args.Contains("-search") || args.Contains("--search"))
            {
                Nist.Search(args);
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
                Smb.SMBBrute(args);
                Console.ResetColor();
                return;
            }
            /*
            else if (args.Contains("-smb-eternalblue"))
            {
                string ip = args[1];
                Console.WriteLine($"Checking {ip}...");
                //SMB_MS17_010.IsVulnerable(ip, true);
                Console.WriteLine("Check Complete");
            }
            */
            else if (args.Contains("-winrm-brute"))
            {
                WinRm.WinRmBrute(args);
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
                args = args.Where(x => !x.Contains("--noping")).ToArray();
            }
            
            // Check if we must include SMBv1 Lookups
            if (args.Contains("-nosmbv1") || args.Contains("--nosmbv1"))
            {
                General.SMBv1 = false;
                args = args.Where(x => !x.Contains("-nosmbv1")).ToArray();
                args = args.Where(x => !x.Contains("--nosmbv1")).ToArray();
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
                var nmapResult = Nmap.ParseFile(fileName);
                target = nmapResult.Target;
                List<int> ports = nmapResult.Ports;
                if (ports.Count == 0)
                {
                    Console.WriteLine("Error: Empty file - Bug Reelix!");
                }
                else
                {
                    PortList.AddRange(ports);
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
                    PortList.AddRange(portArg.Split(',').ToList().Select(int.Parse));
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
                    Console.WriteLine($"Invalid target: {target}");
                    return;
                }

                if (!isHostOnline.Value)
                {
                    Console.WriteLine($"Host {target} is not responding to pings :(");
                    Console.WriteLine("If you are sure it's up and are specifying ports, you can use -noping");
                    return;
                }
            }

            if (PortList.Count == 0)
            {
                // Scan the target
                string fileName = Nmap.DefaultScan(args, mustPing);
                fileName += ".nmap";

                // Parse the ports
                var nmapResult = Nmap.ParseFile(fileName);
                target = nmapResult.Target;
                PortList.AddRange(nmapResult.Ports);
            }

            // Ports have been defined (Either nmap or custom)
            if (PortList.Count != 0)
            {
                ScanPorts(PortList);
            }
            else
            {
                // All parsing and scans done - But still no ports
                Console.WriteLine("No open ports found to scan :<");
                return;
            }

            // All done - Output stats
            DateTime endDate = DateTime.Now;
            TimeSpan t = endDate - startDate;
            Console.WriteLine($"Done in {t.TotalSeconds:0.00}s - Have fun :)");
            Console.ResetColor();
        }

        private static void ScanPorts(List<int> portsToScan)
        {
            PortInfo.LoadPortInfo();

            Console.Write("Scanning: " + target);
            Console.Write(" (Port");
            if (portsToScan.Count > 1)
            {
                Console.Write("s");
            }

            Console.WriteLine(": " + string.Join(",", portsToScan) + ")");

            // Multi-threaded scan
            foreach (int port in portsToScan)
            {
                Thread myThread = new(() => ScanPort(port));
                ThreadList.Add(myThread);
                myThread.Start();
            }

            // Wait for the scans to finish
            foreach (Thread theThread in ThreadList)
            {
                theThread.Join();
            }

            // And clear the thread list
            ThreadList.Clear();

            // Everything done - Now for some helpful info!
            Console.WriteLine("Finished - Some things you probably want to do: ");
            if (portsToScan.Count == 0)
            {
                // Something broke, or there are only UDP Ports :|
                Console.WriteLine($"- nmap -sC -sV -p- {target} -oN nmap.txt");
                Console.WriteLine($"- nmap -sU {target} -oN nmap-UDP.txt");
            }
            else
            {
                PostScanList.Add(
                    $"- Nmap Script+Version Scan: sudo nmap -sC -sV -p{string.Join(",", portsToScan)} {target} -oN nmap.txt" +
                    Environment.NewLine);
                PostScanList.Add($"- Nmap UDP Scan: sudo nmap -sU {target} (-F for top 100)" + Environment.NewLine);
                foreach (string item in PostScanList)
                {
                    // They already have newlines in them
                    Console.Write(item);
                }
            }
        }

        static void ScanPort(int port)
        {
            string toDo = PortInfo.ScanPort(target, port);
            if (toDo != "")
            {
                PostScanList.Add(toDo);
            }
        }
    }
}