using System;
using System.Collections.Generic;
using System.IO;

namespace Reecon
{
    class Nmap
    {
        public static void DefaultScan(string[] args)
        {
            // -nmap[0]
            // ip[1]
            // outputfile[2]
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: -nmap ip outfile");
                return;
            }
            string target = "";
            string fileName = "";
            if (args.Length == 2)
            {
                target = args[1];
                Console.WriteLine("Outfile name (1 word, no extension)");
                fileName = Console.ReadLine();
            }
            else if (args.Length == 3)
            {
                target = args[1];
                fileName = args[2];
            }
            DateTime beforeNmapDate = DateTime.Now;
            Console.WriteLine($"Doing an optimized Nmap scan on {target} - This may take awhile...");
            General.RunProcess($"nmap", $"-sS -p- --min-rate=5000 {target} -oG {fileName}.nmap");
            DateTime afterNmapDate = DateTime.Now;
            TimeSpan nmapScanDuration = afterNmapDate - beforeNmapDate;
            Console.WriteLine("Scan complete in " + string.Format("{0:0.00}s", nmapScanDuration.TotalSeconds) + $" - {fileName}.nmap for reecon");
        }

        public static void CustomScan(int level, string target)
        {
            // Nmap on Linux requires sudo for a Syn scan (-sS)
            Console.WriteLine($"Starting a Level {level} Nmap on {target}");
            if (level == 1)
            {
                // -F = Fast (100 Most Common Ports)
                if (General.GetOS() == General.OS.Linux)
                {
                    General.RunProcess("sudo", $"nmap {target} -sS -F --min-rate=50 -oG nmap-fast.txt");
                }
                else
                {
                    General.RunProcess("nmap", $"{target} -sS -F --min-rate=50 -oG nmap-fast.txt");
                }
            }
            else if (level == 2)
            {
                // Top 1,000 Ports (Excl. Top 100?)
                if (General.GetOS() == General.OS.Linux)
                {
                    General.RunProcess("sudo", $"nmap {target} -sS --min-rate=500 -oG nmap-normal.txt");
                }
                else
                {
                    General.RunProcess("nmap", $"{target} -sS --min-rate=500 -oG nmap-normal.txt");
                }
            }
            else if (level == 3)
            {
                // -p- = All Ports
                if (General.GetOS() == General.OS.Linux)
                {
                    General.RunProcess("sudo", $"nmap {target} -sS -p- --min-rate=5000 -oG nmap-slow.txt -oN nmap-all.txt");
                }
                else
                {
                    Console.WriteLine("Bug Reelix to fix RunNMap");
                }
            }
        }

        // Parses an -oG nmap file for ports and scans the results
        public static (string Target, List<int> Ports) ParseFile(string fileName, bool deleteFile = true)
        {
            if (!File.Exists(fileName))
            {
                Console.WriteLine("Error - Cannot find file: " + fileName);
                Environment.Exit(0);
            }
            string returnTarget;
            List<int> allPorts = new List<int>();
            List<int> returnPorts = new List<int>();

            StreamReader sr1 = new StreamReader(fileName);
            string[] fileLines = sr1.ReadToEnd().Split(new[] { Environment.NewLine }, StringSplitOptions.None);
            sr1.Close();
            if (deleteFile)
            {
                File.Delete(fileName);
            }
            // fileLines[1]: Host: 10.10.10.175 ()   Status: Up
            returnTarget = fileLines[1].Split(' ')[1];
            if (fileLines[1].Contains("0 hosts up"))
            {
                Console.WriteLine("Error - Host is down :(");
                Environment.Exit(0);
            }
            if (!fileLines[2].Contains("/open/"))
            {
                Console.WriteLine("No open ports found");
                return (returnTarget, returnPorts);
            }
            string portLine = fileLines[2];
            string[] portItems = portLine.Split('\t');
            string portSection = portItems[1];
            portSection = portSection.Replace("Ports: ", "");
            foreach (string item in portSection.Split(new[] { ", " }, StringSplitOptions.None))
            {
                int port = int.Parse(item.Split('/')[0]);
                string status = item.Split('/')[1];
                if (status == "open")
                {
                    if (!allPorts.Contains(port))
                    {
                        allPorts.Add(port);
                        returnPorts.Add(port);
                    }
                }
                else
                {
                    // Unknown status - Add it to the found list, but skip it
                    if (!allPorts.Contains(port))
                    {
                        allPorts.Add(port);
                    }
                    if (status != "closed")
                    {
                        Console.WriteLine("Unknown Status: " + port + " -> " + status);
                    }
                }
            }
            return (returnTarget, returnPorts);
        }
    }
}
