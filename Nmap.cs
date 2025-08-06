using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;

namespace Reecon
{
    internal static class Nmap
    {
        // Does an optimised nmap scan of the host, and outputs it in a greppable format for processing
        public static string DefaultScan(string[] args, bool mustPing)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ip outfile");
                Environment.Exit(0);
            }
            string target = "";
            string fileName = "";
            if (args.Length == 1)
            {
                target = args[0];
                Console.WriteLine("Outfile name (1 word, no extension)");
                fileName = Console.ReadLine() ?? "reecon";
            }
            else if (args.Length == 2)
            {
                target = args[0];
                fileName = args[1];
            }

            if (General.GetOS() == General.OS.Windows)
            {
                List<string> nmapOutput = General.GetProcessOutput("nmap", "-V");
                if (nmapOutput.Count == 0 || !nmapOutput[0].Contains("https://nmap.org"))
                {
                    Console.WriteLine("Error - nmap is not installed");
                    Environment.Exit(0);
                }
            }
            // Check if nmap is installed
            else if (General.GetOS() == General.OS.Linux)
            {
                if (!General.IsInstalledOnLinux("nmap"))
                {
                    Console.WriteLine("Error - nmap is not installed");
                    Environment.Exit(0);
                }
            }
            else
            {
                Console.WriteLine("Error - There is no nmap detection on this OS :<");
                Environment.Exit(0);
            }

            DateTime beforeNmapDate = DateTime.Now;
            Console.WriteLine($"Doing an optimized Nmap scan on {target} - This may take awhile...");
            string noPing = mustPing ? "" : " -Pn ";
            if (General.GetOS() == General.OS.Linux)
            {
                General.RunProcess($"sudo", $"nmap -sS -p- {noPing} --min-rate=5000 {target} -oG {fileName}.nmap");
            }
            else
            {
                General.RunProcess($"nmap", $"-sS -p- {noPing} --min-rate=5000 {target} -oG {fileName}.nmap");
            }
            DateTime afterNmapDate = DateTime.Now;
            TimeSpan nmapScanDuration = afterNmapDate - beforeNmapDate;
            Console.WriteLine("Optimized Nmap Scan complete in " + $"{nmapScanDuration.TotalSeconds:0.00}s" + $" - Created {fileName}.nmap for reecon");
            return fileName;
        }

        // Parses an -oG nmap file for ports and scans the results
        public static (string Target, List<int> Ports) ParseFile(string fileName)
        {
            if (!File.Exists(fileName))
            {
                Console.WriteLine("Error - Cannot find file: " + fileName);
                Environment.Exit(0);
            }

            List<int> allPorts = new();
            List<int> returnPorts = new();

            StreamReader sr1 = new(fileName);
            string[] fileLines = sr1.ReadToEnd().Replace("\r", "").Split(["\n"], StringSplitOptions.None);
            sr1.Close();
            // fileLines[1]: Host: 10.10.10.175 ()   Status: Up
            string upLine = fileLines[1];
            string returnTarget = upLine.Split(' ')[1];
            if (fileLines[1].Contains("0 hosts up"))
            {
                Console.WriteLine("Error - Host is down :(");
                Environment.Exit(0);
            }
            string portLine = fileLines[2];
            string[] portItems = portLine.Split('\t');
            string portSection = portItems[1];
            portSection = portSection.Replace("Ports: ", "");
            foreach (string item in portSection.Split([", "], StringSplitOptions.None))
            {
                if (item == "")
                {
                    continue;
                }
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
                else if (status == "filtered")
                {
                    if (!allPorts.Contains(port))
                    {
                        allPorts.Add(port);
                        Console.WriteLine($"Port {port} - Filtered".Recolor(Color.Orange));
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
