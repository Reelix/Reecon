﻿using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;

namespace Reecon
{
    class NFS // Port 2049
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "Port is always required")]
        public static string GetInfo(string target, int port)
        {
            // TODO: https://svn.nmap.org/nmap/scripts/nfs-ls.nse

            string fileList = "";
            if (General.GetOS() == General.OS.Windows)
            {
                if (File.Exists(@"C:\Windows\System32\showmount.exe"))
                {
                    List<string> outputLines = General.GetProcessOutput(@"C:\Windows\System32\showmount.exe", "-e " + target);
                    if (outputLines.Count > 1)
                    {
                        outputLines.RemoveAt(0);
                        fileList = "- Files:" + Environment.NewLine;
                        foreach (string line in outputLines)
                        {
                            fileList += "-- " + line + Environment.NewLine;
                        }
                        fileList = fileList.Trim(Environment.NewLine.ToCharArray());
                        fileList += Environment.NewLine + $"- To Mount --> mount \\\\{target}\\shareNameHere x:";
                    }
                    fileList = fileList.Trim(Environment.NewLine.ToCharArray());
                    return fileList;
                }
                else
                {
                    fileList = "- showmount does not exist - Bug Reelix to update this section for more compatibility";
                    return fileList;
                }
            }
            else if (General.GetOS() == General.OS.Linux)
            {
                if (General.IsInstalledOnLinux("showmount")) // "/sbin/showmount" OR "/usr/sbin/showmount"
                {
                    List<string> showmountOutput = General.GetProcessOutput("showmount", "-e " + target);
                    foreach (string line in showmountOutput)
                    {
                        // https://github.com/TheRealPoloMints/Blog/blob/master/Security%20Challenge%20Walkthroughs/Networks%202/bash

                        // NFS V1
                        if (line.Trim().EndsWith("*"))
                        {
                            fileList += "- " + line.Pastel(Color.Orange) + Environment.NewLine;
                            fileList += "-- NFSV1 -> " + "sudo mount -t nfs {target}:/mountNameHere /tmp/mount/ -nolock".Pastel(Color.Orange) + Environment.NewLine;
                            fileList += "--- " + "Try copy over a version of bash onto the share, +s +x it, then ./bash -p".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        // NFS V2
                        else if (line.Contains(" (everyone)"))
                        {
                            fileList += "- " + line.Pastel(Color.Orange) + Environment.NewLine;
                            fileList += "-- NFSV2 -> " + $"sudo mount -t nfs -o vers=2 {target}:/mountNameHere /mnt".Pastel(Color.Orange) + Environment.NewLine;
                            fileList += "--- " + "Try copy over a version of bash onto the share, +s +x it, then ./bash -p".Pastel(Color.Orange) + Environment.NewLine;
                        }
                        else
                        {
                            fileList += "- " + line + Environment.NewLine;
                        }
                    }
                    return fileList.Trim(Environment.NewLine.ToCharArray());

                    //
                    // Windows
                    //

                    // ManagementClass objMC = new ManagementClass("Win32_ServerFeature"); // Only in Windows Server 2008 / R2
                    /*
                    ManagementClass objMC = new ManagementClass("Win32_OptionalFeature");
                    ManagementObjectCollection objMOC = objMC.GetInstances();
                    foreach (ManagementObject objMO in objMOC)
                    {
                        //Console.WriteLine("Woof!");
                        string featureName = (string)objMO.Properties["Name"].Value;
                        if (!featureName.ToUpper().Contains("NFS"))
                        {
                            continue;
                        }
                        uint installState = 0;
                        try
                        {
                            installState = (uint)objMO.Properties["InstallState"].Value; // 1 = Enabled, 2 = Disabled, 3 = Absent, 4 = Unknown
                        }
                        catch
                        {
                            Console.WriteLine("Error - InstallState is: " + (string)objMO.Properties["InstallState"].Value);
                        }

                        //add to my list
                        Console.WriteLine("Installed: " + featureName + " -> " + installState);
                    }
                    */
                }
                else
                {
                    return "- Error - showmount is not installed - Unable to enumerate! Run: sudo apt install nfs-common".Pastel(Color.Red);
                }
            }
            else
            {
                Console.WriteLine("Error - OS Not Supportd - Bug Reelix");
            }
            return "";
        }
    }
}
