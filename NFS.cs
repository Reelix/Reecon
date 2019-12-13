using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class NFS // Port 2049
    {
        public static string GetFileList(string ip)
        {
            // TODO: https://svn.nmap.org/nmap/scripts/nfs-ls.nse

            string fileList = "";
            if (File.Exists(@"C:\Windows\System32\showmount.exe"))
            {
                List<string> outputLines = General.GetProcessOutput(@"C:\Windows\System32\showmount.exe", "-e " + ip);
                if (outputLines.Count > 1)
                {
                    outputLines.RemoveAt(0);
                    fileList = "- Files:" + Environment.NewLine;
                    foreach (string line in outputLines)
                    {
                        fileList += "-- " + line + Environment.NewLine;
                    }
                    fileList = fileList.Trim(Environment.NewLine.ToCharArray());
                    fileList += Environment.NewLine + "- To Mount --> mount \\\\" + ip + "\\shareNameHere x:";
                }
                fileList = fileList.Trim(Environment.NewLine.ToCharArray());
                return fileList;
            }
            else
            {
                // Turn Windows Features
                fileList = "- showmount does not exist - Bug Reelix to update this section for more compatibility";
                return fileList;

                //
                // Linux
                //

                // which showmount (/sbin/showmount ?)
                // sudo apt install nfs-common

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
            return "";
        }
    }
}
