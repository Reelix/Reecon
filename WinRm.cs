using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Reecon
{
    internal static class WinRm // Windows Remote Management - 5985 / 5986
    {
        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            // TODO: Figure out how to do basic evil-winrm.rb connections
            // evil-winrm.rb -i 10.10.10.161

            string returnInfo = "";

            // Needs more testing
            WebHeaderCollection requestHeaders = new() { { "Content-Type", "application/soap+xml;charset=UTF-8" } };

            // To Test: CSL Potato (CyberSecLabs no longer seems to exist, so...)
            byte[] byteData = Encoding.ASCII.GetBytes("dsadsasa");

            try
            {
                Web.UploadDataResult result = Web.UploadData(port == 5986 ? $"https://{ip}:{port}/wsman" : $"http://{ip}:{port}/wsman", byteData);

                // Parse the result
                if (result.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // Remove some non-important ones
                    result.ResponseHeaders.Remove("Date");
                    result.ResponseHeaders.Remove("Connection");

                    // Parse the existing ones
                    if (result.ResponseHeaders.Server.Count != 0)
                    {
                        string headerValue = string.Join(", ", result.ResponseHeaders.Server);
                        returnInfo += "- Server: " + headerValue + Environment.NewLine;

                        // Should this even be in WinRM... ?
                        // https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=34561
                        // Aiohttp versions from and including 1.0.5 and before 3.9.2
                        // Eg: curl --path-as-is host.com/data/../../../../../../../../../../../etc/passwd
                        // - Server: Python/3.9 aiohttp/3.9.1
                        if (headerValue != "Microsoft-HTTPAPI/2.0")
                        {
                            returnInfo += "-- WinRM.cs Webclient Path - Bug Reelix!!!" + Environment.NewLine;
                        }
                        result.ResponseHeaders.Remove("Server");
                    }
                    if (result.ResponseHeaders.WwwAuthenticate.Count != 0)
                    {
                        string headerValue = string.Join(", ", result.ResponseHeaders.WwwAuthenticate);
                        returnInfo += "- Authentication Methods: " + headerValue + Environment.NewLine;
                        result.ResponseHeaders.Remove("WWW-Authenticate");
                    }

                    if (result.ResponseHeaders.Any())
                    {
                        foreach (var item in result.ResponseHeaders)
                        {
                            Console.WriteLine(item.Key + " -> " + string.Join(", ", item.Value));
                        }
                        returnInfo += "- Weird WinRM Response Headers!";
                    }
                }
                else if (result.StatusCode == HttpStatusCode.NotFound)
                {
                    bool isProbablyWinRm = false;
                    bool containsAuthentication = false;
                    foreach (var responseHeader in result.ResponseHeaders)
                    {
                        string headerName = responseHeader.Key;
                        string headerValue = string.Join(',', responseHeader.Value);
                        if (headerName == "Server")
                        {
                            returnInfo += "- Server: " + headerValue + Environment.NewLine;
                            if (headerValue == "Microsoft-HTTPAPI/2.0")
                            {
                                isProbablyWinRm = true;
                                returnInfo += "-- WinRM.cs Webclient Path - Bug Reelix!!!" + Environment.NewLine;
                            }
                        }
                        else if (headerName == "WWW-Authenticate")
                        {
                            returnInfo += "- Authentication Methods: " + headerValue + Environment.NewLine;
                            containsAuthentication = true;
                        }
                    }
                    if (!containsAuthentication)
                    {
                        returnInfo += "- Authentication Methods: None";
                    }
                    else if (!isProbablyWinRm)
                    {
                        returnInfo += "- No wsman found - Probably not WinRM";
                    }
                }
                else if (result.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    returnInfo += "- Service Unavailable (It's broken)";
                }
                else
                {
                    returnInfo += $"- Unknown response: {result.StatusCode} - Bug Reelix!";
                }
            }
            catch (Exception ex)
            {
                string exType = ex.GetType().Name;
                if (ex.Message.StartsWith("No connection could be made because the target machine actively refused it."))
                {
                    returnInfo += "- No connection could be made because the target machine actively refused it - The Port is probably Closed.";
                }
                else
                {
                    returnInfo += $"- Fatal Response in WinRM.cs of type {exType}: {ex.Message} - Bug Reelix!";
                    General.HandleUnknownException(ex);
                }
            }

            returnInfo = returnInfo.Trim(Environment.NewLine.ToCharArray());
            return ("WinRM", returnInfo);
        }

        public static void WinRmBrute(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("WinRM Brute Usage: reecon -winrm-brute IP Userfile Passfile");
                return;
            }
            string ip = args[1];
            string userFile = args[2];
            string passFile = args[3];

            // Windows: Only files
            if (General.GetOS() == General.OS.Windows)
            {
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
                WinRMBrute_Windows(ip, userFile, passFile);
            }
            // Linux takes either
            else
            {
                WinRMBrute_Linux(ip, userFile, passFile);
            }
        }

        private static void WinRMBrute_Windows(string ip, string userFile, string passFile)
        {
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
                    List<string> processResult = General.GetProcessOutput("powershell", $"$creds = New-Object System.Management.Automation.PSCredential -ArgumentList ('{user}', (ConvertTo-SecureString \"{pass}\" -AsPlainText -Force)); Test-WSMan -ComputerName {ip} -Credential $creds -Authentication Negotiate -erroraction SilentlyContinue");
                    if (processResult.Count != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Success!");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed");
                    }
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
            General.RunProcess("powershell", @"Set-Item WSMan:\localhost\Client\TrustedHosts '' -Force");
        }

        private static void WinRMBrute_Linux(string ip, string userFile, string passFile)
        {
            // This is currently just a nxc wrapper until I figure out a better way to do it.
            if (General.IsInstalledOnLinux("nxc"))
            {
                Console.WriteLine("Starting - Please wait...");
                General.RunProcessWithOutput("nxc", $"winrm {ip} -u {userFile} -p {passFile}");
            }
            else
            {
                Console.WriteLine("This requires NetExec -> https://github.com/Pennyw0rth/NetExec");
            }
        }
    }
}
