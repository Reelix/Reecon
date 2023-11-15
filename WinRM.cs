using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Text;

namespace Reecon
{
    class WinRM
    {
        public static string GetInfo(string ip, int port)
        {
            // TODO: Figure out how to do basic evil-winrm.rb connections
            // evil-winrm.rb -i 10.10.10.161

            string returnInfo = "";

            // Yes = I know it's obsolete - Need to fix this some day...
            WebClient wc = new();
            wc.Headers.Add("Content-Type", "application/soap+xml;charset=UTF-8");
            // Fix for invalid SSL Certs
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(
                delegate { return true; }
            );
            // Test: CSL Potato (CyberSecLabs no longer seems to exist, so...)
            Byte[] byteData = Encoding.ASCII.GetBytes("dsadsasa");
            try
            {
                if (port == 5986)
                {
                    wc.UploadData("https://" + ip + ":" + port + "/wsman", byteData);
                }
                else
                {
                    wc.UploadData("http://" + ip + ":" + port + "/wsman", byteData);
                }
                returnInfo = "- wsman upload returned no error - Bug Reelix";
            }
            catch (WebException wex)
            {
                if (((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.Unauthorized)
                {
                    foreach (string item in wex.Response.Headers)
                    {
                        string headerName = item;
                        string headerValue = wex.Response.Headers[headerName];
                        if (headerName == "Server")
                        {
                            returnInfo += "- Server: " + headerValue + Environment.NewLine;
                        }
                        else if (headerName == "WWW-Authenticate")
                        {
                            returnInfo += "- Authentication Methods: " + headerValue + Environment.NewLine;
                        }
                    }
                    if (returnInfo == "")
                    {
                        returnInfo = "- wsman found, but headers are weird - Bug Reelix";
                    }
                }
                else if (((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    bool isProbablyWinRM = false;
                    bool containsAuthentication = false;
                    foreach (string item in wex.Response.Headers)
                    {
                        string headerName = item;
                        string headerValue = wex.Response.Headers[headerName];
                        if (headerName == "Server")
                        {
                            returnInfo += "- Server: " + headerValue + Environment.NewLine;
                            if (headerValue == "Microsoft-HTTPAPI/2.0")
                            {
                                isProbablyWinRM = true;
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
                    else if (!isProbablyWinRM)
                    {
                        returnInfo += "- No wsman found - Probably not WinRM";
                    }
                }
                else if (((HttpWebResponse)wex.Response).StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    returnInfo += "- Service Unavailable (It's broken)";
                }
                else
                {
                    returnInfo += "- Unknown response: " + ((HttpWebResponse)wex.Response).StatusCode + " - Bug Reelix";
                }
            }

            return returnInfo.Trim(Environment.NewLine.ToCharArray());
        }

        public static void WinRMBrute(string[] args)
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

        private static void WinRMBrute_Linux(string ip, string userFile, string passFile)
        {
            if (General.IsInstalledOnLinux("crackmapexec", ""))
            {
                Console.WriteLine("Starting - Please wait...");
                General.RunProcessWithOutput("crackmapexec", "winrm " + ip + " -u " + userFile + " -p " + passFile);
            }
            else
            {
                Console.WriteLine("This requires crackmapexec -> https://github.com/byt3bl33d3r/CrackMapExec/releases");
            }
        }
    }
}
