using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class SSH // Commonly Port 22 or 2222
    {
        public static (string PortName, string PortInfo) GetInfo(string ip, int port)
        {
            string sshVersion = SSH.GetVersion(ip, port);
            if (sshVersion == "Closed")
            {
                return ("Closed", "");
            }
            string authMethods = "- Authentication Methods: " + SSH.GetAuthMethods(ip, port);
            string returnInfo = sshVersion + Environment.NewLine + authMethods;
            return ("SSH", returnInfo);
        }
        // Get version
        public static string GetVersion(string ip, int port)
        {
            int timeout = 10000;
            Byte[] buffer = new Byte[512];
            using (Socket sshSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                sshSocket.ReceiveTimeout = timeout; // ms
                sshSocket.SendTimeout = timeout; // ms
                try
                {
                    var result = sshSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        int bytes = sshSocket.Receive(buffer, buffer.Length, 0);
                        string responseMessage = Encoding.ASCII.GetString(buffer, 0, bytes);
                        responseMessage = responseMessage.Trim();
                        
                        string versionMessage = "";
                        if (responseMessage.Contains("\r"))
                        {
                            versionMessage = responseMessage.Split("\r")[0].Trim('\n');
                        }
                        else
                        {
                            versionMessage = responseMessage;
                        }
                        // SSH-2.0-OpenSSH_6.6.1p1
                        // SSH-2.0-dropbear_0.45
                        // SSH-2.0-dropbear_2016.74
                        if (versionMessage.StartsWith("SSH-2.0-"))
                        {
                            versionMessage = versionMessage.Remove(0, 8);
                            versionMessage = versionMessage.Replace("_", " ");
                            versionMessage += " (protocol 2.0)"; // Nmap's format
                        }
                        else if (versionMessage.Trim() == "")
                        {
                            // Can also get here on closed ports - What the?
                            versionMessage = "Port is open, but no version info";
                        }
                        else
                        {
                            versionMessage = $"Weird SSH Version: {versionMessage}";
                        }
                        // https://gist.github.com/0x4D31/35ddb0322530414bbb4c3288292749cc
                        if (responseMessage.ToLower().Contains("libssh"))
                        {
                            versionMessage += Environment.NewLine;
                            versionMessage += "--> libssh detected - Bug Reelix!";
                        }
                        return versionMessage;
                    }
                    else
                    {
                        sshSocket.Close();
                        return "Closed";
                    }
                }
                catch (SocketException se)
                {
                    if (se.Message.StartsWith("No connection could be made because the target machine actively refused it"))
                    {
                        return "Port is closed";
                    }
                    return "SSG.GetVersion - Fatal Woof: " + se.Message;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("SSH.GetVersion - Something broke: " + ex.Message);
                    return "SSH.GetVersion - Borked - Bug Reelix";
                }
            }
        }

        // Get Auth Methods
        public static string GetAuthMethods(string ip, int port)
        {
            string returnString = "";
            if (string.IsNullOrEmpty(ip))
            {
                Console.WriteLine("Error in ssh.GetAuthMethods - Missing IP");
                return "";
            }
            List<string> outputLines = General.GetProcessOutput("ssh", $"-o PreferredAuthentications=none -o StrictHostKeyChecking=no -o ConnectTimeout=5 {ip} -p {port} -oHostKeyAlgorithms=ssh-ed25519,ssh-rsa");
            // kex_exchange_identification: read: Connection reset by peer
            if (outputLines.Count == 1 && outputLines[0].EndsWith("Connection refused"))
            {
                return "- Port is closed";
            }
            if (outputLines.Any(x => x.Contains("no matching key exchange method found. Their offer:")))
            {
                string theLine = outputLines.First(x => x.Contains("no matching key exchange method found. Their offer:"));
                string authMethods = theLine.Remove(0, theLine.IndexOf("Their offer: ") + 13);
                return "Unknown - Weird Auth Algos: " + authMethods + Environment.NewLine + $"--> ssh {ip} -p {port} -o PreferredAuthentications=none -o StrictHostKeyChecking=no -o ConnectTimeout=5 -oHostKeyAlgorithms=ABOVE";
            }
            // Similar
            if (outputLines.Any(x => x.Contains("no matching host key type found. Their offer")))
            {
                string theLine = outputLines.First(x => x.Contains("no matching host key type found. Their offer"));
                string authMethods = theLine.Remove(0, theLine.IndexOf("Their offer: ") + 13);
                return "Unknown - Weird Auth Algos: " + authMethods + Environment.NewLine + $"--> ssh {ip} -p {port} -o PreferredAuthentications=none -o StrictHostKeyChecking=no -o ConnectTimeout=5 -oHostKeyAlgorithms=ABOVE";
            }
            if (outputLines.Count == 1 && outputLines[0].Trim() == "kex_exchange_identification: Connection closed by remote host")
            {
                return "- They have no auth methods to give you";
            }
            if (outputLines.Contains("kex_exchange_identification: read: Connection reset by peer"))
            {
                returnString = "- Port is open, but connection reset with no info :(";
                return returnString;
            }
            if (!outputLines.Any(x => x.Contains("Permission denied")))
            {
                if ((outputLines.Count == 1 || outputLines.Count == 2) && outputLines[0].Contains("Connection timed out"))
                {
                    return "Timed out :(";
                }
                else
                {
                    Console.WriteLine("Error in ssh.GetAuthMethods - No Permission denied found");
                    foreach (string line in outputLines)
                    {
                        Console.WriteLine($"Debug: --> {line}");
                    }
                    return "";
                }
            }
            returnString = outputLines.First(x => x.Contains("Permission denied"));
            returnString = returnString.Remove(0, returnString.IndexOf("("));
            returnString = returnString.Replace("(", "").Replace(")", "");
            returnString = returnString.Replace(",", ", ");
            returnString = returnString.Trim('.');  
            // ssh - oPreferredAuthentications = none - oStrictHostKeyChecking = no 10.10.10.147

            // reelix@10.10.10.147: Permission denied(publickey, password).
            // reelix@10.10.10.110: Permission denied (publickey,keyboard-interactive).
            return returnString;
        }


    }
}
