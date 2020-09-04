using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class SSH
    {
        public static string GetInfo(string ip, int port)
        {
            string returnInfo = "";
            string sshVersion = "- SSH Version: " + SSH.GetVersion(ip, port);
            string authMethods = "- Authentication Methods: " + SSH.GetAuthMethods(ip, port);
            returnInfo = sshVersion + Environment.NewLine + authMethods;
            return returnInfo;
        }
        // Get version
        public static string GetVersion(string ip, int port)
        {
            try
            {
                Byte[] buffer = new Byte[512];
                using (Socket sshSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sshSocket.Connect(ip, port);
                    int bytes = sshSocket.Receive(buffer, buffer.Length, 0);
                    string versionMessage = Encoding.ASCII.GetString(buffer, 0, bytes);
                    versionMessage = versionMessage.Trim().Replace(Environment.NewLine, "");
                    // SSH-2.0-OpenSSH_6.6.1p1
                    // SSH-2.0-dropbear_0.45
                    if (versionMessage.StartsWith("SSH-2.0-"))
                    {
                        versionMessage = versionMessage.Remove(0, 8);
                        versionMessage = versionMessage.Replace("_", "");
                        versionMessage += " (protocol 2.0)"; // Nmap's format
                    }
                    if (versionMessage.Trim() == "")
                    {
                        versionMessage = "Port is open, but no version info";
                    }
                    return versionMessage;
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
            List<string> outputLines = General.GetProcessOutput("ssh", $"-oPreferredAuthentications=none -oStrictHostKeyChecking=no {ip} -p {port}");
            // kex_exchange_identification: read: Connection reset by peer
            if (outputLines.Count == 1 && outputLines[0].EndsWith("Connection refused"))
            {
                return "- Port is closed";
            }
            if (outputLines.Count == 1 && outputLines[0].Contains("no matching key exchange method found. Their offer:"))
            {
                return "- Weird Auth Method: " + outputLines[0];
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
                Console.WriteLine("Error in ssh.GetAuthMethods - No Permission denied found");
                foreach (string line in outputLines)
                {
                    Console.WriteLine($"Debug: --> {line}");
                }
                return "";
            }
            returnString = outputLines.First(x => x.Contains("Permission denied"));
            returnString = returnString.Remove(0, returnString.IndexOf("("));
            returnString = returnString.Replace("(", "").Replace(")", "");
            // ssh - oPreferredAuthentications = none - oStrictHostKeyChecking = no 10.10.10.147

            // reelix@10.10.10.147: Permission denied(publickey, password).
            // reelix@10.10.10.110: Permission denied (publickey,keyboard-interactive).
            return returnString;
        }


    }
}
