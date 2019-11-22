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
        // Get version
        public static string GetVersion(string ip)
        {
            Byte[] buffer = new Byte[512];
            using (Socket sshSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                sshSocket.Connect(ip, 22);
                int bytes = sshSocket.Receive(buffer, buffer.Length, 0);
                string versionMessage = Encoding.ASCII.GetString(buffer, 0, bytes);
                return versionMessage.Trim().Replace(Environment.NewLine, "");
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
            List<string> outputLines = new List<string>();
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = "ssh";
            p.StartInfo.Arguments = "-oPreferredAuthentications=none -oStrictHostKeyChecking=no " + ip + " -p " + port;
            p.OutputDataReceived += (sender, e) => outputLines.Add(e.Data);
            p.ErrorDataReceived += (sender, e) => outputLines.Add(e.Data);
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();
            p.Close();
            outputLines.RemoveAll(string.IsNullOrEmpty);
            // kex_exchange_identification: read: Connection reset by peer
            if (outputLines.Contains("kex_exchange_identification: read: Connection reset by peer"))
            {
                returnString = "- SSH Exists, but connection reset - Doesn't like you :(";
                return returnString;
            }
            if (!outputLines.Contains("Permission denied"))
            {
                Console.WriteLine("Error in ssh.GetAuthMethods - No Permission denied found");
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
