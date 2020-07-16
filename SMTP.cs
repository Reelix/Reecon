using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class SMTP // Generally Port 25
    {
        public static string GetInfo(string ip, int port)
        {
            string returnText = "";
            string smtpBanner = "";
            Byte[] buffer = new Byte[5000];
            using (Socket smtpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // They're like.... REALLY SLOW!
                smtpSocket.ReceiveTimeout = 15000;
                smtpSocket.SendTimeout = 15000;
                try
                {
                    smtpSocket.Connect(ip, port);
                    // Wait for info
                    int bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                    smtpBanner = Encoding.ASCII.GetString(buffer, 0, bytes);
                    if (smtpBanner.StartsWith("220") && smtpBanner.Contains("ESMTP"))
                    {
                        // We got a valid response! Let's do some parsing!
                        smtpBanner = smtpBanner.Remove(0, 4);
                        string hostName = smtpBanner.Substring(0, smtpBanner.IndexOf(" ESMTP"));
                        string nameAndDate = smtpBanner.Remove(0, smtpBanner.IndexOf(" ESMTP") + 7).Trim("\r\n".ToCharArray()); // Remove the space afterwards
                        returnText = $"- Host: {hostName}" + Environment.NewLine + $"- Name: {nameAndDate}";

                        // Now - Try to get some commands
                        /* 250-debian
                        250 - PIPELINING -> Can send multiple commands at once (Separated by newlines)
                        250 - SIZE 10240000
                        250 - VRFY
                        250 - ETRN
                        250 - STARTTLS
                        250 - ENHANCEDSTATUSCODES -> These numbers on the left
                        250 - 8BITMIME
                        250 - DSN
                        250 - SMTPUTF8
                        250 CHUNKING
                            */
                        byte[] cmdBytes = Encoding.ASCII.GetBytes(("EHLO " + ip + "\n").ToCharArray());
                        smtpSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                        string ehloResult = Encoding.ASCII.GetString(buffer, 0, bytes);
                        bool isPipeliningEnabled = false;
                        if (ehloResult.Length != 0)
                        {
                            List<string> ehloItems = ehloResult.Split(Environment.NewLine.ToCharArray()).ToList();
                            ehloItems.RemoveAll(string.IsNullOrEmpty);
                            string commands = "";
                            foreach (string item in ehloItems)
                            {
                                string commandItem = item.Replace("250-", "");
                                // This took awhile to fix.
                                // The split can keep a \r if used on Linux for data from a Windows host
                                // \r sends the carriage to the start of the line and can subsequently overrides text
                                commandItem = commandItem.Replace("\r", "");
                                if (commandItem == "PIPELINING")
                                {
                                    isPipeliningEnabled = true;
                                }
                                commands += commandItem + ",";
                            }
                            commands = commands.Trim(',');
                            returnText += Environment.NewLine + "- SMTP Commands: " + commands;
                            if (isPipeliningEnabled)
                            {
                                returnText += Environment.NewLine + "- PIPELINING is enabled - Command Spam allowed!";
                            }
                            /*
                                RCPT TO:<woof@woof.com>
                                503 5.5.1 Error: need MAIL command
                                MAIL FROM:<test@woof.com>
                                250 2.1.0 Ok
                            */
                            returnText += Environment.NewLine + "- Maybe try phish?" + Environment.NewLine
                                        + "-- MAIL FROM:<test@woof.com>" + Environment.NewLine
                                        + "-- RCPT TO:<woof@woof.com>" + Environment.NewLine
                                        + "-- DATA" + Environment.NewLine
                                        + "-- Type Stuff here, put a . on its own line to queue the send";
                        }
                    }
                    else
                    {
                        returnText = "- Non-SMTP Banner Detected: " + smtpBanner;
                    }    
                }
                catch (Exception ex)
                {
                    returnText = "Error - Unable to connect: " + ex.Message;
                }
            }
            return returnText;
        }
    }
}
