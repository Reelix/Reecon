using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    internal static class SMTP // Generally Port 25
    {
        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnText = "";
            byte[] buffer = new byte[5000];
            using (Socket smtpSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                smtpSocket.ReceiveTimeout = 5000;
                smtpSocket.SendTimeout = 5000;
                try
                {
                    Console.WriteLine($"Connecting to {ip}:{port}");
                    smtpSocket.Connect(ip, port);
                    // Wait for info
                    int bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                    string smtpBanner = Encoding.ASCII.GetString(buffer, 0, bytes);
                    if (smtpBanner.StartsWith("220 ")) // Most, but not all SMTP banners contain the text smtp - But all contains a 220 followed by a space
                    {
                        // We got a valid response! Let's do some parsing!
                        // 220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
                        // 220 ubuntu GoldentEye SMTP Electronic-Mail agent

                        // Remove the number
                        smtpBanner = smtpBanner.Remove(0, 4);

                        string hostName = "";
                        string nameAndDate = "";
                        // SMTP OR ESMTP
                        if (smtpBanner.ToUpper().IndexOf("ESMTP", StringComparison.Ordinal) != -1)
                        {
                            int esmtpIndex = smtpBanner.ToUpper().IndexOf("ESMTP", StringComparison.Ordinal);
                            hostName = smtpBanner.Substring(0, esmtpIndex);
                            nameAndDate = smtpBanner.Remove(0, esmtpIndex + 6);
                        }
                        else if (smtpBanner.ToUpper().IndexOf("SMTP", StringComparison.Ordinal) != -1)
                        {
                            int smtpIndex = smtpBanner.ToUpper().IndexOf("SMTP", StringComparison.Ordinal);
                            hostName = smtpBanner.Substring(0, smtpIndex);
                            nameAndDate = smtpBanner.Remove(0, smtpIndex + 5);
                        }
                        string newlineChars;
                        if (nameAndDate.EndsWith("\r\n"))
                        {
                            returnText += "- Windows Newline Characters Detected" + Environment.NewLine;
                            newlineChars = "\r\n";
                        }
                        else if (nameAndDate.EndsWith("\n"))
                        {
                            returnText += "- Linux Newline Characters Detected" + Environment.NewLine;
                            newlineChars = "\n";
                        }
                        else
                        {
                            return ("SMTP?", "- Unknown newline character :<");
                        }
                        if (hostName != "")
                        {
                            returnText = returnText.Trim(newlineChars.ToCharArray());
                            returnText += $"- Host: {hostName}" + Environment.NewLine;
                        }
                        if (nameAndDate != "")
                        {
                            nameAndDate = nameAndDate.Trim(newlineChars.ToCharArray());
                            returnText += $"- Name: {nameAndDate}" + Environment.NewLine;
                        }

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
                        byte[] ehloBytes = Encoding.ASCII.GetBytes(("EHLO " + ip + newlineChars).ToCharArray());
                        smtpSocket.Send(ehloBytes, ehloBytes.Length, 0);
                        bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                        string ehloResponse = Encoding.ASCII.GetString(buffer, 0, bytes);
                        // Console.WriteLine("Response: " + ehloResponse);
                        bool isPipeliningEnabled = false;
                        if (ehloResponse.Length != 0)
                        {
                            // Bad EHLO Response
                            if (ehloResponse.Trim() == "550 Forged EHLO/HELO data")
                            {
                                returnText += "- EHLO requires the Domain Name - Additional checks may fail" + Environment.NewLine;
                            }
                            else if (ehloResponse.Trim().StartsWith("550 "))
                            {
                                returnText += "- Unable to EHLO: " + ehloResponse.Remove(0, 4) + Environment.NewLine;
                            }
                            else
                            {
                                // Good EHLO Response - Parse it
                                List<string> ehloItems = ehloResponse.Split(newlineChars.ToCharArray()).ToList();
                                ehloItems.RemoveAll(string.IsNullOrEmpty);
                                // Console.WriteLine(ehloItems.Count + " items");
                                string commands = "";
                                foreach (string item in ehloItems)
                                {
                                    string commandItem = item.Replace("250-", "").Replace("250 ", "").Replace(newlineChars, "");
                                    if (commandItem == "PIPELINING")
                                    {
                                        isPipeliningEnabled = true;
                                    }
                                    commands += commandItem + ",";
                                }
                                commands = commands.Trim(',');
                                returnText += "- SMTP Commands: " + commands + Environment.NewLine;
                                if (isPipeliningEnabled)
                                {
                                    returnText += "- PIPELINING is enabled - Command Spam allowed!" + Environment.NewLine;
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("Fatal Error in Reecon.SMTP - Bug Reelix!");
                        }

                        // Check the MAIL FROM to see if we can phish
                        byte[] mailFromBytes = Encoding.ASCII.GetBytes(("MAIL FROM:<test@test.com>" + newlineChars).ToCharArray());
                        smtpSocket.Send(mailFromBytes, mailFromBytes.Length, 0);
                        bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                        string mailFromResponse = Encoding.ASCII.GetString(buffer, 0, bytes).Trim();
                        // 550 HELO/EHLO not yet given -> Requires a valid EHLO First
                        // 250 2.1.0 Ok
                        // 550 Submission must be authenticated -> Requires Auth
                        // 530 5.7.1 Authentication required
                        if (mailFromResponse.StartsWith("550 ") || mailFromResponse.StartsWith("550-") || mailFromResponse.StartsWith("530 "))
                        {
                            mailFromResponse = mailFromResponse.Remove(0, 4);
                            if (mailFromResponse == "Submission must be authenticated")
                            {
                                returnText += "- Unable to phish: Credentials are required for MAIL FROM" + Environment.NewLine;
                            }
                            else if (mailFromResponse == "HELO/EHLO not yet given")
                            {
                                returnText += "- Unable to phish: Requires a valid EHLO" + Environment.NewLine;
                            }
                            else if (mailFromResponse.Contains("Authentication required"))
                            {
                                returnText += "- Unable to phish: Credentials are required for MAIL FROM" + Environment.NewLine;
                            }
                            else
                            {
                                returnText += "- Unable to phish: " + mailFromResponse + Environment.NewLine;
                            }
                        }
                        else if (mailFromResponse.StartsWith("250 ") || mailFromResponse.StartsWith("250-"))
                        {
                            // Can Spoof the Mail From!
                            returnText += "- " + "Valid unauth'd MAIL FROM! Maybe try phish?".Recolor(Color.Orange) + Environment.NewLine;
                            
                            // How about the RCPT TO?
                            byte[] rcptToBytes = Encoding.ASCII.GetBytes(($"RCPT TO:<test@{ip}>" + newlineChars).ToCharArray());
                            smtpSocket.Send(rcptToBytes, rcptToBytes.Length, 0);
                            bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                            string rcptToResponse = Encoding.ASCII.GetString(buffer, 0, bytes).Trim();
                            if (rcptToResponse.StartsWith("250" ) || rcptToResponse.StartsWith("250-"))
                            {
                                returnText += "-- No RCPT Validation Enabled - Try with a URL?" + Environment.NewLine;
                                returnText += $"-- swaks --to target@domain.com --from it@domain.com --server {ip} --port {port} --body body.txt" + Environment.NewLine;
                            }
                            else if (rcptToResponse.StartsWith("550"))
                            {
                                returnText += "-- " + "RCPT Validation Enabled - You can validate user accounts!".Recolor(Color.Orange) + Environment.NewLine;
                                returnText += $"-- Phishing Command: swaks --to target@domain.com --from it@domain.com --server {ip} --port {port} --body phish.txt" + Environment.NewLine;
                            }
                            else if (rcptToResponse.StartsWith("501")) // 501 5.1.3 Bad recipient address syntax
                            {
                                // Can't RCPT to mails - How about names?
                                // https://github.com/rapid7/metasploit-framework/blob/master//modules/auxiliary/scanner/smtp/smtp_enum.rb
                                // use auxiliary/scanner/smtp/smtp_enum
                                returnText += "-- Unable to RCPT TO addresses - Checking name test..." + Environment.NewLine;
                                rcptToBytes = Encoding.ASCII.GetBytes(($"RCPT TO:asdniasudnaisud" + newlineChars).ToCharArray());
                                smtpSocket.Send(rcptToBytes, rcptToBytes.Length, 0);
                                bytes = smtpSocket.Receive(buffer, buffer.Length, 0);
                                rcptToResponse = Encoding.ASCII.GetString(buffer, 0, bytes).Trim();
                                if (rcptToResponse.StartsWith("550") && rcptToResponse.Contains("User unknown in local recipient table"))
                                {
                                    returnText += "-- " + "Name test verified! Use Metasploit: auxiliary/scanner/smtp/smtp_enum".Recolor(Color.Orange) + Environment.NewLine;
                                    returnText += $"-- Phishing Command: swaks --from it@domain.com --to user,user2,user3 --server {ip} --port {port} --body @phish.txt" + Environment.NewLine;
                                }
                                else
                                {
                                    returnText += "-- Unknown rcptToResponse response: " + rcptToResponse + Environment.NewLine;
                                }
                            }
                            else if (rcptToResponse.StartsWith("554")) // 554 5.7.1 <test@smtp.domainhere.com>: Recipient address rejected: Access denied
                            {
                                returnText += "-- Rejected recipient address - Manual exploitation attempt required :(" + Environment.NewLine;
                            }
                            else
                            {
                                returnText += "-- Unknown rcptToResponse - Bug Reelix - DEBUG: " + rcptToResponse + Environment.NewLine;
                            }
                        }
                        // https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smtp/smtp_enum.rb
                        else if (mailFromResponse.Trim() == "")
                        {
                            returnText += "- No MAIL FROM response." + Environment.NewLine;
                        }
                        else
                        {
                            returnText += "- Unknown MAIL FROM Response: " + mailFromResponse + Environment.NewLine;
                        }
                    }
                    else
                    {
                        returnText = "- Non-SMTP Banner Detected: " + smtpBanner + Environment.NewLine;
                    }
                }
                catch (Exception ex)
                {
                    returnText = "- SMTP.cs Error - Unable to connect: " + ex.Message + Environment.NewLine;
                }
            }
            returnText = returnText.Trim(Environment.NewLine.ToCharArray());
            return ("SMTP", returnText);
        }
    }
}
