using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Reecon
{
    class General
    {
        public static void ShowHelp()
        {
            Console.WriteLine("Usage");
            Console.WriteLine("-----");
            Console.WriteLine("Basic Scan:\tReecon IPHere (Optional: -noping to skip the online check)");
            Console.WriteLine("Display IP:\tReecon -ip");
            Console.WriteLine("NMap-Load Scan:\tReecon outfile.nmap (Requires -oG on a regular nmap scan)");
            Console.WriteLine("Binary Pwn:\tReecon -pwn FileName (Very buggy)");
            Console.WriteLine("LDAP Auth Enum:\tReecon -ldap IP validUsername validPassword");
            Console.WriteLine("Searchsploit:\tReecon -searchsploit nameHere (Beta)");
            Console.WriteLine("Shell Gen:\tReecon -shell");
            Console.WriteLine("SMB Brute:\tReecon -smb-brute (Linux Only)");
            Console.WriteLine("WinRM Brute:\tReecon -winrm-brute IP UserList PassList");
            Console.WriteLine("LFI Test:\tReecon -lfi (Very buggy)");
            Console.WriteLine("Web Info:\tReecon -web url (Very buggy)");
        }

        public static List<string> MultiBannerGrab(string ip, int port, int bufferSize = 512, int timeout = 5000)
        {
            List<string> returnList = new();
            ConcurrentBag<string> resultCollection = new();
            List<string> toTest = new()
            {
                "",
                "Woof\r\n\r\n",
                "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n"
            };
            Parallel.ForEach(toTest, theBanner => resultCollection.Add(BannerGrabThread(ip, port, theBanner, bufferSize = 512, timeout)));
            returnList.AddRange(resultCollection.ToList());
            if (returnList.Any(x => x == "Reecon - Connection reset")) // Something forced a reset
            {
                // Console.WriteLine("Testing a reset web grab");
                if (Web.BasicHTTPSTest(ip, port))
                {
                    returnList.Add("Reecon - HTTPS");
                }
            }
            return returnList.ToList();
        }

        public static string BannerGrab(string ip, int port, string initialText = "", int bufferSize = 512, int timeout = 10000)
        {
            string bannerText = "";
            Byte[] buffer = new Byte[bufferSize];
            using (Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = timeout;
                bannerGrabSocket.SendTimeout = timeout;
                try
                {
                    var result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        if (!bannerGrabSocket.Connected)
                        {
                            bannerGrabSocket.Close();
                            return "Reecon - Closed";
                        }
                        if (initialText.Length != 0)
                        {
                            Byte[] cmdBytes = Encoding.ASCII.GetBytes(initialText.ToCharArray());
                            bannerGrabSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        }
                        int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                        if (bytes == 1)
                        {
                            // Streaming result
                            while (bytes != 0)
                            {
                                bannerText += Encoding.ASCII.GetString(buffer, 0, bytes);
                                bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                            }
                        }
                        else
                        {
                            bannerText += Encoding.ASCII.GetString(buffer, 0, bytes);
                        }
                        bannerText = bannerText.Trim();
                    }
                    else
                    {
                        bannerGrabSocket.Close();
                        return "Reecon - Closed";
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        // Could just mean that we're using the wrong info to grab the banner
                        // Do nothing - A timeout response is handled later
                    }
                    else if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        bannerText = "Reecon - Connection refused";
                    }
                    // Connection reset by peer
                    else if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        bannerText = "Reecon - Connection reset";
                    }
                    else
                    {
                        Console.WriteLine($"Error in BannerGrab with SocketErrorCode code: {ex.SocketErrorCode}");
                        return "";
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                    return "";
                }
            }

            // We can't get anything - Try some customs
            if (bannerText.Length == 0 && initialText.Length == 0)
            {
                bannerText = BannerGrab(ip, port, "Woof\r\n\r\n");
            }
            else if (bannerText.Length == 0 && initialText.StartsWith("Woof"))
            {
                // Nothing on the default - Try some HTTP
                // Can't use Environment.NewLine since Linux interprets it as \n which is invalid for IIS
                bannerText = BannerGrab(ip, port, $"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n");
            }
            return bannerText;
        }

        private static string BannerGrabThread(string ip, int port, string initialText = "", int bufferSize = 512, int timeout = 10000)
        {
            string bannerText = "";
            Byte[] buffer = new Byte[bufferSize];
            using (Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = timeout;
                bannerGrabSocket.SendTimeout = timeout;
                try
                {
                    var result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        if (!bannerGrabSocket.Connected)
                        {
                            bannerGrabSocket.Close();
                            return "Reecon - Closed";
                        }
                        if (initialText.Length != 0)
                        {
                            Byte[] cmdBytes = Encoding.ASCII.GetBytes(initialText.ToCharArray());
                            bannerGrabSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        }
                        int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                        if (bytes == 1)
                        {
                            // Streaming result
                            while (bytes != 0)
                            {
                                bannerText += Encoding.ASCII.GetString(buffer, 0, bytes);
                                bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                            }
                        }
                        else
                        {
                            bannerText += Encoding.ASCII.GetString(buffer, 0, bytes);
                        }
                        bannerText = bannerText.Trim();
                    }
                    else
                    {
                        bannerGrabSocket.Close();
                        return "Reecon - Closed";
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        // Could just mean that we're using the wrong info to grab the banner
                        // Do nothing - A timeout response is handled later
                    }
                    else if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        bannerText = "Reecon - Connection refused";
                    }
                    // Connection reset by peer
                    else if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        bannerText = "Reecon - Connection reset";
                    }
                    else
                    {
                        Console.WriteLine($"Error in BannerGrab with SocketErrorCode code: {ex.SocketErrorCode}");
                        return "";
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                    return "";
                }
            }
            return bannerText;
        }


        // This is for custom requests where you know the actual bytes to send
        public static byte[] BannerGrabBytes(string ip, int port, List<byte[]> bytesToSend, int bufferSize = 1024)
        {
            byte[] returBuffer = Array.Empty<byte>();
            byte[] buffer = new byte[bufferSize];
            using Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            bannerGrabSocket.ReceiveTimeout = 10000;
            bannerGrabSocket.SendTimeout = 10000;
            try
            {
                var result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                bool success = result.AsyncWaitHandle.WaitOne(10000, true);
                if (success)
                {
                    if (!bannerGrabSocket.Connected)
                    {
                        bannerGrabSocket.Close();
                        return Encoding.ASCII.GetBytes("Reecon - Closed");
                    }
                    foreach (byte[] cmdBytes in bytesToSend)
                    {
                        bannerGrabSocket.Send(cmdBytes);
                        int receivedBytes = bannerGrabSocket.Receive(buffer);
                        returBuffer = buffer.Take(receivedBytes).ToArray();
                    }
                    return returBuffer;
                }
                else
                {
                    bannerGrabSocket.Close();
                    return Encoding.ASCII.GetBytes("Reecon - Closed");
                }
            }
            catch (SocketException ex)
            {
                return Encoding.ASCII.GetBytes($"General.BannerGrabBytes Error: {ex.Message}");
            }
        }

        public static bool? IsUp(string ip)
        {
            using Ping myPing = new();
            try
            {
                PingOptions myOptions = new();
                try
                {
                    PingReply reply = myPing.Send(ip, 1000);
                    if (reply.Status == IPStatus.Success)
                    {
                        return true;
                    }
                    return false;
                }
                catch (PingException pex)
                {
                    if (pex.Message == "An exception occurred during a Ping request.")
                    {
                        return null;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (SocketException ex)
            {
                if (ex.Message.StartsWith("Could not resolve host"))
                {
                    // Invalid hostname - Cannot resolve
                    return false;
                }
                else
                {
                    Console.WriteLine(ex.Message);
                    Thread.Sleep(2500);
                    return false;
                }
            }
        }

        public static void ClearPreviousConsoleLine()
        {
            Console.SetCursorPosition(0, Console.CursorTop - 1);
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(new string(' ', Console.WindowWidth));
            Console.SetCursorPosition(0, currentLineCursor);
        }

        /// <summary>
        /// If you want to run a process and display the output
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="arguments"></param>
        public static void RunProcessWithOutput(string processName, string arguments)
        {
            // Console.WriteLine("Running Process " + processName + " with args: " + arguments);
            Process p = new();
            p.StartInfo.UseShellExecute = true;
            p.StartInfo.FileName = processName;
            p.StartInfo.Arguments = arguments;
            p.Start();
            p.WaitForExit();
            // Console.WriteLine("Process has run - Yay!");
        }

        /// <summary>
        /// If you want to run a process and hide the output
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="arguments"></param>
        public static void RunProcess(string processName, string arguments, int waitForExitSeconds = 500)
        {
            // Console.WriteLine("Running Process " + processName + " with args: " + arguments);
            Process p = new();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = processName;
            p.StartInfo.Arguments = arguments;
            p.Start();
            p.WaitForExit(waitForExitSeconds * 1000);
            p.Close();
            // Console.WriteLine("Process has run - Yay!");
        }

        /// <summary>
        /// If you want to run a process and return the output
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        public static List<string> GetProcessOutput(string processName, string arguments)
        {
            // Console.WriteLine("Running Process " + processName + " with args: " + arguments);
            List<string> outputLines = new();
            Process p = new();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = processName;
            p.StartInfo.Arguments = arguments;
            p.OutputDataReceived += (sender, e) => outputLines.Add(e.Data);
            p.ErrorDataReceived += (sender, e) => outputLines.Add(e.Data);
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();    
            p.Close();
            outputLines.RemoveAll(string.IsNullOrEmpty); // Useful?
            return outputLines;
        }

        public enum OS
        {
            Windows,
            Linux,
            Mac,
            Unknown
        }

        public static OS GetOS()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return OS.Windows;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return OS.Linux;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return OS.Mac;
            }
            else
            {
                // I can get others, but they're not really supported yet
                return OS.Unknown;
            }
        }

        public static bool IsInstalledOnLinux(string app, string path = "")
        {
            List<string> processOutput = GetProcessOutput("which", app);
            if (processOutput.Count == 0)
            {
                return false;
            }
            if (path == "" || processOutput[0].Trim() == path)
            {
                return true;
            }
            return false;
        }

        public static byte[] GetBytes(string inputString)
        {
            return Encoding.ASCII.GetBytes(inputString);
        }

        public static List<string> MatchCollectionToList(MatchCollection matchCollection)
        {
            List<string> returnList = new();
            foreach (Match item in matchCollection)
            {
                if (!returnList.Contains(item.Value))
                {
                    returnList.Add(item.Value);
                }
            }
            return returnList;
        }

        public static List<IP> GetIPList()
        {
            List<IP> ipList = new();
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface ni in networkInterfaces)
            {
                IPInterfaceProperties properties = ni.GetIPProperties();
                string name = ni.Name;
                if (name != "lo") // Loopback
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            IP returnIP = new()
                            {
                                Name = name,
                                Address = ip.Address
                            };
                            ipList.Add(returnIP);
                        }
                    }
                }
            }
            return ipList;
        }
        public static void PrintIPList()
        {
            List<IP> ipList = GetIPList();
            foreach (IP ip in ipList)
            {
                Console.WriteLine($"{ip.Name}: {ip.Address}");
            }
        }

        public class IP
        {
            public string Name;
            public IPAddress Address;
        }
    }
}
