using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
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
        static HttpClient httpClient = new HttpClient();
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
                "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n",
                // TLS
                // "0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00"
            };
            Parallel.ForEach(toTest, theBanner => resultCollection.Add(BannerGrabThread(ip, port, theBanner, bufferSize = 512, timeout)));
            returnList.AddRange(resultCollection.ToList());
            if (returnList.Any(x => x == "Reecon - Connection reset"))
            {
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
                            Byte[] cmdBytes;
                            if (initialText.StartsWith("0x") && initialText.Contains(", "))
                            {
                                string[] s = initialText.Split(',');
                                byte[] data = new byte[s.Length];
                                for (int i = 0; i < data.Length; i++)
                                {
                                    data[i] = byte.Parse(s[i].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber);
                                }
                                cmdBytes = data;
                            }
                            else
                            {
                                cmdBytes = Encoding.ASCII.GetBytes(initialText.ToCharArray());
                            }
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

        // Used for a better UI
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
            if (GetOS() != OS.Linux)
            {
                throw new Exception("Error: General.IsInstallOnLinux called on a non-Linux environment - Bug Reelix!");
            }
            List<string> processOutput = GetProcessOutput("which", app);
            if (processOutput.Count == 0)
            {
                Console.WriteLine("Debugging weird nmap bug - 1/2");
                Console.WriteLine("If you actually do have nmap installed, send this to Reelix");
                return false;
            }
            if (path == "" || processOutput[0].Trim() == path)
            {
                return true;
            }
            if (app == "nmap")
            {
                Console.WriteLine("Debugging weird nmap bug - 2/2");
                Console.WriteLine("If you actually do have nmap installed, send this to Reelix");
                foreach (string item in processOutput)
                {
                    Console.WriteLine("-- " + item);
                }
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

        public static string DownloadString(string path, string cookie="")
        {
            string toReturn = "";
            HttpRequestMessage theRequest = new HttpRequestMessage(HttpMethod.Get, path);
            if (cookie != "")
            {
                theRequest.Headers.Add("Cookie", cookie);
            }
            using (HttpResponseMessage response = httpClient.Send(theRequest))
            {
                using (StreamReader readStream = new(response.Content.ReadAsStream()))
                {
                    toReturn = readStream.ReadToEnd();
                }
            }
            return toReturn;
        }

        public static async void DownloadFile(string uri, string outputPath)
        {
            Uri uriResult;

            if (!Uri.TryCreate(uri, UriKind.Absolute, out uriResult))
            {
                throw new InvalidOperationException("URI is invalid.");
            }

            if (!File.Exists(outputPath))
            {
                throw new FileNotFoundException("File not found.", nameof(outputPath));
            }

            byte[] fileBytes = await httpClient.GetByteArrayAsync(uri);
            File.WriteAllBytes(outputPath, fileBytes);
        }
    }
}
