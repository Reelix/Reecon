using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
    internal static class General
    {
        public static string ProgramName => typeof(Program).Assembly.GetName().Name ?? "Filename Error in Program.cs - Bug Reelix";

        public static bool SMBv1 { get; set; }

        public static void ShowBanner()
        {
            Console.WriteLine("Reecon - Version 0.40 ( https://github.com/Reelix/Reecon )".Recolor(Color.Yellow));
        }
        public static void ShowHelp()
        {
            ShowBanner();
            Console.WriteLine("Usage");
            Console.WriteLine("-----");
            Console.WriteLine($"Basic Scan:\t{ProgramName} IP OutputName (Optional: -noping to skip the online check)");
            Console.WriteLine($"Parse Nmap:\t{ProgramName} outfile.nmap (Requires -oG on a regular nmap scan)");
            Console.WriteLine($"Display IP:\t{ProgramName} -ip");
            Console.WriteLine($"Binary Pwn:\t{ProgramName} -pwn FileName (Very buggy)");
            Console.WriteLine($"LDAP Auth Enum:\t{ProgramName} -ldap IP port validUsername validPassword (NTLM Auth Only)");
            Console.WriteLine($"Nist Search:\t{ProgramName} -search NameHere (Only 6/10+ results)");
            Console.WriteLine($"Searchsploit:\t{ProgramName} -searchsploit NameHere (Beta)");
            Console.WriteLine($"Shell Gen:\t{ProgramName} -shell");
            Console.WriteLine($"SMB Brute:\t{ProgramName} -smb-brute (Linux Only)");
            Console.WriteLine($"WinRM Brute:\t{ProgramName} -winrm-brute IP UserList PassList");
            Console.WriteLine($"LFI Test:\t{ProgramName} -lfi (Very buggy)");
            Console.WriteLine($"Web Info:\t{ProgramName} -web url (Very buggy)");
            Console.WriteLine($"IP Lookup:\t{ProgramName} -lookup IP");
            Console.WriteLine($"API Key Lookup:\t{ProgramName} -apikey APIKey");
        }

        // Fingerprinting service
        public static List<List<byte>> MultiBannerGrab(string ip, int port, int bufferSize = 512, int timeout = 5000)
        {
            List<List<byte>> returnList = new();
            ConcurrentBag<List<byte>> resultCollection = new();
            List<string> toTest =
            [
                "",
                "Woof\r\n\r\n",
                // HTTP (Windows)
                "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n",
                // Minecraft
                "0xFE, 0x01"
                // TLS
                // "0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00"
            ];
            Parallel.ForEach(toTest, theBanner => resultCollection.Add(BannerGrabThread(ip, port, theBanner, bufferSize, timeout)));
            returnList.AddRange(resultCollection.ToList());
            if (returnList.Any(x => Encoding.UTF8.GetString(x.ToArray()) == "Reecon - Connection reset"))
            {
                if (Web.BasicHttpsTest(ip, port))
                {
                    returnList.Add(Encoding.UTF8.GetBytes("Reecon - HTTPS").ToList());
                }
            }
            if (returnList.Any(x => Encoding.UTF8.GetString(x.ToArray()).Contains("Client sent an HTTP request to an HTTPS server")))
            {
                // Whoops - It's an https that got caught by an http!
                returnList.RemoveAll(x => Encoding.UTF8.GetString(x.ToArray()).Contains("Client sent an HTTP request to an HTTPS server"));
                returnList.Add(Encoding.UTF8.GetBytes("Reecon - HTTPS").ToList());
            }
            // if (result.Contains("Page Text: Client sent an HTTP request to an HTTPS server."))
            // Remove it, HTTPS instead.
            return returnList.ToList();
        }

        public static string BannerGrab(string ip, int port, string initialText = "", int bufferSize = 512, int timeout = 10000)
        {
            string bannerText = "";
            byte[] buffer = new byte[bufferSize];
            using (Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = timeout;
                bannerGrabSocket.SendTimeout = timeout;
                try
                {
                    IAsyncResult result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
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
                            byte[] cmdBytes = Encoding.UTF8.GetBytes(initialText.ToCharArray());
                            bannerGrabSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        }
                        int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                        if (bytes == 1)
                        {
                            // Streaming result
                            while (bytes != 0)
                            {
                                bannerText += Encoding.UTF8.GetString(buffer, 0, bytes);
                                bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                            }
                        }
                        else
                        {
                            bannerText += Encoding.UTF8.GetString(buffer, 0, bytes);
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
                    HandleUnknownException(ex);
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

        private static List<byte> BannerGrabThread(string ip, int port, string initialText = "", int bufferSize = 512, int timeout = 10000)
        {
            List<byte> bannerBytes = new List<byte>();
            byte[] buffer = new byte[bufferSize];
            using (Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = timeout;
                bannerGrabSocket.SendTimeout = timeout;
                try
                {
                    IAsyncResult result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        if (!bannerGrabSocket.Connected)
                        {
                            bannerGrabSocket.Close();
                            return Encoding.UTF8.GetBytes("Reecon - Closed").ToList();
                        }
                        if (initialText.Length != 0)
                        {
                            byte[] cmdBytes;

                            // Check if it's a hex input instead of just a regular banner string
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
                                cmdBytes = Encoding.UTF8.GetBytes(initialText.ToCharArray());
                            }
                            bannerGrabSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        }
                        int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                        if (bytes == 1)
                        {
                            // Streaming result
                            while (bytes != 0)
                            {
                                bannerBytes.AddRange(buffer.Take(bytes));
                                bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                            }
                        }
                        else
                        {
                            bannerBytes.AddRange(buffer.Take(bytes));
                        }
                    }
                    else
                    {
                        bannerGrabSocket.Close();
                        return Encoding.UTF8.GetBytes("Reecon - Closed").ToList();
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
                        bannerBytes = Encoding.UTF8.GetBytes("Reecon - Connection refused").ToList();
                    }
                    // Connection reset by peer
                    else if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        bannerBytes = Encoding.UTF8.GetBytes("Reecon - Connection reset").ToList();
                    }
                    else
                    {
                        Console.WriteLine($"Error in BannerGrab with SocketErrorCode code: {ex.SocketErrorCode}");
                        bannerBytes = Encoding.UTF8.GetBytes("").ToList();
                        return bannerBytes;
                    }
                }
                catch (Exception ex)
                {
                    
                    Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                    HandleUnknownException(ex);
                    bannerBytes = Encoding.UTF8.GetBytes("").ToList();
                    return bannerBytes;
                }
            }
            // Console.WriteLine("Buffer Bytes: " + bannerBytes.Count);
            return bannerBytes;
        }

        // This is for custom requests where you know the actual bytes to send
        public static byte[] BannerGrabBytes(string ip, int port, List<byte[]> bytesToSend, int bufferSize = 1024)
        {
            byte[] buffer = new byte[bufferSize];
            using Socket bannerGrabSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            bannerGrabSocket.ReceiveTimeout = 10000;
            bannerGrabSocket.SendTimeout = 10000;
            try
            {
                IAsyncResult result = bannerGrabSocket.BeginConnect(ip, port, null, null); // Error if an invalid IP
                bool success = result.AsyncWaitHandle.WaitOne(10000, true);
                if (success)
                {
                    if (!bannerGrabSocket.Connected)
                    {
                        bannerGrabSocket.Close();
                        return Encoding.UTF8.GetBytes("Reecon - Closed");
                    }
                    
                    List<byte> accumulatedData = new List<byte>();
                    foreach (byte[] cmdBytes in bytesToSend)
                    {
                        bannerGrabSocket.Send(cmdBytes);
                        
                        // Loop indefinately until we receive no more bytes
                        // There's a bug on some services that they send data in segments
                        // Was previously sleeping and waiting for everything, but this is better

                        while (true)
                        {
                            int receivedBytes = bannerGrabSocket.Receive(buffer);
                            // Console.WriteLine("Received: " + receivedBytes);
                            if (receivedBytes > 0)
                            {
                                accumulatedData.AddRange(buffer.Take(receivedBytes));
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                    return accumulatedData.ToArray();
                }
                else
                {
                    bannerGrabSocket.Close();
                    // Test
                    return Encoding.UTF8.GetBytes("Reecon - Closed");
                }
            }
            catch (SocketException ex)
            {
                return Encoding.UTF8.GetBytes($"General.BannerGrabBytes Error: {ex.Message}");
            }
        }

        public static bool? IsUp(string ip)
        {
            using Ping myPing = new();
            try
            {
                try
                {
                    PingReply reply = myPing.Send(ip, 1000);
                    return reply.Status == IPStatus.Success;
                }
                catch (PingException pex)
                {
                    if (pex.Message == "An exception occurred during a Ping request.")
                    {
                        return null;
                    }
                    Console.WriteLine("General.cs->IsUp - Unknown pex.Message: " + pex.Message);
                    return false;
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
        /// <param name="waitForExitSeconds"></param>
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
            List<string> outputLines = [];
            Process p = new();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = processName;
            p.StartInfo.Arguments = arguments;
            p.OutputDataReceived += (_, e) => outputLines.Add(e.Data ?? "");
            p.ErrorDataReceived += (_, e) => outputLines.Add(e.Data ?? "");
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();
            p.Close();
            outputLines.RemoveAll(string.IsNullOrEmpty); // Useful?
            if (processName == "nmap" && outputLines.Count == 0)
            {
                Console.WriteLine("Debug Args: " + arguments);
            }
            return outputLines;
        }

        public enum OperatingSystem
        {
            Windows,
            Linux,
            Mac,
            Unknown
        }

        public static OperatingSystem GetOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return OperatingSystem.Windows;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return OperatingSystem.Linux;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return OperatingSystem.Mac;
            }
            else
            {
                // I can get others, but they're not really supported yet
                return OperatingSystem.Unknown;
            }
        }

        public static bool IsInstalledOnLinux(string app, string path = "")
        {
            if (General.GetOperatingSystem() != OperatingSystem.Linux)
            {
                throw new Exception("Error: General.IsInstallOnLinux called on a non-Linux environment - Bug Reelix!");
            }

            // Effectively replicating "which"
            string pathValue = Environment.GetEnvironmentVariable("PATH") ?? "";
            // Console.WriteLine("Linux PATH: " + pathValue);
            List<string> linuxPaths = pathValue.Split(":").ToList();
            foreach (string pathDirectory in linuxPaths)
            {
                string directory = pathDirectory.EndsWith('/') ? pathDirectory : pathDirectory + "/";
                if (Directory.Exists(directory))
                {
                    List<string> files = Directory.GetFiles(directory).ToList();
                    if (path != "")
                    {
                        if (files.Contains(path))
                        {
                            return true;
                        }
                    }
                    else
                    {
                        if (files.Exists(x => x.Remove(0, x.LastIndexOf('/') + 1) == app))
                        {
                            return true;
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"Error - Directory ${pathDirectory} does not exist for app {app}. Your PATH variable might be broken");
                }
            }
            return false;
        }

        public static byte[] GetBytes(string inputString)
        {
            return Encoding.UTF8.GetBytes(inputString);
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


        public class IP
        {
            public required string Name;
            public required IPAddress Address;
        }

        public static List<IP> GetIpList()
        {
            List<IP> ipList = new List<IP>();
            List<NetworkInterface> networkInterfaces = NetworkInterface.GetAllNetworkInterfaces().ToList();
            networkInterfaces = networkInterfaces.Where(x => x.Name != "lo").ToList(); // Remove Loopback
            foreach (NetworkInterface ni in networkInterfaces)
            {
                foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        IP returnIp = new IP
                        {
                            Name = ni.Name,
                            Address = ip.Address
                        };
                        ipList.Add(returnIp);
                    }
                }
            }
            return ipList;
        }

        public static void PrintIpList()
        {
            List<IP> ipList = GetIpList();
            foreach (IP ip in ipList)
            {
                Console.WriteLine($"{ip.Name}: {ip.Address}");
            }
        }

        // Maybe move these to Web or another class?
        public static HttpStatusCode GetResponseCode(string url, string? cookie = null)
        {
            // These 2 lines fix:
            // System.Net.Http.HttpRequestException: The SSL connection could not be established
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                UseCookies = false, // Needed for a custom Cookie header
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };

            HttpClient httpClient = new(clientHandler);
            HttpRequestMessage request = new(HttpMethod.Get, url);
            if (cookie != null)
            {
                // Console.WriteLine("Setting cookie to " + cookie + " on the ResponseCode check");
                request.Headers.Add("Cookie", cookie);
            }
            HttpResponseMessage response = new();
            try
            {
                response = httpClient.Send(request);
            }
            catch (HttpRequestException hre)
            {
                if (hre.InnerException?.Message == "No such host is known.")
                {
                    Console.WriteLine("Error: " + hre.InnerException.Message);
                    Console.WriteLine($"You might have messed up the URL: {url}");
                    response.StatusCode = HttpStatusCode.PreconditionFailed;
                }
                else
                {
                    Console.WriteLine("Fatal Error in General.GetResponseCode (Bug Reelix): " + hre.InnerException?.Message);
                }
            }
            return response.StatusCode;

        }

        // HttpClient version of WebClient.DownloadFile(uri, outpath)
        public static void DownloadFile(string uri, string outputPath)
        {
            HttpClient client = new HttpClient();
            HttpRequestMessage message = new(HttpMethod.Get, uri);
            HttpResponseMessage response = client.Send(message);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                Stream httpStream = response.Content.ReadAsStream();
                FileStream fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
                httpStream.CopyTo(fileStream);
            }
        }


        public static byte[] ReceiveSocketData(Socket theSocket)
        {
            byte[] buffer = new byte[5000];
            byte[] totBuffer = new byte[5000];
            int size = theSocket.Receive(buffer, buffer.Length, 0);
            int totSize = 0;
            Array.Copy(buffer, 0, totBuffer, totSize, size);
            while (theSocket.Poll(1000, SelectMode.SelectRead))
            {
                totSize += size;
                size = theSocket.Receive(buffer);
                Array.Copy(buffer, 0, totBuffer, totSize, size);
            }
            return totBuffer;
        }

        // Changes the color of a specific string in a line of text, then everything after is white
        // Whilst colour is technically correct for EU-based, color is more often used in software development
        public static string Recolor(this string? input, Color color)
        {
            // https://misc.flogisoft.com/bash/tip_colors_and_formatting
            // For using one of the 256 colors on the foreground (text color), the control sequence is “<Esc>[38;5;ColorNumberm” where ColorNumber is one of the following colors:
            string toReturn = "";
            string backToWhite = "\u001b[97m";
            string yellow = "\u001b[38;5;228m"; // 226/227 are too bright - Either 228/229 - Not sure...
            string green = "\u001b[38;5;46m";
            string orange = "\u001b[38;5;214m";
            string red = "\u001b[38;5;9m";
            if (color == Color.Yellow)
            {
                toReturn = $"{yellow}{input}{backToWhite}";
            }
            else if (color == Color.Green)
            {
                // Console.WriteLine("Setting Green");
                toReturn = $"{green}{input}{backToWhite}";
            }
            else if (color == Color.Orange)
            {
                // Console.WriteLine("Setting Orange");
                toReturn = $"{orange}{input}{backToWhite}";
            }
            else if (color == Color.Red)
            {
                toReturn = $"{red}{input}{backToWhite}";
            }
            else if (color == Color.White)
            {
                toReturn = $"{backToWhite}";
            }
            else
            {
                Console.WriteLine("Unknown Color: " + color.Name);
            }
            return toReturn;
        }
        
        public static void HandleUnknownException(Exception ex)
        {
            string exType = ex.GetType().Name;
            StackTrace trace = new StackTrace(ex, true);
            StackFrame frame = trace.GetFrames().Last();
            int lineNumber = frame.GetFileLineNumber();
            string? fileName = frame.GetFileName();
            Console.WriteLine($"- Unhandled Error in {fileName} of type {exType} on Line {lineNumber} - Bug Reelix!".Recolor(Color.Red));
            if (ex.InnerException != null)
            {
                Console.WriteLine("-- Inner Exception: " + ex.InnerException.Message);
                if (ex.InnerException.InnerException != null)
                {
                    // Now we're going deep!
                    Console.WriteLine("--- Inner INNER Exception: " + ex.InnerException.InnerException.Message);
                }
            }
        }
    }
}
