using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Reecon
{
    class General
    {
        public static string BannerGrab(string ip, int port, string initialText = "", int bufferSize = 512, int timeout = 10000)
        {
            string bannerText = "";
            Byte[] buffer = new Byte[bufferSize];
            using (Socket bannerGrabSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
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
                    // 10060 - Timeout (WSAETIMEDOUT)
                    // 10035 - Blocking (WSAEWOULDBLOCK)
                    // Mono on Linux and Mono on Windows has different errors
                    // https://github.com/mono/mono/blob/master/mcs/class/System/Test/System.Net.Sockets/NetworkStreamTest.cs#L71-L72
                    if (ex.ErrorCode == 10060 || ex.ErrorCode == 10035)
                    {
                        // Do nothing - An empty banner response is handled later
                    }
                    // No connection could be made because the target machine actively refused it
                    else if (ex.ErrorCode == 10061)
                    {
                        bannerText = "Reecon - Closed";
                    }
                    // Connection reset by peer
                    else if (ex.ErrorCode == 10054)
                    {
                        bannerText = "Reecon - Connection reset by peer";
                    }
                    else
                    {
                        Console.WriteLine($"Error in BannerGrab with error code: {ex.ErrorCode}");
                        throw ex;
                    }
                }
                catch (Exception ex)
                {
                    /*
                    // Mono - Linux Message
                    if (ex.Message == "Operation on non-blocking socket would block")
                    {
                        bannerText = "";
                    }
                    // Mono - Windows Message / .NET Framework Message
                    else if (ex.Message == "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond")
                    {
                        bannerText = "";
                    }
                    */
                    // Someone doesn't want us here - Need to find the specific ErrorCode to stick it above
                    if (ex.Message == "Connection reset by peer")
                    {
                        Console.WriteLine("In Exception with connection reset by peer");
                        bannerText = "Connection reset by peer";
                    }
                    else
                    {
                        Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                        return "";
                    }
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
                bannerText = BannerGrab(ip, port, "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n");
            }
            return bannerText;
        }

        // This is for custom requests where you know the actual bytes to send
        public static byte[] BannerGrabBytes(string ip, int port, List<byte[]> bytesToSend, int bufferSize = 1024)
        {
            byte[] returBuffer = Array.Empty<byte>();
            byte[] buffer = new byte[bufferSize];
            using (Socket bannerGrabSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
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
                    return Encoding.ASCII.GetBytes("General.BannerGrabBytes Error: " + ex.Message);
                }
            }
        }

        public static bool IsUp(string ip)
        {
            using (Ping myPing = new Ping())
            {
                try
                {
                    PingOptions myOptions = new PingOptions();
                    PingReply reply = myPing.Send(ip, 1000);
                    if (reply.Status == IPStatus.Success)
                    {
                        return true;
                    }
                    return false;
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
                        System.Threading.Thread.Sleep(2500);
                        return false;
                    }
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
            Process p = new Process();
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
            Process p = new Process();
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
            List<string> outputLines = new List<string>();
            Process p = new Process();
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
            List<string> returnList = new List<string>();
            foreach (Match item in matchCollection)
            {
                if (!returnList.Contains(item.Value))
                {
                    returnList.Add(item.Value);
                }
            }
            return returnList;
        }

        public static void GetIP()
        {
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
                            Console.WriteLine($"{name}: {ip.Address}");
                        }
                    }
                }
            }
        }
    }
}
