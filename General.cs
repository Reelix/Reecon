using System;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class General
    {
        public static string BannerGrab(string ip, int port, string initialText = "")
        {
            string bannerText = "";
            Byte[] buffer = new Byte[512];
            using (Socket bannerGrabSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = 5000;
                bannerGrabSocket.SendTimeout = 5000;
                try
                {
                    bannerGrabSocket.Connect(ip, port); // Error if an invalid IP
                    if (initialText != "")
                    {
                        Byte[] cmdBytes = Encoding.ASCII.GetBytes(initialText.ToCharArray());
                        bannerGrabSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    }
                    int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                    bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    bannerText = bannerText.Trim();
                }
                catch (Exception ex)
                {
                    // Mono Timeout Message
                    if (ex.Message == "Operation on non-blocking socket would block")
                    {
                        return "";
                    }
                    // .NET Framework Timeout Message
                    else if (ex.Message == "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond")
                    {
                        bannerText = BannerGrab(ip, port, "Woof" + Environment.NewLine + Environment.NewLine);
                    }
                    // Someone doesn't want us here
                    else if (ex.Message == "Connection reset by peer")
                    {
                        bannerText = "Connection reset by peer";
                    }
                    else
                    {
                        Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                        return "";
                    }
                }
            }
            if (bannerText == "" && initialText == "")
            {
                Console.WriteLine("Port " + port + " - No initial response - Trying more");
                bannerText = BannerGrab(ip, port, "Woof" + Environment.NewLine + Environment.NewLine);
            }
            return bannerText;
        }

        public static string BannerGrab2(string ip, int port)
        {
            Byte[] buffer = new Byte[512];
            using (Socket bannerGrabSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                bannerGrabSocket.ReceiveTimeout = 30000;
                bannerGrabSocket.SendTimeout = 30000;
                try
                {
                    bannerGrabSocket.Connect(ip, port); // Error if an invalid IP
                    Byte[] cmdBytes = Encoding.ASCII.GetBytes(("HEAD / HTTP/1.1" + Environment.NewLine + Environment.NewLine).ToCharArray());
                    int bytes = bannerGrabSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = "";
                    if (bytes != 0)
                    {
                        // Received something from the get go!
                        Console.WriteLine("Received Bytes: " + bytes);
                        bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                        return bannerText.Trim();
                    }
                    return bannerText;
                }
                catch (Exception ex)
                {
                    // Mono Timeout Message
                    if (ex.Message == "Operation on non-blocking socket would block")
                    {
                        return "";
                    }
                    // .NET Framework Timeout Message
                    else if (ex.Message == "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond")
                    {
                        return "";
                    }
                    // Someone doesn't want us here
                    else if (ex.Message == "Connection reset by peer")
                    {
                        return "Connection reset by peer";
                    }
                    else
                    {
                        Console.WriteLine($"Error in General.BannerGrab ({ip}:{port} - {ex.Message})");
                        return "";
                    }
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
    }
}
