using System;
using System.Net.Sockets;
using System.Text;
using System.Net.NetworkInformation;

namespace ReeRecon
{
    class General
    {
        public static string BannerGrab(string ip, int port)
        {
            Byte[] buffer = new Byte[512];
            using (Socket sshSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    sshSocket.Connect(ip, port); // Error if an invalid IP
                    Byte[] cmdBytes = Encoding.ASCII.GetBytes(("HELLO\r\n").ToCharArray());
                    sshSocket.Send(cmdBytes, cmdBytes.Length, 0);

                    // Port 445 - System.Net.Sockets.SocketException (0x80004005): Connection reset by peer
                    int bytes = sshSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    bannerText = bannerText.Trim();
                    return bannerText;
                }
                catch
                {
                    return "";
                }
            }
        }

        public static bool IsUp(string ip)
        {
            Ping myPing = new Ping();
            PingReply reply = myPing.Send(ip, 1000);
            myPing.Dispose();
            if (reply.Status == IPStatus.Success)
            {
                return true;
            }
            return false;
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
