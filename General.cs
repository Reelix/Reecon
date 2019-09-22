using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ReeRecon
{
    class General
    {
        public static string BannerGrab(string ip, int port)
        {
            Byte[] buffer = new Byte[512];
            Socket sshSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sshSocket.Connect(ip, port);
            Byte[] cmdBytes = Encoding.ASCII.GetBytes(("HELLO\r\n").ToCharArray());
            sshSocket.Send(cmdBytes, cmdBytes.Length, 0);
            try
            {
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
}
