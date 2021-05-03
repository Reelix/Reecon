using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class VNC
    {
        public static string GetInfo(string target, int port)
        {
            string returnText = "";
            Byte[] buffer = new Byte[500];
            using (Socket vncSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                vncSocket.ReceiveTimeout = 5000;
                vncSocket.SendTimeout = 5000;
                try
                {
                    vncSocket.Connect(target, port);
                    int bytes = vncSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    bannerText = bannerText.Trim();
                    if (bannerText.StartsWith("RFB 003.008")) // RFB 003.008\n
                    {
                        // Send the banner header back
                        byte[] cmdBytes = Encoding.ASCII.GetBytes((bannerText + Environment.NewLine).ToCharArray());
                        vncSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        bytes = vncSocket.Receive(buffer, buffer.Length, 0);
                        if (bytes == 3)
                        {
                            returnText += "- VNC Header Confirmed (RFB 3.8 - 3 Perm Bytes)" + Environment.NewLine;
                        }
                        else
                        {
                            returnText += "- Unknown VNC Perm Bytes: " + bytes;
                        }
                    }
                    else
                    {
                        returnText += "- Unknown VNC Header: " + bannerText;
                    }
                }
                catch (Exception ex)
                {
                    returnText += $"- Unknown Error: {ex.Message}";
                }
            }
            return returnText;
        }
    }
}
