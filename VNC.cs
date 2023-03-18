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
            Byte[] buffer = new Byte[12];
            using (Socket vncSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                vncSocket.ReceiveTimeout = 5000;
                vncSocket.SendTimeout = 5000;
                try
                {
                    vncSocket.Connect(target, port);
                    int byteCount = vncSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = Encoding.ASCII.GetString(buffer, 0, byteCount);
                    bannerText = bannerText.Trim();
                    if (bannerText.StartsWith("RFB "))
                    {
                        returnText += "- VNC Header Confirmed." + Environment.NewLine;
                        // Extract the protocol version from the data string
                        string version = bannerText.Remove(0, 4).Trim();
                        Version theVersion = Version.Parse(version);
                        returnText += "- Protocol version: " + theVersion;
                        // Extract the Auth Version
                        byteCount = vncSocket.Receive(buffer, 0, 1, SocketFlags.None);
                        Console.WriteLine("Read: " + byteCount);
                        int numSecurityTypes = buffer[0];
                        Console.WriteLine("Security Types: " + numSecurityTypes);
                        Console.WriteLine("Total Bytes: " + byteCount);
                        Console.WriteLine("Full Banner Text: " + bannerText);
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
