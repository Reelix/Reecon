using System;
using System.Net.Sockets;
using System.Text;
using static Reecon.OSINT_Instagram_Info;

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
                        // https://www.dcs.ed.ac.uk/home/vnc/rfbproto.pdf
                        // Handshaking begins by the server sending the client a ProtocolVersion message. This
                        // lets the client know which is the latest RFB protocol version number supported by the
                        // server
                        returnText += "- VNC Header Confirmed." + Environment.NewLine;
                        // Extract the protocol version from the data string
                        string version = bannerText.Remove(0, 4).Trim();
                        Version theVersion = Version.Parse(version);
                        returnText += "- Protocol version: " + theVersion + Environment.NewLine;

                        // The client then replies with a similar message giving the version number of the protocol which should actually be used
                        // Console.WriteLine("Sending back....");
                        // vncSocket.Send(buffer, 0, byteCount, SocketFlags.None);
                        // byteCount = vncSocket.Receive(buffer, buffer.Length, 0);
                        // Once the protocol version has been decided, the server then sends a word indicating the
                        // authentication scheme to be used on the connection:
                    }
                    else
                    {
                        // Not VNC
                        returnText += "- Unknown VNC Header: " + bannerText + Environment.NewLine;
                        string portInfo = PortInfo.FindUnknownPortInfo(target, port);
                        return portInfo;
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
