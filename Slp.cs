using System;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    // Port 25565
    internal static class Slp // Server List Ping - Technically Legacy Server List Ping, but it's fine for now
    {
        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnText = "";
            byte[] buffer = new byte[5000];
            using (Socket slpSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // https://wiki.vg/Server_List_Ping#1.6
                // https://gist.github.com/Emzi0767/6223787
                slpSocket.ReceiveTimeout = 5000;
                slpSocket.SendTimeout = 5000;
                try
                {
                    slpSocket.Connect(ip, port);
                    slpSocket.Send(new byte[] { 0xFE, 0x01 });
                    int bytes = slpSocket.Receive(buffer, buffer.Length, 0);
                    if (buffer[0] != 0xFF)
                    {
                        throw new InvalidDataException("Received invalid packet");
                    }
                    string packet = Encoding.BigEndianUnicode.GetString(buffer, 3, bytes - 3);
                    if (!packet.StartsWith('§'))
                    {
                        throw new InvalidDataException("Received invalid data");
                    }
                    string[] packetData = packet.Split('\u0000');
                    returnText = "- " + "Minecraft Server Detected".Recolor(Color.Green) + Environment.NewLine;
                    returnText += "-- Protocol Version: " + packetData[1] + Environment.NewLine;
                    returnText += "-- Server Version: " + packetData[2] + Environment.NewLine;
                    returnText += "-- Message Of The Day: " + packetData[3] + Environment.NewLine;
                    string currentPlayerCount = packetData[4];
                    string maxPlayerCount = packetData[5];
                    returnText += $"-- Players: {currentPlayerCount}/{maxPlayerCount}" + Environment.NewLine;
                }
                catch (TimeoutException)
                {
                    returnText += "- Error: " + "Timeout".Recolor(Color.Red) + Environment.NewLine;
                }
                catch (Exception ex)
                {
                    returnText += "- Error - Cannot pull Minecraft Server Info: " + ex.Message + Environment.NewLine;
                }
            }
            returnText = returnText.Trim(Environment.NewLine.ToCharArray());
            return ("Minecraft", returnText);
        }
    }
}
