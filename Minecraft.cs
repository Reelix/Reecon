using System;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    // Port 25565
    class Minecraft
    {
        public static (string, string) GetInfo(string ip, int port)
        {
            string returnText = "";
            Byte[] buffer = new Byte[5000];
            using (Socket minecraftSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // https://wiki.vg/Server_List_Ping#1.6
                // https://gist.github.com/Emzi0767/6223787
                minecraftSocket.ReceiveTimeout = 5000;
                minecraftSocket.SendTimeout = 5000;
                try
                {
                    minecraftSocket.Connect(ip, port);
                    minecraftSocket.Send(new byte[] { 0xFE, 0x01 });
                    int bytes = minecraftSocket.Receive(buffer, buffer.Length, 0);
                    if (buffer[0] != 0xFF)
                    {
                        throw new InvalidDataException("Received invalid packet");
                    }
                    string packet = Encoding.BigEndianUnicode.GetString(buffer, 3, bytes - 3);
                    if (!packet.StartsWith("§"))
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
