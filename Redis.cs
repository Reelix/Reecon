using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class Redis
    {
        public static string GetInfo(string ip, int port)
        {
            // This has only been tested on a non-passworded Redis 4 Server, so will probably break anywhere else
            string returnText = "";
            Byte[] buffer = new Byte[5000];
            using (Socket redisSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // Doing multiple requests with lots of data, so give it some time  
                redisSocket.ReceiveTimeout = 10000;
                redisSocket.SendTimeout = 5000;
                try
                {
                    redisSocket.Connect(ip, port); // Error if an invalid IP
                    byte[] cmdBytes = Encoding.ASCII.GetBytes(("INFO" + Environment.NewLine).ToCharArray());
                    redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    // Get basic info
                    int bytes = redisSocket.Receive(buffer, buffer.Length, 0);
                    string redisText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    redisText = redisText.Trim();
                    List<string> redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                    string redisVersion = redisLines.First(x => x.StartsWith("redis_version:"));
                    returnText += "- " + redisVersion;
                    string os = redisLines.First(x => x.StartsWith("os:"));
                    returnText += Environment.NewLine + "- " + os;
                    string osBits = redisLines.First(x => x.StartsWith("arch_bits:"));
                    returnText += Environment.NewLine + "- " + osBits;
                    string exeLocation = redisLines.First(x => x.StartsWith("executable:"));
                    returnText += Environment.NewLine + "- " + exeLocation;
                    string configLocation = redisLines.First(x => x.StartsWith("config_file:"));
                    returnText += Environment.NewLine + "- " + configLocation;
                    string connectedClients = redisLines.First(x => x.StartsWith("connected_clients:"));
                    returnText += Environment.NewLine + "- " + connectedClients;

                    // Get dbfilenme
                    cmdBytes = Encoding.ASCII.GetBytes(("CONFIG GET dbfilename" + Environment.NewLine).ToCharArray());
                    redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    bytes = redisSocket.Receive(buffer, buffer.Length, 0);
                    redisText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                    string dbfilename = "";
                    if (redisLines.Count == 6)
                    {
                        dbfilename += Environment.NewLine + "-- CONFIG GET dbfilename: " + redisLines[4];
                        returnText += dbfilename;
                    }

                    // Get dir
                    cmdBytes = Encoding.ASCII.GetBytes(("CONFIG GET dir" + Environment.NewLine).ToCharArray());
                    redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    bytes = redisSocket.Receive(buffer, buffer.Length, 0);
                    redisText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                    string dir = "";
                    if (redisLines.Count == 6)
                    {
                        dir += Environment.NewLine + "-- CONFIG GET dir: " + redisLines[4];
                        returnText += dir;
                    }
                }
                catch (Exception ex)
                {
                    returnText += Environment.NewLine + "- Error - Cannot pull Redis Text: " + ex.Message;
                }
            }
            return returnText;
        }
    }
}
