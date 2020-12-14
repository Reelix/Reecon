using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class Telnet // Port 23
    {
        public static string GetInfo(string ip, int port)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            int timeout = 5000; // ms
            string bannerText = "";
            Byte[] buffer = new Byte[512];
            using (Socket telnetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                telnetSocket.ReceiveTimeout = timeout;
                telnetSocket.SendTimeout = timeout;
                try
                {
                    var result = telnetSocket.BeginConnect(ip, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        // Back and forth handshakes for some reason - I have no idea...
                        // Receive 1 - And Parrot
                        int bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                        if (buffer[0] == 255 && buffer[1] == 253 && buffer[2] == 24)
                        {
                            telnetSocket.Send(buffer, bytes, 0);
                            // Receive 2 - And Parrot
                            bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                            telnetSocket.Send(buffer, bytes, 0);
                            // Receive 3 - And Parrot
                            bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                            telnetSocket.Send(buffer, bytes, 0);
                            // Receive 4 - And Parrot
                            bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                            telnetSocket.Send(buffer, bytes, 0);
                            // Receive 5 - And Parrot
                            bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                            telnetSocket.Send(buffer, bytes, 0);
                            // Receive 6 - And this is the one we want
                            bytes = telnetSocket.Receive(buffer, buffer.Length, 0);
                            string response = Encoding.UTF8.GetString(buffer, 0, bytes);
                            if (response.Length > 5)
                            {
                                return "- - - - - - - - - - - - - - - -" + Environment.NewLine + response + Environment.NewLine + "- - - - - - - - - - - - - - - -";
                            }
                            else if (response.Length > 0)
                            {
                                return "- Weird response length: " + response;
                            }
                            else
                            {
                                return "- No Response :<";
                            }
                        }
                        else
                        {
                            return "- Invalid Telnet Response :<";
                        }

                    }
                    bannerText = bannerText.Trim();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error in Telnet.cs: " + ex.Message + " - Bug Reelix");
                }
            }
            return "- :(";
        }
    }
}