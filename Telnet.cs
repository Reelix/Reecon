using System;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class Telnet // Port 23
    {
        public static (string, string) GetInfo(string ip, int port)
        {
            Console.OutputEncoding = Encoding.UTF8;
            int timeout = 5000; // ms
            string bannerText = "";
            Byte[] buffer = new Byte[512];
            using (Socket telnetSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
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
                        // https://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
                        // https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
                        // IAC,<type of operation>,<option>
                        // IAC: 255
                        // Type: ??
                        if (buffer[0] == 255 && buffer[1] == 253)
                        {
                            // Option: 1 = Echo - RFC857
                            if (buffer[2] == 1)
                            {
                                return ("Telnet (Echo)", "- Valid Telnet response, but it's an Echo service (RFC857) - You can probably ignore this");
                            }
                            // Option: 24 = Terminal Type - RFC1091
                            else if (buffer[2] == 24)
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
                                    return ("Telnet?", "- - - - - - - - - - - - - - - -" + Environment.NewLine + response + Environment.NewLine + "- - - - - - - - - - - - - - - -");
                                }
                                else if (response.Length > 0)
                                {
                                    return ("Telnet?", "- Weird response length: " + response);
                                }
                                else
                                {
                                    return ("Telnet?", "- No Response :<");
                                }
                            }
                            // 37 = Authentication Option - RFC2941
                            else if (buffer[2] == 37)
                            {
                                return ("Telnet", "- Authentication required");
                            }
                            else
                            {
                                return ("Telnet?", "- Unhandled Telnet Response Code " + (int)buffer[2] + " - Bug Reelix!");
                            }
                        }
                        else
                        {
                            return ("Telnet?", "- Invalid Telnet Response :<");
                        }

                    }
                    bannerText = bannerText.Trim();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error in Telnet.cs: " + ex.Message + " - Bug Reelix");
                }
            }
            return ("Telnet?", "- :(");
        }
    }
}