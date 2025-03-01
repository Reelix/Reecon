using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class POP3 // Port 110 by default
    {
        public static (string PortName, string PortData) GetInfo(string ip, int port)
        {
            string returnText = "";
            Byte[] buffer = new Byte[500];
            using (Socket popSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // Doing multiple requests with lots of data, so give it some time  
                popSocket.ReceiveTimeout = 5000;
                popSocket.SendTimeout = 5000;
                try
                {
                    popSocket.Connect(ip, port);
                    int bytes = popSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    string newlineChars = "";
                    if (bannerText.EndsWith("\r\n"))
                    {
                        returnText += "- Windows Newline Characters Detected" + Environment.NewLine;
                        newlineChars = "\r\n";
                    }
                    else if (bannerText.EndsWith("\n"))
                    {
                        returnText += "- Linux Newline Characters Detected" + Environment.NewLine;
                        newlineChars = "\n";
                    }
                    bannerText = bannerText.Trim();
                    returnText = "- Banner: " + bannerText + Environment.NewLine;
                    // CAPA bilities
                    byte[] cmdBytes = Encoding.ASCII.GetBytes(("CAPA" + newlineChars).ToCharArray());
                    popSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    bytes = popSocket.Receive(buffer, buffer.Length, 0);
                    string responseText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    List<string> capabilities = responseText.Split(newlineChars.ToCharArray()).ToList();
                    if (capabilities.Any() && capabilities[0].StartsWith("+OK CAPA"))
                    {
                        // Remove the +OK CAPA
                        capabilities.RemoveAt(0);
                        returnText += "- Capabilities: " + string.Join(',', capabilities).Trim(',').Replace(",,", ",") + Environment.NewLine;
                        // CAPA contains USER
                        if (responseText.Contains("USER"))
                        {
                            returnText += "-- USER Supported" + Environment.NewLine;

                            cmdBytes = Encoding.ASCII.GetBytes(("USER test" + newlineChars).ToCharArray());
                            popSocket.Send(cmdBytes, cmdBytes.Length, 0);
                            bytes = popSocket.Receive(buffer, buffer.Length, 0);
                            responseText = Encoding.ASCII.GetString(buffer, 0, bytes);
                            // Console.WriteLine(userText);
                            responseText = responseText.Trim();
                            returnText += $"- User \"test\": {responseText}" + Environment.NewLine;
                        }
                    }

                    // Misc Test -> ?
                    cmdBytes = Encoding.ASCII.GetBytes(("?" + newlineChars).ToCharArray());
                    popSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    bytes = popSocket.Receive(buffer, buffer.Length, 0);
                    responseText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    responseText = responseText.Trim();

                    // https://github.com/search?q=%22-ERR+Invalid+command+in+current+state%22&type=code
                    if (responseText.Contains("-ERR Invalid command in current state."))
                    {
                        returnText += "- hMailServer Detected" + Environment.NewLine;
                        // https://www.hmailserver.com/documentation/latest/?page=ts_start_server
                        // hMailServer 4.0 and forward will store hMailServer.ini in the hMailServer Bin directory to avoid this problem.
                        // https://www.hmailserver.com/documentation/latest/?page=reference_inifilesettings
                        // https://www.hmailserver.com/documentation/latest/?page=folderstructure
                        // C:\Program Files\hMailServer\Bin\hMailServer.ini
                        // returnText += "-- TODO - Path?";
                    }
                }
                catch (Exception ex)
                {
                    returnText += $"- Unknown Error: {ex.Message}";
                }
            }
            return ("POP3", returnText);
        }
    }
}
