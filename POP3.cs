using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class POP3
    {
        public static string GetInfo(string ip)
        {
            string returnText = "";
            Byte[] buffer = new Byte[500];
            using (Socket popSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // Doing multiple requests with lots of data, so give it some time  
                popSocket.ReceiveTimeout = 5000;
                popSocket.SendTimeout = 5000;
                try
                {
                    popSocket.Connect(ip, 110);
                    int bytes = popSocket.Receive(buffer, buffer.Length, 0);
                    string bannerText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    bannerText = bannerText.Trim();
                    returnText = "- Banner: " + bannerText + Environment.NewLine;
                    // Console.WriteLine(returnText);
                    byte[] cmdBytes = Encoding.ASCII.GetBytes(("USER test" + Environment.NewLine).ToCharArray());
                    popSocket.Send(cmdBytes, cmdBytes.Length, 0);
                    bytes = popSocket.Receive(buffer, buffer.Length, 0);
                    string userText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    // Console.WriteLine(userText);
                    userText = userText.Trim();
                    returnText += $"- User Test: {userText}";

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
