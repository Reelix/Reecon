using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class Rsync // Generally Port 873 - And a lower case s in sync
    {
        public static string GetInfo(string ip, int port)
        {
            string returnText = "";
            Byte[] buffer = new Byte[5000];
            using (Socket rsyncSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                // It's SLOW!
                rsyncSocket.ReceiveTimeout = 15000;
                rsyncSocket.SendTimeout = 5000;
                try
                {

                    rsyncSocket.Connect(ip, port);
                    /*
                    Connection to 10.10.10.200 873 port[tcp/*] succeeded!
                    @RSYNCD: 31.0
                    @RSYNCD: 31.0
                    #list
                    conf_backups    EncFS-encrypted configuration backups
                    @RSYNCD: EXIT
                    */
                    // Get Version Header
                    int bytes = rsyncSocket.Receive(buffer, buffer.Length, 0);
                    string versionText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    if (!versionText.StartsWith("@RSYNCD"))
                    {
                        return "- Invalid RSync Header: " + versionText;
                    }
                    else
                    {
                        // Cannot clean up the actual versionText variable since we need the exact thing on the return
                        returnText += "- Version: " + versionText.Trim() + Environment.NewLine;
                    }
                    // Parrot Back with a list command
                    byte[] cmdBytes = Encoding.ASCII.GetBytes((versionText + Environment.NewLine + "#list").ToCharArray());
                    rsyncSocket.Send(cmdBytes, cmdBytes.Length, 0);

                    // Get Result
                    bytes = rsyncSocket.Receive(buffer, buffer.Length, 0);
                    string listText = Encoding.ASCII.GetString(buffer, 0, bytes);
                    List<string> listLines = listText.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).ToList();
                    foreach (string item in listLines)
                    {
                        returnText += "-- File: " + item;
                    }
                }
                catch (Exception ex)
                {
                    returnText += Environment.NewLine + "- Error - Cannot pull Rsync Text: " + ex.Message;
                }
            }
            return returnText;
        }
    }
}
