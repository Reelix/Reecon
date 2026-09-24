using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    internal static class MySql // Port 3306
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string toReturn = "";
            // Get basic info
            (uint CapabilitiesLower, byte Protocol, string Version, string AuthPlugin) serverInfo = GetServerInfo(target, port);
            if (serverInfo.Protocol == 0xFF)
            {
                // An Error
                int errorCode = int.Parse(serverInfo.Version.Split('|')[0]); // 1130 = // ER_HOST_NOT_PRIVILEGED
                string errorMessage = serverInfo.Version.Split('|')[1];
                toReturn += $"- Cannot Connect: {errorMessage} (Error Code: {errorCode})" + Environment.NewLine;
                if (errorCode == 1130)
                {
                    toReturn += "-- The MySQL host blocks access to your IP - No other info can be gained.";
                }

                return ("MySQL", toReturn);
            }

            // No errors - Carry on!
            toReturn += $"- Version: {serverInfo.Version}" + Environment.NewLine;
            toReturn += $"- Protocol: {serverInfo.Protocol}" + Environment.NewLine;
            // toReturn += $"- Capabilities flags: {serverInfo.capabilitiesLower}" + Environment.NewLine;
            List<string> capabilities = MySql_Protocol.ParseCapabilities(serverInfo.CapabilitiesLower);
            if (capabilities.Count > 0)
            {
                toReturn += "- Capabilities: " + string.Join(", ", capabilities) + Environment.NewLine;
            }

            toReturn += $"- Auth Plugin: {serverInfo.AuthPlugin}" + Environment.NewLine;

            // https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
            List<(string Username, string Password)> credentials = new List<(string, string)>
            {
                ("root", "mysql"),
                ("root", "root"),
                ("root", "chippc"),
                ("admin", ""),
                ("admin", "admin"),
                ("root", ""),
                ("root", "nagiosxi"),
                ("root", "usbw"),
                ("cloudera", "cloudera"),
                ("root", "cloudera"),
                ("root", "moves"),
                ("moves", "moves"),
                ("root", "testpw"),
                ("root", "p@ck3tf3nc3"),
                ("mcUser", "medocheck123"),
                ("root", "mktt"),
                ("root", "123"),
                ("dbuser", "123"),
                ("asteriskuser", "amp109"),
                ("asteriskuser", "eLaStIx.asteriskuser.2oo7"),
                ("root", "password"),
                ("root", "raspberry"),
                ("root", "openauditrootuserpassword"),
                ("root", "vagrant"),
                ("root", "123qweASD#"),
            };

            foreach (var credential in credentials)
            {
                try
                {
                    // Console.WriteLine($"Trying {cred.Username}:{cred.Password}");
                    using (TcpClient client = new TcpClient(target, port))
                    {
                        client.ReceiveTimeout = 5000;
                        using (NetworkStream stream = client.GetStream())
                        {
                            (bool IsAuthenticated, string Response) result = MySql_Protocol.Authenticate(stream, credential.Username, credential.Password, serverInfo.AuthPlugin);
                            if (!result.IsAuthenticated)
                            {
                                if (result.Response == "")
                                {
                                    // Console.WriteLine("Incorrect Credentials");
                                    // Incorrect password, but no errors - Carry on
                                }
                                else
                                {
                                    // Something bad happened - Abort!
                                    // Defensive split to prevent IndexOutOfRangeException
                                    string[] parts = result.Response.Split('|');
                                    string errorCode = parts.Length > 0 ? parts[0] : "-1";
                                    string errorMessage = parts.Length > 1 ? parts[1] : "Unknown error";

                                    toReturn += $"- Error in MySQL.cs - {errorCode}: {errorMessage}";
                                    break;
                                }
                            }
                            else
                            {
                                toReturn += "- " + $"Discovered Creds: {credential.Username} / {credential.Password}".Recolor(Color.Orange) + Environment.NewLine;
                                // Console.WriteLine("Authentication successful!");
                                // Send SELECT VERSION() query and display result
                                MySql_Protocol.SendQuery(stream, "SELECT User, authentication_string from mysql.user;");
                                string queryResponse = MySql_Protocol.ReadQueryResponse(stream);
                                if (queryResponse.StartsWith("-- Row"))
                                {
                                    toReturn += queryResponse;
                                    break;
                                }

                                toReturn += "- User cannot read mysql.user";
                                break;
                                // Console.WriteLine($"Server version from query: {versionResult}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    General.HandleUnknownException(ex);
                }
            }

            return ("MySQL", toReturn.Trim(Environment.NewLine.ToCharArray()));
        }

        private static (uint CapabilitiesLower, byte Protocol, string Version, string AuthPlugin) GetServerInfo(string host, int port)
        {
            using (TcpClient client = new TcpClient(host, port))
            {
                using (NetworkStream stream = client.GetStream())
                {
                    MySql_Protocol.BasicPacket packet = MySql_Protocol.BasicPacket.Read(stream);
                    MySql_Protocol.HandshakeV10 handshake = MySql_Protocol.HandshakeV10.Parse(packet);

                    if (handshake.ProtocolVersion == 0xFF) // Error packet
                    {
                        if (handshake.ErrorCode != 1130) // ER_HOST_NOT_PRIVILEGED - Host 'x.x.x.x' is not allowed to connect to this MySQL server
                        {
                            Console.WriteLine($"Server returned unknown error code: {handshake.ErrorCode}");
                        }

                        return (0, handshake.ProtocolVersion, $"{handshake.ErrorCode}|{handshake.ErrorMessage}", "");
                    }

                    return (handshake.Capabilities, handshake.ProtocolVersion, handshake.ServerVersion, handshake.AuthPluginName);
                }
            }
        }

        public static bool CheckBanner(List<byte> buffer)
        {
            // 1. Minimum MySQL packet: 4 bytes header + at least 1 byte payload
            if (buffer.Count < 5) return false;

            // 2. Validate MySQL Packet Framing (3-byte Length + 1-byte Sequence ID)
            int payloadLength = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
            byte sequenceId = buffer[3];

            // The initial packet from MySQL MUST have sequence ID == 0
            if (sequenceId != 0) return false;

            // Received byte count must match the declared packet length + 4-byte header
            if (buffer.Count < payloadLength + 4) return false;

            byte packetType = buffer[4];

            // Case A: HandshakeV10 Banner (0x0A)
            if (packetType == 0x0A && buffer.Count > 5)
            {
                // HandshakeV10 contains a null-terminated version string starting at index 5
                int nullPos = buffer.IndexOf(0, 5);
                if (nullPos > 5)
                {
                    // Thread ID (4 bytes) + Auth Data Part 1 (8 bytes) + Filler (1 byte)
                    // The filler byte at (nullPos + 1 + 4 + 8) must always be 0x00
                    int fillerPos = nullPos + 13;
                    if (fillerPos < buffer.Count && buffer[fillerPos] == 0x00)
                    {
                        return true;
                    }
                }
            }

            // Case B: Connection Error Packet (0xFF)
            if (packetType == 0xFF && buffer.Count >= 7)
            {
                // Little-endian error code
                ushort errorCode = (ushort)(buffer[5] | (buffer[6] << 8));

                // Common MySQL initial connection rejection error codes:
                // 1130 = ER_HOST_NOT_PRIVILEGED (Host not allowed)
                // 1040 = ER_CON_COUNT_ERROR (Too many connections)
                // 1129 = ER_HOST_IS_BLOCKED (Blocked due to connection errors)
                if (errorCode is 1130 or 1040 or 1129)
                {
                    return true;
                }

                // Fallback: Check if message contains standard MySQL/MariaDB text
                string message = Encoding.UTF8.GetString(buffer.ToArray(), 7, buffer.Count - 7);
                if (message.Contains("MySQL", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("MariaDB", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}