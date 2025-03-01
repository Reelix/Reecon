using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Reecon
{
    class MySQL // Port 3306
    {
        // https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
        // https://svn.nmap.org/nmap/scripts/mysql-info.nse
        // --> https://svn.nmap.org/nmap/nselib/mysql.lua -> receiveGreeting
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string toReturn = "";
            // Get basic info
            (uint capabilitiesLower, byte protocol, string version) serverInfo = GetServerInfo(target, port);
            toReturn += $"- Version: {serverInfo.version}" + Environment.NewLine;
            toReturn += $"- Protocol: {serverInfo.protocol}" + Environment.NewLine;
            // toReturn += $"- Capabilities flags: {serverInfo.capabilitiesLower}" + Environment.NewLine;
            List<string> capabilities = ParseCapabilities(serverInfo.capabilitiesLower);
            if (capabilities.Count > 0)
            {
                toReturn += "- Capabilities: " + string.Join(", ", capabilities) + Environment.NewLine;
            }

            var credentials = new List<(string user, string password)>
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
            
            foreach (var cred in credentials)
            {
                (bool result, string info) tested = TestCreds(target, port, cred.user, cred.password, serverInfo.capabilitiesLower);
                if (tested.result == true)
                {
                    toReturn += tested.info;
                    break;
                }
            }
            return ("MySQL", toReturn);
        }

        static (bool result, string info) TestCreds(string server, int port, string user, string password, uint capabilitiesLower)
        {
            string returnInfo = "";
            // Console.WriteLine($"\nTesting credentials: User={user}, Password={password}");
            try
            {
                using (TcpClient client = new TcpClient(server, port) { ReceiveTimeout = 5000 })
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] buffer = new byte[2048];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (Authenticate(stream, buffer, bytesRead, user, password, capabilitiesLower))
                    {
                        returnInfo += $"- Discovered Creds: {user} / {password}" + Environment.NewLine;
                        // Console.WriteLine("Authentication successful!");
                        // Send SELECT VERSION() query and display result
                        SendQuery(stream, "SELECT User, authentication_string from mysql.user;");
                        string QueryResponse = ReadQueryResponse(stream);
                        if (QueryResponse.StartsWith("- Row"))
                        {
                            returnInfo += QueryResponse;
                            return (true, returnInfo);
                        }
                        else
                        {
                            returnInfo += "- User cannot read mysql.user";
                            return (true, returnInfo);
                        }
                        // Console.WriteLine($"Server version from query: {versionResult}");
                    }
                    else
                    {
                        return (false, "");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                if (ex is IOException ioEx && ioEx.InnerException is SocketException sockEx)
                {
                    Console.WriteLine($"Socket Error Code: {sockEx.ErrorCode}");
                }
            }
            return (false, "Error");
        }

        static (uint capabilitiesLower, byte protocol, string version) GetServerInfo(string host, int port)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (NetworkStream stream = client.GetStream())
            {
                byte[] buffer = new byte[2048];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                using (MemoryStream ms = new MemoryStream(buffer, 0, bytesRead))
                {
                    ms.Seek(4, SeekOrigin.Begin);
                    byte protocol = (byte)ms.ReadByte(); // Capture protocol version

                    StringBuilder version = new StringBuilder();
                    int b;
                    while ((b = ms.ReadByte()) != 0 && b != -1)
                    {
                        version.Append((char)b);
                    }

                    ms.Seek(4, SeekOrigin.Current); // Thread ID
                    ms.Seek(8, SeekOrigin.Current); // Salt part 1
                    ms.Seek(1, SeekOrigin.Current); // Filler

                    byte[] capabilityLowerBytes = new byte[2];
                    ms.Read(capabilityLowerBytes, 0, 2);
                    uint capabilitiesLower = BitConverter.ToUInt16(capabilityLowerBytes, 0);

                    return (capabilitiesLower, protocol, version.ToString());
                }
            }
        }

        static bool Authenticate(NetworkStream stream, byte[] packet, int length, string user, string password, uint serverCapabilities)
        {
            byte sequenceNumber = packet[3];
            using (MemoryStream ms = new MemoryStream(packet, 0, length))
            {
                ms.Seek(4, SeekOrigin.Begin);
                int protocolVersion = ms.ReadByte();
                if (protocolVersion != 0x0A) // Check for Handshake V10
                {
                    Console.WriteLine($"Unexpected protocol version: {protocolVersion:X2}");
                    Console.WriteLine("TODO: Implement support for non-Protocol 10 handshakes.");
                    return false;
                }

                while (ms.ReadByte() != 0 && ms.Position < ms.Length) { } // Skip version string

                byte[] threadIdBytes = new byte[4];
                ms.Read(threadIdBytes, 0, 4);
                int threadId = BitConverter.ToInt32(threadIdBytes, 0);
                // Console.WriteLine($"Thread ID: {threadId}");

                byte[] authPluginDataPart1 = new byte[8];
                ms.Read(authPluginDataPart1, 0, 8);
                // Console.WriteLine($"Salt Part 1: {BitConverter.ToString(authPluginDataPart1)}");

                ms.Seek(1, SeekOrigin.Current); // Filler
                ms.Seek(2, SeekOrigin.Current); // Lower capabilities
                ms.Seek(3, SeekOrigin.Current); // Charset + status

                byte[] capabilityUpperBytes = new byte[2];
                ms.Read(capabilityUpperBytes, 0, 2);

                int authPluginDataLen = ms.ReadByte();
                byte[] authPluginDataPart2 = new byte[authPluginDataLen - 8];
                ms.Seek(10, SeekOrigin.Current); // Reserved
                ms.Read(authPluginDataPart2, 0, authPluginDataPart2.Length);
                // Console.WriteLine($"Salt Part 2: {BitConverter.ToString(authPluginDataPart2)}");

                byte[] scramble = new byte[20];
                Array.Copy(authPluginDataPart1, 0, scramble, 0, 8);
                Array.Copy(authPluginDataPart2, 0, scramble, 8, 12);
                // Console.WriteLine($"Full Salt (Scramble): {BitConverter.ToString(scramble)}");

                // Define client capabilities explicitly
                uint clientCapabilities = 0x0001 | 0x0200 | 0x8000; // LongPassword, Protocol41, SecureConnection
                SendAuthResponse(stream, user, password, scramble, clientCapabilities, (byte)(sequenceNumber + 1));

                byte[] responseBuffer = new byte[2048];
                // Console.WriteLine("Waiting for server response...");
                int responseBytes = stream.Read(responseBuffer, 0, responseBuffer.Length);
                // Console.WriteLine($"Received {responseBytes} bytes");

                if (responseBytes > 0)
                {
                    // Console.WriteLine($"Server response bytes: {BitConverter.ToString(responseBuffer, 0, responseBytes)}");
                    return ParseServerResponse(responseBuffer, responseBytes);
                }
                else
                {
                    Console.WriteLine("No response bytes read!");
                    return false;
                }
            }
        }

        static List<string> ParseCapabilities(uint flags)
        {
            List<string> capabilities = new List<string>();
            if ((flags & 0x0001) != 0) capabilities.Add("LongPassword");
            if ((flags & 0x0002) != 0) capabilities.Add("FoundRows");
            if ((flags & 0x0004) != 0) capabilities.Add("LongColumnFlag");
            if ((flags & 0x0008) != 0) capabilities.Add("ConnectWithDatabase");
            if ((flags & 0x0010) != 0) capabilities.Add("DontAllowDatabaseTableColumn");
            if ((flags & 0x0020) != 0) capabilities.Add("SupportsCompression");
            if ((flags & 0x0040) != 0) capabilities.Add("ODBCClient");
            if ((flags & 0x0080) != 0) capabilities.Add("SupportsLoadDataLocal");
            if ((flags & 0x0100) != 0) capabilities.Add("IgnoreSpaceBeforeParenthesis");
            if ((flags & 0x0200) != 0) capabilities.Add("Speaks41ProtocolNew");
            if ((flags & 0x0400) != 0) capabilities.Add("InteractiveClient");
            if ((flags & 0x0800) != 0) capabilities.Add("Speaks41ProtocolOld");
            if ((flags & 0x1000) != 0) capabilities.Add("IgnoreSigpipes");
            if ((flags & 0x2000) != 0) capabilities.Add("SupportsTransactions");
            if ((flags & 0x4000) != 0) capabilities.Add("Support41Auth");
            if ((flags & 0x8000) != 0) capabilities.Add("SupportsMultipleStatments");
            return capabilities;
        }

        static void SendAuthResponse(NetworkStream stream, string user, string password, byte[] scramble, uint clientCapabilities, byte sequenceNumber)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(BitConverter.GetBytes(clientCapabilities), 0, 4);
                ms.Write(BitConverter.GetBytes(16777215), 0, 4); // Max packet size
                ms.WriteByte(33); // UTF-8 charset
                ms.Write(new byte[23], 0, 23); // Reserved
                byte[] userBytes = Encoding.ASCII.GetBytes(user);
                ms.Write(userBytes, 0, userBytes.Length);
                ms.WriteByte(0); // Null-terminated username
                byte[] authResponse = GenerateAuthResponse(password, scramble);
                // Console.WriteLine($"Hashed Password: {BitConverter.ToString(authResponse)}");
                ms.WriteByte((byte)authResponse.Length); // Length-encoded auth response
                ms.Write(authResponse, 0, authResponse.Length);
                // Removed extra null byte here
                byte[] pluginName = Encoding.ASCII.GetBytes("mysql_native_password");
                ms.Write(pluginName, 0, pluginName.Length);
                ms.WriteByte(0); // Null-terminated plugin name

                byte[] packetData = ms.ToArray();
                using (MemoryStream headerMs = new MemoryStream())
                {
                    byte[] lengthBytes = BitConverter.GetBytes(packetData.Length);
                    headerMs.Write(lengthBytes[0..3], 0, 3); // Packet length
                    headerMs.WriteByte(sequenceNumber); // Sequence number
                    headerMs.Write(packetData, 0, packetData.Length);
                    byte[] fullPacket = headerMs.ToArray();
                    // Console.WriteLine($"Sending auth packet: {BitConverter.ToString(fullPacket)}");
                    stream.Write(fullPacket, 0, fullPacket.Length);
                    stream.Flush();
                }
            }
        }

        static byte[] GenerateAuthResponse(string password, byte[] scramble)
        {
            if (string.IsNullOrEmpty(password))
                return Array.Empty<byte>();

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] passwordHash = sha1.ComputeHash(Encoding.ASCII.GetBytes(password));
                byte[] doubleHash = sha1.ComputeHash(passwordHash);
                byte[] concat = new byte[scramble.Length + doubleHash.Length];
                Array.Copy(scramble, 0, concat, 0, scramble.Length);
                Array.Copy(doubleHash, 0, concat, scramble.Length, doubleHash.Length);
                byte[] concatHash = sha1.ComputeHash(concat);

                byte[] authResponse = new byte[20];
                for (int i = 0; i < 20; i++)
                {
                    authResponse[i] = (byte)(passwordHash[i] ^ concatHash[i]);
                }
                return authResponse;
            }
        }

        static bool ParseServerResponse(byte[] response, int length)
        {
            using (MemoryStream ms = new MemoryStream(response, 0, length))
            {
                ms.Seek(4, SeekOrigin.Begin); // Skip header
                byte status = (byte)ms.ReadByte();
                if (status == 0x00)
                {
                    return true; // OK packet
                }
                else if (status == 0xFF)
                {
                    // Console.WriteLine("Error packet received:");
                    byte[] errorCodeBytes = new byte[2];
                    ms.Read(errorCodeBytes, 0, 2);
                    int errorCode = BitConverter.ToUInt16(errorCodeBytes, 0);
                    ms.Seek(1, SeekOrigin.Current); // Skip '#'
                    byte[] sqlStateBytes = new byte[5];
                    ms.Read(sqlStateBytes, 0, 5);
                    string sqlState = Encoding.ASCII.GetString(sqlStateBytes);
                    byte[] errorMessageBytes = new byte[ms.Length - ms.Position];
                    ms.Read(errorMessageBytes, 0, errorMessageBytes.Length);
                    string errorMessage = Encoding.ASCII.GetString(errorMessageBytes);
                    if (!errorMessage.StartsWith("Access denied for user"))
                    {
                        Console.WriteLine($"Fatal Error in MySQL.cs - Error Code: {errorCode}, SQL State: {sqlState}, Message: {errorMessage}");
                    }
                    else
                    {
                        return false; // ERR packet
                    }
                }
                Console.WriteLine($"Unexpected response status: {status:X2}");
                return false;
            }
        }

        // Send a query packet (COM_QUERY)
        static void SendQuery(NetworkStream stream, string query)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(0x03); // COM_QUERY command
                byte[] queryBytes = Encoding.UTF8.GetBytes(query);
                ms.Write(queryBytes, 0, queryBytes.Length);

                byte[] packetData = ms.ToArray();
                using (MemoryStream headerMs = new MemoryStream())
                {
                    byte[] lengthBytes = BitConverter.GetBytes(packetData.Length);
                    headerMs.Write(lengthBytes[0..3], 0, 3); // 3-byte length
                    headerMs.WriteByte(0x00); // Sequence number starts at 0 for new command
                    headerMs.Write(packetData, 0, packetData.Length);
                    byte[] fullPacket = headerMs.ToArray();
                    // Console.WriteLine($"Sending query packet: {BitConverter.ToString(fullPacket)}");
                    stream.Write(fullPacket, 0, fullPacket.Length);
                    stream.Flush();
                }
            }
        }

        // Read and parse the result of SELECT VERSION();
        static string ReadQueryResponse(NetworkStream stream)
        {
            byte[] buffer = new byte[2048];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                return "No response received from query!";
            }
            // Console.WriteLine($"Full response buffer: {BitConverter.ToString(buffer, 0, bytesRead)}");

            using (MemoryStream ms = new MemoryStream(buffer, 0, bytesRead))
            {
                // Column count packet
                ms.Seek(4, SeekOrigin.Begin); // Skip 3-byte length + 1-byte seq
                byte packetType = (byte)ms.ReadByte();

                if (packetType == 0xFF) // Error packet
                {
                    byte[] errorCodeBytes = new byte[2];
                    ms.Read(errorCodeBytes, 0, 2);
                    int errorCode = BitConverter.ToUInt16(errorCodeBytes, 0);
                    ms.Seek(1, SeekOrigin.Current); // Skip '#'
                    byte[] sqlStateBytes = new byte[5];
                    ms.Read(sqlStateBytes, 0, 5);
                    string sqlState = Encoding.ASCII.GetString(sqlStateBytes);
                    byte[] errorMessageBytes = new byte[ms.Length - ms.Position];
                    ms.Read(errorMessageBytes, 0, errorMessageBytes.Length);
                    string errorMessage = Encoding.ASCII.GetString(errorMessageBytes);
                    return $"Query error - Code: {errorCode}, SQL State: {sqlState}, Message: {errorMessage}";
                }
                string toReturn = "";
                int columnCount = packetType; // Number of columns
                
                // Parse column definition packets
                int packetLength = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
                ms.Seek(packetLength + 4, SeekOrigin.Begin); // Skip column count packet

                string[] columnNames = new string[columnCount];
                string[] columnTypes = new string[columnCount];
                int[] columnLengths = new int[columnCount];

                for (int i = 0; i < columnCount; i++)
                {
                    if (ms.Position >= ms.Length)
                    {
                        bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0)
                        {
                            return "Fatal Error in MySQL.cs - No column definition received!";
                        }
                        ms.SetLength(0);
                        ms.Write(buffer, 0, bytesRead);
                        ms.Seek(0, SeekOrigin.Begin);
                    }

                    packetLength = buffer[(int)ms.Position] | (buffer[(int)ms.Position + 1] << 8) | (buffer[(int)ms.Position + 2] << 16);
                    // Console.WriteLine($"Column def {i + 1} packet at {ms.Position}: {BitConverter.ToString(buffer, (int)ms.Position, packetLength + 4)}");
                    ms.Seek(4, SeekOrigin.Current); // Skip header

                    // Parse column definition (https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html)
                    ms.Seek(ReadLengthEncodedInteger(ms), SeekOrigin.Current); // Skip catalog
                    ms.Seek(ReadLengthEncodedInteger(ms), SeekOrigin.Current); // Skip schema
                    ms.Seek(ReadLengthEncodedInteger(ms), SeekOrigin.Current); // Skip table
                    ms.Seek(ReadLengthEncodedInteger(ms), SeekOrigin.Current); // Skip org_table
                    int nameLength = ReadLengthEncodedInteger(ms);
                    byte[] nameBytes = new byte[nameLength];
                    ms.Read(nameBytes, 0, nameLength);
                    columnNames[i] = Encoding.UTF8.GetString(nameBytes);
                    ms.Seek(ReadLengthEncodedInteger(ms), SeekOrigin.Current); // Skip org_name

                    int fixedFieldsLength = ReadLengthEncodedInteger(ms); // Should be 0x0C (12 bytes)
                    if (fixedFieldsLength != 0x0C) throw new Exception("Unexpected fixed fields length");
                    byte[] fixedFields = new byte[12];
                    ms.Read(fixedFields, 0, 12);

                    // Extract useful info
                    int charset = fixedFields[0] | (fixedFields[1] << 8);
                    columnLengths[i] = BitConverter.ToInt32(fixedFields, 2); // Column length
                    byte type = fixedFields[6]; // Column type
                    columnTypes[i] = type switch
                    {
                        0xFE => "VARCHAR",
                        0xFD => "VARBINARY",
                        0x0F => "CHAR",
                        0xFC => "BLOB",
                        _ => $"Unknown (0x{type:X2})"
                    };

                    // Console.WriteLine($"Column {i + 1}: Name={columnNames[i]}, Type={columnTypes[i]}, Length={columnLengths[i]}, Charset={charset}");
                }

                // Skip first EOF packet
                if (ms.Position + 9 > ms.Length)
                {
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        return "Fatal Error in MySQL.cs - No EOF packet received!";
                    }
                    ms.SetLength(0);
                    ms.Write(buffer, 0, bytesRead);
                    ms.Seek(0, SeekOrigin.Begin);
                }
                packetLength = buffer[(int)ms.Position] | (buffer[(int)ms.Position + 1] << 8) | (buffer[(int)ms.Position + 2] << 16);
                // Console.WriteLine($"EOF packet at {ms.Position}: {BitConverter.ToString(buffer, (int)ms.Position, packetLength + 4)}");
                ms.Seek(packetLength + 4, SeekOrigin.Current); // Skip EOF

                // Read row data packets until EOF
                while (true)
                {
                    if (ms.Position + 4 >= ms.Length)
                    {
                        bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0)
                        {
                            return "Fatal Error in MySQL.cs - No more row data received!";
                        }
                        ms.SetLength(0);
                        ms.Write(buffer, 0, bytesRead);
                        ms.Seek(0, SeekOrigin.Begin);
                    }

                    packetLength = buffer[(int)ms.Position] | (buffer[(int)ms.Position + 1] << 8) | (buffer[(int)ms.Position + 2] << 16);
                    byte sequence = buffer[(int)ms.Position + 3];
                    ms.Seek(4, SeekOrigin.Current); // Skip header
                    if (ms.ReadByte() == 0xFE && packetLength < 9) // EOF packet
                    {
                        // Console.WriteLine($"Final EOF packet at {ms.Position - 5}: {BitConverter.ToString(buffer, (int)ms.Position - 5, packetLength + 4)}");
                        break;
                    }
                    ms.Seek(-1, SeekOrigin.Current); // Backtrack to start of row data

                    // Console.WriteLine($"Row data packet at {ms.Position - 4}: {BitConverter.ToString(buffer, (int)ms.Position - 4, packetLength + 4)}");
                    List<string> rowValues = new List<string>();
                    for (int i = 0; i < columnCount; i++)
                    {
                        int valueLength = ReadLengthEncodedInteger(ms);
                        byte[] valueBytes = new byte[valueLength];
                        ms.Read(valueBytes, 0, valueLength);
                        rowValues.Add(Encoding.UTF8.GetString(valueBytes));
                    }
                    toReturn += $"- Row: {columnNames[0]}={rowValues[0]}, {columnNames[1]}={rowValues[1]}" + Environment.NewLine;
                }
                return toReturn;
            }
        }

        // Helper to read MySQL length-encoded integer
        static int ReadLengthEncodedInteger(MemoryStream ms)
        {
            byte firstByte = (byte)ms.ReadByte();
            if (firstByte < 0xFB) // 1-byte integer
                return firstByte;
            if (firstByte == 0xFC) // 2-byte integer
            {
                byte[] bytes = new byte[2];
                ms.Read(bytes, 0, 2);
                return BitConverter.ToUInt16(bytes, 0);
            }
            if (firstByte == 0xFD) // 3-byte integer
            {
                byte[] bytes = new byte[3];
                ms.Read(bytes, 0, 3);
                return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
            }
            if (firstByte == 0xFE) // 8-byte integer
            {
                byte[] bytes = new byte[8];
                ms.Read(bytes, 0, 8);
                return (int)BitConverter.ToInt64(bytes, 0);
            }
            throw new Exception("Invalid length-encoded integer");
        }
    }
}
