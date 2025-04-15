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
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            string toReturn = "";
            // Get basic info
            (uint CapabilitiesLower, byte Protocol, string Version) serverInfo = GetServerInfo(target, port);
            if (serverInfo.Protocol == 0xFF)
            {
                // An Error
                int errorCode = int.Parse(serverInfo.Version.Split('|')[0]); // 1130 = // ER_HOST_NOT_PRIVILEGED
                string errorMessage = serverInfo.Version.Split('|')[1];
                toReturn += $"- Error - Cannot Connect: {errorMessage} (Error Code: {errorCode})";
                return ("MySQL", toReturn);
            }

            // No errors - Carry on!
            toReturn += $"- Version: {serverInfo.Version}" + Environment.NewLine;
            toReturn += $"- Protocol: {serverInfo.Protocol}" + Environment.NewLine;
            // toReturn += $"- Capabilities flags: {serverInfo.capabilitiesLower}" + Environment.NewLine;
            List<string> capabilities = ParseCapabilities(serverInfo.CapabilitiesLower);
            if (capabilities.Count > 0)
            {
                toReturn += "- Capabilities: " + string.Join(", ", capabilities) + Environment.NewLine;
            }

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
            
            foreach ((string Username, string Password) cred in credentials)
            {
                try
                {
                    using (TcpClient client = new TcpClient(target, port) { ReceiveTimeout = 5000 })
                    {
                        using (NetworkStream stream = client.GetStream())
                        {
                            byte[] buffer = new byte[2048];
                            int bytesRead = stream.Read(buffer, 0, buffer.Length);
                            (bool IsAuthenticated, string Response) result = Authenticate(stream, buffer, bytesRead, cred.Username, cred.Password, serverInfo.CapabilitiesLower);
                            if (result.IsAuthenticated == false)
                            {
                                if (result.Response == "")
                                {
                                    // Incorrect password, but no errors - Carry on
                                    continue;
                                }
                                else
                                {
                                    // Something bad happened - Abort!
                                    string errorCode = result.Response.Split('|')[0];
                                    string errorMessage = result.Response.Split('|')[1];

                                    toReturn += $"- Error {errorCode}: {errorMessage}";
                                    break;
                                }
                            }
                            else
                            {
                                toReturn += $"- Discovered Creds: {cred.Username} / {cred.Password}" + Environment.NewLine;
                                // Console.WriteLine("Authentication successful!");
                                // Send SELECT VERSION() query and display result
                                SendQuery(stream, "SELECT User, authentication_string from mysql.user;");
                                string QueryResponse = ReadQueryResponse(stream);
                                if (QueryResponse.StartsWith("- Row"))
                                {
                                    toReturn += QueryResponse;
                                    break;
                                }
                                else
                                {
                                    toReturn += "- User cannot read mysql.user";
                                    break;
                                }
                                // Console.WriteLine($"Server version from query: {versionResult}");
                            }
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
            }
            return ("MySQL", toReturn);
        }

        static (uint CapabilitiesLower, byte Protocol, string Version) GetServerInfo(string host, int port)
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
                    if (protocol == 0xFF) // Error
                    {
                        if (bytesRead >= 7) // Enough for error code
                        {
                            int errorCode = (byte)ms.ReadByte() | ((byte)ms.ReadByte() << 8); // Little-endian
                            if (errorCode == 1130) // ER_HOST_NOT_PRIVILEGED
                            {
                                string errorMessage = System.Text.Encoding.UTF8.GetString(buffer, 7, bytesRead - 7);
                                return (0, protocol, errorCode + "|" + errorMessage);
                            }
                            Console.WriteLine($"Server returned unknown error code: {errorCode}");
                        }
                        else
                        {
                            Console.WriteLine("Error packet too short to parse.");
                        }
                        return (0, protocol, "-1|Unknown");
                    }

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

        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        static (bool IsAuthed, string Message) Authenticate(NetworkStream stream, byte[] packet, int length, string user, string password, uint serverCapabilities)
        {
            byte sequenceNumber = packet[3];
            using (MemoryStream ms = new MemoryStream(packet, 0, length))
            {
                ms.Seek(4, SeekOrigin.Begin);

                // protocol version	-> int<1>
                int protocolVersion = ms.ReadByte();
                if (protocolVersion == 0xFF)
                {
                    if (length >= 7) // Ensure enough bytes for header + 2-byte error code
                    {
                        int errorCode = packet[5] | (packet[6] << 8); // Little-endian: lower byte first
                        Console.WriteLine($"Error Code: {errorCode}");
                        string errorMessage = Encoding.UTF8.GetString(packet, 7, length - 7);
                        if (errorCode == 1130) // ER_HOST_NOT_PRIVILEGED
                        {
                            Console.WriteLine($"Error Message: {errorMessage}");
                            return (false, errorCode + "|" + errorMessage);
                        }
                        else
                        {
                            Console.WriteLine("Unknown Error Code: " + errorCode);
                            Console.WriteLine($"Error Message: {errorMessage}");
                            return (false, errorCode + "|" + errorMessage);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Received an error packet from the server.");
                        Console.WriteLine($"Raw packet: {BitConverter.ToString(packet, 0, length)}");
                        return (false, "-1|Unknown Error");
                    }
                }
                else if (protocolVersion != 0x0A) // Check for Handshake V10
                {
                    Console.WriteLine($"Unexpected protocol version: {protocolVersion:X2}");
                    Console.WriteLine("TODO: Implement support for non-Protocol 10 handshakes.");
                    return (false, "-1|Unexpected protocol version: {protocolVersion:X2}");
                }

                // Skip version info - We already got it in GetServerInfo
                while (ms.ReadByte() != 0 && ms.Position < ms.Length) { }

                // 	thread id - int<4>
                byte[] threadIdBytes = new byte[4];
                ms.Read(threadIdBytes, 0, 4);
                int threadId = BitConverter.ToInt32(threadIdBytes, 0);
                // Console.WriteLine($"Thread ID: {threadId}");

                // 	auth-plugin-data-part-1 -> string[8]	
                byte[] authPluginDataPart1 = new byte[8];
                ms.Read(authPluginDataPart1, 0, 8);
                // Console.WriteLine($"Salt Part 1: {BitConverter.ToString(authPluginDataPart1)}");

                // filler -> int<1>
                ms.Seek(1, SeekOrigin.Current); // Filler
                // capability_flags_1 -> int<2>
                ms.Seek(2, SeekOrigin.Current); // Lower capabilities
                ms.Seek(3, SeekOrigin.Current); // Charset + status

                // capability_flags_2 -> int<2>
                byte[] capabilityUpperBytes = new byte[2];
                ms.Read(capabilityUpperBytes, 0, 2);

                // auth_plugin_data_len -> int<1>
                int authPluginDataLen = ms.ReadByte();

                // reserved -> string[10]
                ms.Seek(10, SeekOrigin.Current); // Reserved


                // auth-plugin-data-part-2-> $length
                byte[] authPluginDataPart2 = new byte[authPluginDataLen - 8]; // length of auth-plugin-data - 8 (Why minus 8? Because the protocol said so...)
                ms.Read(authPluginDataPart2, 0, authPluginDataPart2.Length);
                // Console.WriteLine($"Salt Part 2: {BitConverter.ToString(authPluginDataPart2)}");

                // 
                byte[] scramble = new byte[20];
                Array.Copy(authPluginDataPart1, 0, scramble, 0, 8);
                Array.Copy(authPluginDataPart2, 0, scramble, 8, 12);
                // Console.WriteLine($"Full Salt (Scramble): {BitConverter.ToString(scramble)}");

                // Define client capabilities explicitly
                // 0x0001 = LongPassword (Password Auth)
                // 0x0200 = Speaks41ProtocolNew (The new protocol)
                // 0x8000 = 4.1 - SecureConnection - This was sniffed - Not sure if I even need it since it's deprecated, but hey...
                uint clientCapabilities = 0x0001 | 0x0200 | 0x8000;
                SendAuthResponse(stream, user, password, scramble, clientCapabilities, (byte)(sequenceNumber + 1));

                byte[] responseBuffer = new byte[2048];
                // Console.WriteLine("Waiting for server response...");
                int responseBytes = stream.Read(responseBuffer, 0, responseBuffer.Length);
                // Console.WriteLine($"Received {responseBytes} bytes");

                if (responseBytes > 0)
                {
                    // Console.WriteLine($"Server response bytes: {BitConverter.ToString(responseBuffer, 0, responseBytes)}");
                    return (ParseServerResponse(responseBuffer, responseBytes), "");
                }
                else
                {
                    Console.WriteLine("No response bytes read!");
                    return (false, "-1|No response bytes read!");
                }
            }
        }

        // https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
        // Shamelessly copied shorthand naming from https://svn.nmap.org/nmap/nselib/mysql.lua
        static List<string> ParseCapabilities(uint flags)
        {
            List<string> capabilities = new List<string>();
            // 1
            if ((flags & 0x0001) != 0) capabilities.Add("LongPassword");
            // 2
            if ((flags & 0x0002) != 0) capabilities.Add("FoundRows");
            // 4
            if ((flags & 0x0004) != 0) capabilities.Add("LongColumnFlag");
            // 8
            if ((flags & 0x0008) != 0) capabilities.Add("ConnectWithDatabase");
            // 16
            if ((flags & 0x0010) != 0) capabilities.Add("DontAllowDatabaseTableColumn");
            // 32
            if ((flags & 0x0020) != 0) capabilities.Add("SupportsCompression");
            // 64
            if ((flags & 0x0040) != 0) capabilities.Add("ODBCClient");
            // 128
            if ((flags & 0x0080) != 0) capabilities.Add("SupportsLoadDataLocal");
            // 256
            if ((flags & 0x0100) != 0) capabilities.Add("IgnoreSpaceBeforeParenthesis");
            // 512
            if ((flags & 0x0200) != 0) capabilities.Add("Speaks41ProtocolNew");
            // 1024
            if ((flags & 0x0400) != 0) capabilities.Add("InteractiveClient");
            // 2048
            if ((flags & 0x0800) != 0) capabilities.Add("SwitchToSSLAfterHandshake");
            // 4096
            if ((flags & 0x1000) != 0) capabilities.Add("IgnoreSigpipes");
            // 8192
            if ((flags & 0x2000) != 0) capabilities.Add("SupportsTransactions");
            // 16384 - DEPRECATED: Old flag for 4.1 protocol
            if ((flags & 0x4000) != 0) capabilities.Add("Speaks41ProtocolOld");
            // 32768 - DEPRECATED: Old flag for 4.1 authentication \ CLIENT_SECURE_CONNECTION.
            if ((flags & 0x8000) != 0) capabilities.Add("Support41Auth");
            return capabilities;
        }

        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
        // Protocol::HandshakeResponse41
        static void SendAuthResponse(NetworkStream stream, string user, string password, byte[] scramble, uint clientCapabilities, byte sequenceNumber)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // client_flag -> int<4> -> Capabilities Flags
                ms.Write(BitConverter.GetBytes(clientCapabilities), 0, 4);
                // max_packet_size -> int<4>
                ms.Write(BitConverter.GetBytes(16777215), 0, 4); // Max packet size
                // character_set -> int<1>
                // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_character_set.html#a_protocol_character_set
                ms.WriteByte(33); // UTF-8 charset
                // filler -> string[23]
                ms.Write(new byte[23], 0, 23); // Reserved

                // username string<NUL>
                byte[] userBytes = Encoding.ASCII.GetBytes(user);
                ms.Write(userBytes, 0, userBytes.Length);
                ms.WriteByte(0); // Null-terminated username

                // if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA { - May need to check later - This one worked in this case, so...

                // auth_response -> string<length>
                byte[] authResponse = GenerateAuthResponse(password, scramble);
                // Console.WriteLine($"Hashed Password: {BitConverter.ToString(authResponse)}");
                ms.WriteByte((byte)authResponse.Length); // Length-encoded auth response
                ms.Write(authResponse, 0, authResponse.Length);

                // Currently assuming if capabilities & CLIENT_PLUGIN_AUTH {
                // client_plugin_name -> string<NUL>
                byte[] pluginName = Encoding.ASCII.GetBytes("mysql_native_password");
                ms.Write(pluginName, 0, pluginName.Length);
                ms.WriteByte(0); // Null-terminated plugin name

                // And send
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
            {
                return Array.Empty<byte>();
            }

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
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
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

        // Read and parse the result of custom queries
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

                // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
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

                // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
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
