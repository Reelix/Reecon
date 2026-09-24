using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Reecon;

public class MySql_Protocol
{
    // Send a query packet (COM_QUERY)
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
    public static void SendQuery(NetworkStream stream, string query)
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

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
    public class BasicPacket
    {
        public int Length { get; set; }
        public byte SequenceId { get; set; }
        public byte[] Payload { get; set; } = Array.Empty<byte>();

        // Reads a complete packet from the network stream
        public static BasicPacket Read(NetworkStream stream)
        {
            byte[] header = new byte[4];
            int read = stream.Read(header, 0, 4);
            if (read == 0) return new BasicPacket();

            if (read < 4)
            {
                stream.ReadExactly(header, read, 4 - read);
            }

            int length = header[0] | (header[1] << 8) | (header[2] << 16);
            byte sequenceId = header[3];

            byte[] payload = new byte[length];
            if (length > 0)
            {
                stream.ReadExactly(payload, 0, length);
            }

            return new BasicPacket
            {
                Length = length,
                SequenceId = sequenceId,
                Payload = payload
            };
        }

        // Parses a packet from an already-read byte buffer
        public static BasicPacket Parse(byte[] buffer, int totalBytes)
        {
            if (totalBytes < 4) return new BasicPacket();

            int length = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
            byte sequenceId = buffer[3];

            int payloadLength = Math.Min(length, totalBytes - 4);
            byte[] payload = new byte[payloadLength];
            if (payloadLength > 0)
            {
                Buffer.BlockCopy(buffer, 4, payload, 0, payloadLength);
            }

            return new BasicPacket
            {
                Length = length,
                SequenceId = sequenceId,
                Payload = payload
            };
        }

        public static void Send(NetworkStream stream, byte[] payload, byte sequenceId)
        {
            byte[] packet = new byte[payload.Length + 4];
            packet[0] = (byte)(payload.Length & 0xFF);
            packet[1] = (byte)((payload.Length >> 8) & 0xFF);
            packet[2] = (byte)((payload.Length >> 16) & 0xFF);
            packet[3] = sequenceId;

            if (payload.Length > 0)
            {
                Buffer.BlockCopy(payload, 0, packet, 4, payload.Length);
            }

            stream.Write(packet, 0, packet.Length);
            stream.Flush();
        }
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
    public class HandshakeV10
    {
        private const uint CLIENT_PLUGIN_AUTH = 0x00080000;

        public byte SequenceId { get; set; }
        public byte ProtocolVersion { get; set; }
        public string ServerVersion { get; set; } = "";
        public int ConnectionId { get; set; }
        public uint Capabilities { get; set; }
        public byte CharacterSet { get; set; }
        public ushort StatusFlags { get; set; }
        public byte[] Scramble { get; set; } = Array.Empty<byte>();
        public string AuthPluginName { get; set; } = "";
        public int ErrorCode { get; set; }
        public string ErrorMessage { get; set; } = "";

        public static HandshakeV10 Parse(BasicPacket packet)
        {
            HandshakeV10 handshake = new HandshakeV10
            {
                SequenceId = packet.SequenceId
            };

            if (packet.Payload.Length == 0) return handshake;

            using (MemoryStream ms = new MemoryStream(packet.Payload))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                // Offset 0 of payload is protocol version (0x0A) or error marker (0xFF)
                handshake.ProtocolVersion = reader.ReadByte();

                if (handshake.ProtocolVersion == 0xFF) // ERR_Packet
                {
                    if (packet.Payload.Length >= 3)
                    {
                        handshake.ErrorCode = reader.ReadUInt16();
                        handshake.ErrorMessage = Encoding.UTF8.GetString(packet.Payload, 3, packet.Payload.Length - 3);
                    }

                    return handshake;
                }

                // Server Version (null-terminated string)
                StringBuilder versionBuilder = new StringBuilder();
                int b;
                while (ms.Position < ms.Length && (b = reader.ReadByte()) != 0)
                {
                    versionBuilder.Append((char)b);
                }

                handshake.ServerVersion = versionBuilder.ToString();

                // Thread / Connection ID (4 bytes)
                handshake.ConnectionId = reader.ReadInt32();

                // Auth Plugin Data Part 1 (8 bytes)
                byte[] authDataPart1 = reader.ReadBytes(8);
                reader.ReadByte(); // Filler (always 0x00)

                // Capabilities (lower 2 bytes)
                ushort capLower = reader.ReadUInt16();

                if (ms.Position < ms.Length)
                {
                    handshake.CharacterSet = reader.ReadByte();
                    handshake.StatusFlags = reader.ReadUInt16();

                    // Capabilities (upper 2 bytes)
                    ushort capUpper = reader.ReadUInt16();
                    handshake.Capabilities = ((uint)capUpper << 16) | capLower;

                    byte authPluginDataLen = 0;
                    if ((handshake.Capabilities & CLIENT_PLUGIN_AUTH) != 0)
                    {
                        authPluginDataLen = reader.ReadByte();
                    }
                    else
                    {
                        reader.ReadByte(); // Filler 0x00
                    }

                    // Reserved (10 bytes)
                    reader.ReadBytes(10);

                    // Auth Plugin Data Part 2
                    int part2Len = Math.Max(13, authPluginDataLen - 8);
                    byte[] authDataPart2 = Array.Empty<byte>();
                    if (ms.Position + part2Len <= ms.Length)
                    {
                        authDataPart2 = reader.ReadBytes(part2Len);
                    }

                    // Assemble full 20-byte scramble
                    handshake.Scramble = new byte[20];
                    Array.Copy(authDataPart1, 0, handshake.Scramble, 0, 8);
                    if (authDataPart2.Length >= 12)
                    {
                        Array.Copy(authDataPart2, 0, handshake.Scramble, 8, 12);
                    }

                    // Auth Plugin Name (null-terminated string)
                    if ((handshake.Capabilities & CLIENT_PLUGIN_AUTH) != 0 && ms.Position < ms.Length)
                    {
                        StringBuilder pluginBuilder = new StringBuilder();
                        while (ms.Position < ms.Length && (b = reader.ReadByte()) != 0)
                        {
                            pluginBuilder.Append((char)b);
                        }

                        handshake.AuthPluginName = pluginBuilder.ToString();
                    }
                }
                else
                {
                    handshake.Capabilities = capLower;
                    handshake.Scramble = authDataPart1;
                }

                return handshake;
            }
        }
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
    // Protocol::HandshakeResponse41
    private static class HandshakeResponse41
    {
        // Client Capability Flags
        // https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
        private const uint CLIENT_LONG_PASSWORD = 0x00000001; // 1
        private const uint CLIENT_PROTOCOL_41 = 0x00000200; // 512 (Speaks41ProtocolNew)
        private const uint CLIENT_SECURE_CONNECTION = 0x00008000; // 32768 (Support41Auth)
        private const uint CLIENT_PLUGIN_AUTH = 0x00080000; // 524288 (Supports plugin auth)

        private const uint DEFAULT_CAPABILITIES = CLIENT_LONG_PASSWORD
                                                  | CLIENT_PROTOCOL_41
                                                  | CLIENT_SECURE_CONNECTION
                                                  | CLIENT_PLUGIN_AUTH;

        public static void Send(NetworkStream stream, string user, string password, byte[] scramble, byte sequenceNumber, string authPlugin)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // client_flag -> int<4> (Capabilities Flags)
                ms.Write(BitConverter.GetBytes(DEFAULT_CAPABILITIES), 0, 4);

                // max_packet_size -> int<4> (16MB max)
                ms.Write(BitConverter.GetBytes(16777215), 0, 4);

                // character_set -> int<1> (33 = utf8_general_ci)
                ms.WriteByte(33);

                // filler -> string[23] (Reserved)
                ms.Write(new byte[23], 0, 23);

                // username -> string<NUL>
                byte[] userBytes = Encoding.ASCII.GetBytes(user);
                ms.Write(userBytes, 0, userBytes.Length);
                ms.WriteByte(0);

                // auth_response -> string<length>
                byte[] authResponse = MySqlAuth.Generate(authPlugin, password, scramble);
                ms.WriteByte((byte)authResponse.Length);
                if (authResponse.Length > 0)
                {
                    ms.Write(authResponse, 0, authResponse.Length);
                }

                // client_plugin_name -> string<NUL>
                byte[] pluginName = Encoding.ASCII.GetBytes(authPlugin);
                ms.Write(pluginName, 0, pluginName.Length);
                ms.WriteByte(0);

                // Wrap in 4-byte MySQL packet header and send
                byte[] packetData = ms.ToArray();
                using (MemoryStream headerMs = new MemoryStream())
                {
                    byte[] lengthBytes = BitConverter.GetBytes(packetData.Length);
                    headerMs.Write(lengthBytes[0..3], 0, 3);
                    headerMs.WriteByte(sequenceNumber);
                    headerMs.Write(packetData, 0, packetData.Length);

                    byte[] fullPacket = headerMs.ToArray();
                    stream.Write(fullPacket, 0, fullPacket.Length);
                    stream.Flush();
                }
            }
        }
    }

    // https://dev.mysql.com/doc/refman/8.4/en/caching-sha2-pluggable-authentication.html
    private static byte[] EncryptPasswordRsa(string password, byte[] scramble, string pemKey)
    {
        byte[] rawPwBytes = Encoding.UTF8.GetBytes(password + "\0");
        byte[] obfuscated = new byte[rawPwBytes.Length];
        for (int i = 0; i < rawPwBytes.Length; i++)
        {
            obfuscated[i] = (byte)(rawPwBytes[i] ^ scramble[i % scramble.Length]);
        }

        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(pemKey);
            return rsa.Encrypt(obfuscated, RSAEncryptionPadding.OaepSHA1);
        }
    }
    
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
    public static (bool IsAuthed, string Message) Authenticate(NetworkStream stream, string user, string password, string authPlugin)
    {
        // 1 - Parse Initial HandshakeV10 Packet
        BasicPacket initialPacket = BasicPacket.Read(stream);
        HandshakeV10 handshake = HandshakeV10.Parse(initialPacket);

        if (handshake.ProtocolVersion == 0xFF) // Error packet
        {
            Console.WriteLine($"Error Code: {handshake.ErrorCode}");
            Console.WriteLine($"Error Message: {handshake.ErrorMessage}");
            return (false, $"{handshake.ErrorCode}|{handshake.ErrorMessage}");
        }

        if (handshake.ProtocolVersion != 0x0A) // Not Version 
        {
            Console.WriteLine($"Unexpected protocol version: {handshake.ProtocolVersion:X2}");
            return (false, $"-1|Unexpected protocol version: {handshake.ProtocolVersion:X2}");
        }

        // 2. Send HandshakeResponse41 (Client Response)
        HandshakeResponse41.Send(stream, user, password, handshake.Scramble, (byte)(handshake.SequenceId + 1), authPlugin);

        // 3. Read Server Verdict
        BasicPacket response = BasicPacket.Read(stream);
        (AuthResult Result, string Error) parse = ParseServerResponse(response);

        // Plain success (0x00)
        if (parse.Result == AuthResult.Success)
        {
            return (true, "");
        }

        // Caching sha2 fast success: drain the trailing OK packet
        if (parse.Result == AuthResult.FastAuthSuccess)
        {
            BasicPacket.Read(stream);
            return (true, "");
        }

        // Handle AuthMoreData (caching_sha2_password full authentication fallback)
        if (parse.Result == AuthResult.AuthMoreData)
        {
            if (response.Payload.Length > 1 && response.Payload[1] == 0x04)
            {
                // Request public key (0x02)
                BasicPacket.Send(stream, [0x02], (byte)(response.SequenceId + 1));

                // Read public key PEM
                BasicPacket keyPacket = BasicPacket.Read(stream);
                if (keyPacket.Payload.Length == 0) return (false, "Connection closed while reading RSA public key");

                if (keyPacket.Payload[0] == 0xFF)
                {
                    var errParse = ParseServerResponse(keyPacket);
                    return (false, errParse.Error);
                }

                int pemOffset = keyPacket.Payload[0] == 0x01 ? 1 : 0;
                string pemKey = Encoding.ASCII.GetString(keyPacket.Payload, pemOffset, keyPacket.Payload.Length - pemOffset).Trim('\0', '\r', '\n', ' ');

                // Encrypt and send
                byte[] encrypted = EncryptPasswordRsa(password, handshake.Scramble, pemKey);
                BasicPacket.Send(stream, encrypted, (byte)(keyPacket.SequenceId + 1));

                // Final verdict
                BasicPacket finalPacket = BasicPacket.Read(stream);
                var finalParse = ParseServerResponse(finalPacket);
                return (finalParse.Result == AuthResult.Success, finalParse.Error);
            }

            return (false, $"-1|Unexpected AuthMoreData sub-status (0x{(response.Payload.Length > 1 ? response.Payload[1] : 0):X2})");
        }

        // Handle AuthSwitch (0xFE)
        if (parse.Result == AuthResult.AuthSwitch)
        {
            // Protocol::AuthSwitchRequest: 0xFE + plugin_name\0 + new_scramble
            int nullIdx = Array.IndexOf(response.Payload, (byte)0, 1);
            string requestedPlugin = Encoding.ASCII.GetString(response.Payload, 1, nullIdx - 1);

            byte[] newScramble = response.Payload[(nullIdx + 1)..];
            if (newScramble.Length > 0 && newScramble[^1] == 0x00)
            {
                newScramble = newScramble[..^1];
            }

            byte switchSeq = (byte)(response.SequenceId + 1);

            if (requestedPlugin == "sha256_password")
            {
                if (string.IsNullOrEmpty(password))
                {
                    BasicPacket.Send(stream, [0x00], switchSeq);
                }
                else
                {
                    // Request public key (0x01 for sha256_password)
                    BasicPacket.Send(stream, [0x01], switchSeq);

                    BasicPacket keyPacket = BasicPacket.Read(stream);
                    if (keyPacket.Payload.Length == 0) return (false, "Connection closed reading public key");

                    int pemOffset = keyPacket.Payload[0] == 0x01 ? 1 : 0;
                    string pemKey = Encoding.ASCII.GetString(keyPacket.Payload, pemOffset, keyPacket.Payload.Length - pemOffset).Trim('\0', '\r', '\n');

                    byte[] encrypted = EncryptPasswordRsa(password, newScramble, pemKey);
                    BasicPacket.Send(stream, encrypted, (byte)(keyPacket.SequenceId + 1));
                }

                BasicPacket finalPacket = BasicPacket.Read(stream);
                var finalParse = ParseServerResponse(finalPacket);
                return (finalParse.Result == AuthResult.Success, finalParse.Error);
            }
            else
            {
                byte[] switchAuthResponse = MySqlAuth.Generate(requestedPlugin, password, newScramble);
                BasicPacket.Send(stream, switchAuthResponse, switchSeq);

                BasicPacket finalPacket = BasicPacket.Read(stream);
                var finalParse = ParseServerResponse(finalPacket);

                if (finalParse.Result == AuthResult.Success || finalParse.Result == AuthResult.FastAuthSuccess)
                {
                    if (finalParse.Result == AuthResult.FastAuthSuccess)
                    {
                        BasicPacket.Read(stream); // Drain trailing OK
                    }

                    return (true, "");
                }

                return (false, finalParse.Error);
            }
        }

        return (false, parse.Error);
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
    // Shamelessly copied shorthand naming from https://svn.nmap.org/nmap/nselib/mysql.lua
    public static List<string> ParseCapabilities(uint flags)
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

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods.html
    private static class MySqlAuth
    {
        public static byte[] Generate(string authPlugin, string password, byte[] scramble)
        {
            if (string.IsNullOrEmpty(password) || scramble.Length == 0)
            {
                return Array.Empty<byte>();
            }

            return authPlugin switch
            {
                "mysql_native_password" => ScrambleNativePassword(password, scramble),
                "caching_sha2_password" => ScrambleCachingSha2(password, scramble),
                _ => throw new NotSupportedException($"Unsupported authentication plugin: '{authPlugin}'")
            };
        }

        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_native_registration.html
        // Formula: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
        public static byte[] ScrambleNativePassword(string password, byte[] scramble)
        {
            byte[] pwBytes = Encoding.UTF8.GetBytes(password);

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hash1 = sha1.ComputeHash(pwBytes);
                byte[] hash2 = sha1.ComputeHash(hash1);

                byte[] buffer = new byte[scramble.Length + hash2.Length];
                Buffer.BlockCopy(scramble, 0, buffer, 0, scramble.Length);
                Buffer.BlockCopy(hash2, 0, buffer, scramble.Length, hash2.Length);

                byte[] digest = sha1.ComputeHash(buffer);

                byte[] result = new byte[20];
                for (int i = 0; i < 20; i++)
                {
                    result[i] = (byte)(hash1[i] ^ digest[i]);
                }

                return result;
            }
        }

        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_caching_sha2_password.html
        // Formula: SHA256(password) XOR SHA256(SHA256(SHA256(password)) + scramble)
        public static byte[] ScrambleCachingSha2(string password, byte[] scramble)
        {
            byte[] pwBytes = Encoding.UTF8.GetBytes(password);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash1 = sha256.ComputeHash(pwBytes);
                byte[] hash2 = sha256.ComputeHash(hash1);

                byte[] buffer = new byte[hash2.Length + scramble.Length];
                Buffer.BlockCopy(hash2, 0, buffer, 0, hash2.Length);
                Buffer.BlockCopy(scramble, 0, buffer, hash2.Length, scramble.Length);

                byte[] digest = sha256.ComputeHash(buffer);

                byte[] result = new byte[32];
                for (int i = 0; i < 32; i++)
                {
                    result[i] = (byte)(hash1[i] ^ digest[i]);
                }

                return result;
            }
        }
    }


    enum AuthResult
    {
        // 0x00: Server accepted login directly (Protocol::OK_Packet)
        Success,

        // 0x01 0x03: caching_sha2_password cache hit (AuthMoreData + FAST_AUTH_SUCCESS)
        FastAuthSuccess,

        // 0x01 0x04: caching_sha2_password cache miss (AuthMoreData + PERFORM_FULL_AUTHENTICATION)
        AuthMoreData,

        // 0xFE: Server demands switching to a different plugin (Protocol::AuthSwitchRequest)
        AuthSwitch,

        // 0xFF: Server rejected connection or credentials (Protocol::ERR_Packet)
        Failed,

        // Catch-all for unexpected or truncated packets
        Unknown
    }

    // Evaluates the server's response to HandshakeResponse41 or AuthSwitchResponse
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
    static (AuthResult Result, string Error) ParseServerResponse(BasicPacket packet)
    {
        if (packet.Payload.Length == 0)
        {
            return (AuthResult.Unknown, "-1|Empty packet received");
        }

        // Byte 0 of the payload is the packet status / type marker
        byte status = packet.Payload[0];

        // 1. OK_Packet (0x00) -> Authentication succeeded
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
        if (status == 0x00)
        {
            return (AuthResult.Success, "");
        }

        // 2. AuthSwitchRequest (0xFE) -> Server requests switching authentication plugin
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_request.html
        if (status == 0xFE)
        {
            return (AuthResult.AuthSwitch, "");
        }

        // 3. AuthMoreData (0x01) -> Extra authentication steps required
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_more_data.html
        if (status == 0x01)
        {
            // For caching_sha2_password:
            // 0x03 = FAST_AUTH_SUCCESS (scramble verified in cache; trailing OK packet follows)
            // 0x04 = PERFORM_FULL_AUTHENTICATION (cache miss; requires RSA exchange)
            if (packet.Payload.Length > 1 && packet.Payload[1] == 0x03)
            {
                return (AuthResult.FastAuthSuccess, "");
            }

            return (AuthResult.AuthMoreData, "");
        }

        // 4. ERR_Packet (0xFF) -> Error response from server
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
        if (status == 0xFF)
        {
            if (packet.Payload.Length < 3)
            {
                return (AuthResult.Failed, "-1|Malformed ERR_Packet: too short");
            }

            // Error code: int<2> at payload offset 1 (Little-endian)
            int errorCode = BitConverter.ToUInt16(packet.Payload, 1);

            // If CLIENT_PROTOCOL_41 is active, payload has:
            // status (1) + error_code (2) + '#' marker (1) + sql_state (5) = 9 bytes before message
            int messageOffset = packet.Payload.Length >= 9 && packet.Payload[3] == (byte)'#' ? 9 : 3;
            string errorMessage = Encoding.UTF8.GetString(packet.Payload, messageOffset, packet.Payload.Length - messageOffset);

            // Standard MySQL error codes:
            // 1045 = ER_ACCESS_DENIED_ERROR (wrong password or username)
            // 1251 = ER_NOT_SUPPORTED_AUTH_MODE (client needs to switch auth plugin)
            bool isStandardAuthFailure = errorCode is 1045 or 1251
                                         || errorMessage.StartsWith("Access denied for user", StringComparison.OrdinalIgnoreCase)
                                         || errorMessage.StartsWith("Client does not support authentication protocol", StringComparison.OrdinalIgnoreCase);

            if (!isStandardAuthFailure)
            {
                // A fatal / server-level error (e.g. host not allowed, connection limit, etc.)
                return (AuthResult.Failed, $"{errorCode}|{errorMessage}");
            }

            // Standard invalid credentials; return empty error so the loop tests the next password
            return (AuthResult.Failed, "");
        }

        return (AuthResult.Unknown, $"-1|Unexpected response status: 0x{status:X2}");
    }

    private static byte[] ReadPacket(NetworkStream stream)
    {
        byte[] header = new byte[4];
        stream.ReadExactly(header, 0, 4);

        int length = header[0] | (header[1] << 8) | (header[2] << 16);
        byte[] payload = new byte[length];
        if (length > 0)
        {
            stream.ReadExactly(payload, 0, length);
        }

        return payload;
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response.html
    public static string ReadQueryResponse(NetworkStream stream)
    {
        // 1. Read first packet (Column Count, OK_Packet, or ERR_Packet)
        byte[] firstPacket = ReadPacket(stream);
        if (firstPacket.Length == 0)
        {
            return "No response received from query!";
        }

        byte packetType = firstPacket[0];

        // Handle Error Packet (0xFF)
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
        if (packetType == 0xFF)
        {
            int errorCode = BitConverter.ToUInt16(firstPacket, 1);
            int messageOffset = firstPacket.Length >= 9 && firstPacket[3] == (byte)'#' ? 9 : 3;
            string errorMessage = Encoding.UTF8.GetString(firstPacket, messageOffset, firstPacket.Length - messageOffset);
            return $"Query error - Code: {errorCode}, Message: {errorMessage}";
        }

        // Handle OK Packet (0x00) for non-SELECT queries (e.g., SET, USE, UPDATE)
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
        if (packetType == 0x00)
        {
            return "Query OK (0 rows returned)";
        }

        // Parse Column Count from length-encoded integer
        int columnCount;
        using (MemoryStream countMs = new MemoryStream(firstPacket))
        {
            columnCount = (int)ReadLengthEncodedInteger(countMs);
        }

        // 2. Read Column Definition Packets
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html
        string[] columnNames = new string[columnCount];
        for (int i = 0; i < columnCount; i++)
        {
            byte[] colPacket = ReadPacket(stream);
            using (MemoryStream colMs = new MemoryStream(colPacket))
            {
                SkipLengthEncodedString(colMs); // catalog
                SkipLengthEncodedString(colMs); // schema
                SkipLengthEncodedString(colMs); // table
                SkipLengthEncodedString(colMs); // org_table

                columnNames[i] = ReadLengthEncodedString(colMs); // name
            }
        }

        // 3. Read intermediate EOF Packet separating column defs from row data
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_eof_packet.html
        byte[] eof1 = ReadPacket(stream);
        if (eof1.Length > 0 && eof1[0] == 0xFF)
        {
            return "Error reading column definitions";
        }

        // 4. Read Text Resultset Row Packets until final EOF (0xFE)
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_row.html
        StringBuilder resultBuilder = new StringBuilder();
        while (true)
        {
            byte[] rowPacket = ReadPacket(stream);

            // Final EOF Packet marker (0xFE with payload length < 9) terminates the resultset
            if (rowPacket.Length > 0 && rowPacket[0] == 0xFE && rowPacket.Length < 9)
            {
                break;
            }

            // Interrupted by an ERR packet
            if (rowPacket.Length > 0 && rowPacket[0] == 0xFF)
            {
                resultBuilder.AppendLine("-- Query interrupted by error packet");
                break;
            }

            // Parse column values for this row
            using (MemoryStream rowMs = new MemoryStream(rowPacket))
            {
                List<string> rowPairs = new List<string>(columnCount);
                for (int i = 0; i < columnCount; i++)
                {
                    int firstByte = rowMs.ReadByte();

                    // 0xFB represents NULL in the MySQL Text Resultset protocol
                    if (firstByte == 0xFB)
                    {
                        rowPairs.Add($"{columnNames[i]}=NULL");
                    }
                    else
                    {
                        rowMs.Seek(-1, SeekOrigin.Current); // Rewind 1 byte
                        rowPairs.Add($"{columnNames[i]}={ReadLengthEncodedString(rowMs)}");
                    }
                }

                resultBuilder.AppendLine("-- Row: " + string.Join(", ", rowPairs));
            }
        }

        return resultBuilder.ToString();
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_strings.html#sect_protocol_basic_dt_string_le
    public static string ReadLengthEncodedString(Stream stream)
    {
        int length = (int)ReadLengthEncodedInteger(stream);
        if (length == 0) return string.Empty;

        // Use stack memory for standard-length column strings to avoid heap allocations
        Span<byte> buffer = length <= 256 ? stackalloc byte[length] : new byte[length];
        stream.ReadExactly(buffer);
        return Encoding.UTF8.GetString(buffer);
    }

    public static void SkipLengthEncodedString(Stream stream)
    {
        long length = ReadLengthEncodedInteger(stream);
        stream.Seek(length, SeekOrigin.Current);
    }

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_le
    public static long ReadLengthEncodedInteger(Stream stream)
    {
        int firstByte = stream.ReadByte();
        if (firstByte < 0) throw new EndOfStreamException();

        if (firstByte < 0xFB)
        {
            return firstByte;
        }

        if (firstByte == 0xFC)
        {
            byte[] bytes = new byte[2];
            stream.ReadExactly(bytes, 0, 2);
            return BitConverter.ToUInt16(bytes, 0);
        }

        if (firstByte == 0xFD)
        {
            byte[] bytes = new byte[3];
            stream.ReadExactly(bytes, 0, 3);
            return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
        }

        if (firstByte == 0xFE)
        {
            byte[] bytes = new byte[8];
            stream.ReadExactly(bytes, 0, 8);
            return BitConverter.ToInt64(bytes, 0);
        }

        throw new InvalidDataException($"Unexpected length-encoded integer marker: 0x{firstByte:X2}");
    }
}