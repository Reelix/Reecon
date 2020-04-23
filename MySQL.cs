// using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    public static class PacketReader
    {
        public static bool EndOfPacket(byte[] buffer, int position) => position >= buffer.Length;

        public static byte Command(byte[] buffer)
        {
            return buffer[0];
        }

        /*
        public static bool IsOkPacket(byte[] buffer)
        {
            return buffer[0] == (byte)ResultMode.Ok && buffer.Length > 3 || buffer[0] == (byte)ResultMode.Eof && buffer.Length <= 5;
        }

        public static bool IsErrPacket(byte[] buffer)
        {
            return buffer[0] == (byte)ResultMode.Error;
        }*/

        public static string PacketToString(byte[] buffer)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < buffer.Length; i++)
            {
                if (i == 0)
                    sb.Append("len=");
                else if (i == 3)
                    sb.Append(" seq=");
                else if (i == 4)
                    sb.Append(" data=");

                var b = buffer[i];
                if (b <= 32 || b >= 128)
                    sb.Append("\\" + b.ToString("X2"));
                else
                    sb.Append((char)b);

            }

            return sb.ToString();
        }

        // ReSharper disable ParameterOnlyUsedForPreconditionCheck.Local
        private static void VerifyRemaining(byte[] buffer, int position, int remaining)
        {
            if (buffer.Length - position < remaining)
            {
                throw new Exception("Out of data: tried to read beyond packet end.");
            }
        }
        // ReSharper enable ParameterOnlyUsedForPreconditionCheck.Local

        public static bool ConsumeNull(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 1);
            if (buffer[position] != 0xFB)
                return false;

            position++;
            return true;
        }

        public static byte ReadInt1(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 1);
            return buffer[position++];
        }

        public static ushort ReadInt2(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 2);
            var result = BitConverter.ToUInt16(buffer, position);
            position += 2;
            return result;
        }

        public static uint ReadInt3(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 3);
            var result = (uint)BitConverter.ToUInt16(buffer, position);
            result |= (uint)buffer[position + 2] >> 16;
            position += 3;
            return result;
        }

        public static uint ReadInt4(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 4);
            var result = BitConverter.ToUInt32(buffer, position);
            position += 4;
            return result;
        }

        public static ulong ReadInt6(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 6);
            var result = (ulong)BitConverter.ToUInt32(buffer, position);
            result |= (ulong)BitConverter.ToUInt16(buffer, position + 4) >> 32;
            position += 6;
            return result;
        }

        public static ulong ReadInt8(byte[] buffer, ref int position)
        {
            VerifyRemaining(buffer, position, 8);
            var result = BitConverter.ToUInt64(buffer, position);
            position += 8;
            return result;
        }

        public static ulong ReadIntLengthEncoded(byte[] buffer, ref int position)
        {
            var value = ReadInt1(buffer, ref position);
            if (value < 251)
                return value;

            switch (value)
            {
                case 0xFC:
                    return ReadInt2(buffer, ref position);

                case 0xFD:
                    return ReadInt3(buffer, ref position);

                case 0xFE:
                    return ReadInt8(buffer, ref position);

                default:
                    throw new Exception("Invalid length-encoded integer " + value.ToString("X2"));
            }
        }

        public static byte[] ReadBytesFixed(byte[] buffer, ref int position, int length)
        {
            VerifyRemaining(buffer, position, length);
            var result = new byte[length];
            Array.Copy(buffer, position, result, 0, length);
            position += length;
            return result;
        }

        public static string ReadStringFixed(byte[] buffer, ref int position, int length, Encoding encoding)
        {
            VerifyRemaining(buffer, position, length);
            var result = encoding.GetString(buffer, position, length);
            position += length;
            return result;
        }

        public static string ReadStringLengthEncoded(byte[] buffer, ref int position, Encoding encoding)
        {
            var len = (int)ReadIntLengthEncoded(buffer, ref position);
            return ReadStringFixed(buffer, ref position, len, encoding);
        }

        public static string ReadStringNullTerminated(byte[] buffer, ref int position, Encoding encoding)
        {
            var origin = position;
            while (ReadInt1(buffer, ref position) != 0)
            {
            }

            return encoding.GetString(buffer, origin, position - origin - 1);
        }

        public static string ReadStringToEnd(byte[] buffer, ref int position, Encoding encoding)
        {
            var len = buffer.Length - position;
            return ReadStringFixed(buffer, ref position, len, encoding);
        }
    }

    public class HandshakeRequest
    {
        public enum CapabilityFlags : uint
        {
            LongPassword = 0x1,
            FoundRows = 0x2,
            LongColumnFlag = 0x4,
            ConnectWithDatabase = 0x8,
            DontAllowDatabaseTableColumn = 0x10,
            SupportsCompression = 0x20,
            ODBCClient = 0x40,
            SupportsLoadDataLocal = 0x80,
            IgnoreSpaceBeforeParenthesis = 0x100,
            Speaks41ProtocolNew = 0x200,
            InteractiveClient = 0x400,
            SwitchToSSLAfterHandshake = 0x800,
            IgnoreSigpipes = 0x1000,
            SupportsTransactions = 0x2000,
            Speaks41ProtocolOld = 0x4000,
            Support41Auth = 0x8000
        }

        public enum StatusFlags : ushort
        {
            InTransaction = 1,
            AutoCommit = 2,
            MoreResultsExist = 8,
            NoGoodIndexUsed = 0x10,
            NoIndexUsed = 0x20,
            CursorExists = 0x40,
            LastRowSent = 0x80,
            DatabaseDropped = 0x100,
            NoBackslashEscapes = 0x200,
            MetadataChanged = 0x400,
            QueryWasSlow = 0x800,
            PsOutParams = 0x1000,
            InReadonlyTransaction = 0x2000,
            SessionStateChanged = 0x4000
        }


        public byte[] AuthData { get; set; }
        public CapabilityFlags Capabilities { get; set; }
        public byte CharacterSet { get; set; }
        public uint ConnectionId { get; set; }
        public string ServerVersion { get; set; }
        public StatusFlags Status { get; set; }
        public byte Version { get; set; }

        public static HandshakeRequest Decode(byte[] buffer, Encoding encoding)
        {
            var result = new HandshakeRequest();
            var position = 0;

            result.Version = PacketReader.ReadInt1(buffer, ref position);
            if (result.Version != 10)
            {
                throw new Exception("Unable to handle protocol version " + result.Version);
            }

            result.ServerVersion = PacketReader.ReadStringNullTerminated(buffer, ref position, encoding);
            result.ConnectionId = PacketReader.ReadInt4(buffer, ref position);
            var auth1 = PacketReader.ReadBytesFixed(buffer, ref position, 8);
            PacketReader.ReadInt1(buffer, ref position);
            uint caps = PacketReader.ReadInt2(buffer, ref position);

            byte[] auth2;
            if (!PacketReader.EndOfPacket(buffer, position))
            {
                result.CharacterSet = PacketReader.ReadInt1(buffer, ref position);
                result.Status = (StatusFlags)PacketReader.ReadInt2(buffer, ref position);
                caps |= (uint)PacketReader.ReadInt2(buffer, ref position) >> 16;

                var authlen = PacketReader.ReadInt1(buffer, ref position);
                PacketReader.ReadStringFixed(buffer, ref position, 10, encoding);
                auth2 = PacketReader.ReadBytesFixed(buffer, ref position, authlen - 8);
            }
            else
                auth2 = new byte[0];

            result.Capabilities = (CapabilityFlags)caps;
            result.AuthData = new byte[auth1.Length + auth2.Length - 1];
            Array.Copy(auth1, 0, result.AuthData, 0, auth1.Length);
            Array.Copy(auth2, 0, result.AuthData, auth1.Length, auth2.Length - 1);

            return result;
        }
    }

    class MySQL
    {
        // Port: 3306

        // C# Version of createLoginHash
        // Thanks to https://github.com/mgefvert/MyRawClient/blob/master/MyRawClient/Auth/NativePassword.cs
        public static byte[] Encrypt(byte[] password, byte[] seedBytes)
        {
            if (password.Length == 0)
            {
                return new byte[1];
            }

            SHA1 sha = new SHA1CryptoServiceProvider();

            var firstHash = sha.ComputeHash(password);
            var secondHash = sha.ComputeHash(firstHash);

            var input = new byte[seedBytes.Length + secondHash.Length];
            Array.Copy(seedBytes, 0, input, 0, seedBytes.Length);
            Array.Copy(secondHash, 0, input, seedBytes.Length, secondHash.Length);
            var thirdHash = sha.ComputeHash(input);

            var finalHash = new byte[thirdHash.Length + 1];
            finalHash[0] = 0x14;
            Array.Copy(thirdHash, 0, finalHash, 1, thirdHash.Length);

            for (var i = 1; i < finalHash.Length; i++)
                finalHash[i] = (byte)(finalHash[i] ^ firstHash[i - 1]);

            return finalHash;
        }

        // https://svn.nmap.org/nmap/nselib/mysql.lua
        private static (int len, (uint responseLen, uint responseNumber)) DecodeHeader(byte[] data, int pos)
        {
            // https://svn.nmap.org/nmap/nselib/mysql.lua
            /*
              local function decodeHeader( data, pos )
              local response = {}
              local pos, tmp = pos or 1, 0 // null or 1

              tmp, pos = string.unpack( "<I4", data, pos )
              response.len = ( tmp & 255 )
              response.number = ( tmp >> 24 )

              return pos, response
              */
            //int pos = pos || 1;
            // I4 = uint
            uint tmp = 0;
            tmp = BitConverter.ToUInt32(data, pos);
            pos += 4;
            uint returnLen = tmp & 255;
            uint returnNumber = (tmp >> 24);
            return (pos, (returnLen, returnNumber));
        }

        public static string ReceiveGreeting(string ip)
        {
            string returnData = "";
            int headerSize = 4;
            byte[] data = new byte[headerSize];
            using (Socket greetingSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                greetingSocket.Connect(ip, 3306);
                try
                {
                    greetingSocket.Receive(data);
                }
                catch (Exception ex)
                {
                    return "- Unable to connect: " + ex.Message;
                }

                (int pos, (uint responseLen, uint responseNumber)) = DecodeHeader(data, 0);

                // do we need to read the remainder
                if (data.Length - headerSize < responseLen)
                {
                    byte[] tmp = new byte[responseLen - data.Length + headerSize];
                    greetingSocket.Receive(tmp);
                    data = data.Concat(tmp).ToArray();
                }

                int protocol = data[pos];
                pos++;
                if (protocol == 10)
                {
                    // <zI4
                    // z: a zero-terminated string
                    // I[n]: an unsigned int with n bytes (default is native size)
                    string version = "";
                    while (true)
                    {
                        char versionChar = Convert.ToChar(data[pos]);
                        pos++;
                        if (versionChar == '\0')
                        {
                            break;
                        }
                        version += versionChar;
                    }
                    returnData += "- Protocol: " + protocol + Environment.NewLine;
                    returnData += "- Version: " + version;
                    return returnData;
                    // String (8 bytes)
                    // response.salt, response.capabilities, pos = string.unpack("<c8xI2", data, pos)
                    // Need salt...
                }
                else if (protocol == 255)
                {
                    // response.errorcode, pos = string.unpack( "<I2", data, pos )
                    // I[n]: an unsigned int with n bytes (default is native size)
                    // I[2] = UInt16 = short
                    ushort errorCode = BitConverter.ToUInt16(data, pos);
                    if (errorCode == 1130)
                    {
                        returnData += "- Unauthorized (It's MySQL - You just don't have permission to connect)";
                    }
                    else
                    {
                        Console.WriteLine("Unknown 255 Error Code: " + errorCode);
                        Console.ReadLine();
                    }
                    return returnData;
                }
                else
                {
                    return "Error - Unrecognized MySQL Protocol: " + protocol + " - Bug Reelix!";
                }
            }
        }

        // Currently requires the GIGANTIC MySQL.dll as well as a dozen other refs >_<
        public static string TestDefaults(string ip)
        {
            List<string> testDetails = new List<string>()
            {
                "root:mysql",
                "root:root",
                "root:chippc",
                "admin:admin",
                "root:",
                "root:nagiosxi",
                "root:usbw",
                "cloudera:cloudera",
                "root:cloudera",
                "root:moves",
                "moves:moves",
                "root:testpw",
                "root:p@ck3tf3nc3",
                "mcUser:medocheck123",
                "root:mktt",
                "root:123",
                "dbuser:123",
                "asteriskuser:amp109",
                "asteriskuser:eLaStIx.asteriskuser.2oo7",
                "root:raspberry",
                "root:openauditrootuserpassword",
                "root:vagrant",
                "root:123qweASD#"
            };
            int tried = 0;
            foreach (string toTest in testDetails)
            {
                string username = toTest.Split(':')[0];
                string password = toTest.Split(':')[1];
                string success = TestPassword(ip, username, password);
                if (success == "true")
                {
                    // Wow o_O
                    Console.WriteLine("Creds Found: " + username + ":" + password);
                    Console.ReadLine();
                    Console.ReadLine();
                    return "- Default Credentails Found: " + username + ":" + password;
                }
                else if (success == "break")
                {
                    break;
                }
                tried++;
            }
            return "- No Default Credentails Found (Tried " + tried + " / " + testDetails.Count + " variations)";
        }

        private static string TestPassword(string ip, string username, string password)
        {
            throw new NotImplementedException("This doesn't work yet");
            if (General.GetOS() == General.OS.Linux)
            {
                List<string> outputLines = General.GetProcessOutput("mysql", "-h121.42.253.211 -uroot -proot");
            }
            string connStr = "server=" + ip +
                       ";user=" + username +
                       //";database=" + dbName +
                       ";port=3306" +
                       ";password=" + password + ";";
            try
            {
                //MySqlConnection conx;
                //using (conx = new MySqlConnection(connStr))
                {
                    //  conx.Open();
                    // Conn was successful
                    return "true";
                }
            }
            catch (Exception ex)
            {
                if (ex.Message.StartsWith($"Authentication to host '{ip}' for user '{username}' using method 'mysql_native_password' failed with message: Access denied for user '{username}'")
                    && (ex.Message.EndsWith("' (using password: YES)") || ex.Message.EndsWith("' (using password: NO)")))
                {
                    return "false";
                }
                else
                {
                    // return "Unknown connection failure message: " + ex.Message;
                    return "break";
                }
            }
        }
    }
}
