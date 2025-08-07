using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Reecon
{
    // Beware
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/

    // Technically SMB2 AND SMB3 (They both have the same ProtocolID... Weird)
    public class Smb2_Protocol
    {
        private static readonly byte[] ZERO_BYTES_2 = { 0x00, 0x00 };
        private static readonly byte[] ZERO_BYTES_4 = Enumerable.Repeat((byte)0x00, 4).ToArray();
        private static readonly byte[] ZERO_BYTES_8 = Enumerable.Repeat((byte)0x00, 8).ToArray();
        private static readonly byte[] ZERO_BYTES_16 = Enumerable.Repeat((byte)0x00, 16).ToArray();

        // --- SMB2 Command Codes ---
        public const ushort SMB2_COMMAND_NEGOTIATE = 0x0000;
        public const ushort SMB2_COMMAND_SESSION_SETUP = 0x0001;
        public const ushort SMB2_COMMAND_LOGOFF = 0x0002;
        public const ushort SMB2_COMMAND_TREE_CONNECT = 0x0003;
        public const ushort SMB2_COMMAND_TREE_DISCONNECT = 0x0004;
        public const ushort SMB2_COMMAND_CREATE = 0x0005;
        public const ushort SMB2_COMMAND_CLOSE = 0x0006;
        public const ushort SMB2_COMMAND_READ = 0x0008;
        public const ushort SMB2_COMMAND_WRITE = 0x0009;


        // [MS-SMB2] 2.2.1.2 SMB2 Packet Header - SYNC
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
        public static byte[] CreateHeader(ushort command, ulong messageId, uint treeId = 0, ulong sessionId = 0)
        {
            List<byte> header = new List<byte>();
            header.AddRange(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' }); // ProtocolId
            header.AddRange(BitConverter.GetBytes((ushort)64)); // StructureSize
            header.AddRange(ZERO_BYTES_2); // CreditCharge
            header.AddRange(ZERO_BYTES_4); // Status/ChannelSequence/Reserved
            header.AddRange(BitConverter.GetBytes(command)); // Command
            header.AddRange(BitConverter.GetBytes((ushort)1)); // Credits Requested
            header.AddRange(ZERO_BYTES_4); // Flags
            header.AddRange(ZERO_BYTES_4); // NextCommand
            header.AddRange(BitConverter.GetBytes(messageId)); // MessageID
            header.AddRange(ZERO_BYTES_4); // Reserved (PID High) / AsyncId[0-3]
            header.AddRange(BitConverter.GetBytes(treeId)); // TreeId
            header.AddRange(BitConverter.GetBytes(sessionId)); // SessionId
            header.AddRange(ZERO_BYTES_16); // Signature
            return header.ToArray();
        }

        public static (uint status, ulong sessionId, uint treeId, byte[] data) ParseHeaderAndGetData(byte[] response)
        {
            if (response.Length < 64) throw new InvalidDataException("Response too short for an SMB2 header.");
            if (response[0] != 0xFE || response[1] != 'S' || response[2] != 'M' || response[3] != 'B')
                throw new InvalidDataException("Invalid SMB2 protocol ID in response.");

            uint status = BitConverter.ToUInt32(response, 8);
            ulong sessionId = BitConverter.ToUInt64(response, 44);
            uint treeId = BitConverter.ToUInt32(response, 52);
            byte[] data = response.Skip(64).ToArray();
            return (status, sessionId, treeId, data);
        }

        private static byte[] PrependDirectTCPHeader(byte[] smbMessage)
        {
            uint streamLength = (uint)smbMessage.Length;
            byte[] packet = new byte[4 + streamLength];
            packet[0] = 0x00;
            packet[1] = (byte)(streamLength >> 16);
            packet[2] = (byte)(streamLength >> 8);
            packet[3] = (byte)streamLength;
            Buffer.BlockCopy(smbMessage, 0, packet, 4, (int)streamLength);
            return packet;
        }

        // 2.2.3 SMB2 NEGOTIATE Request
        public static byte[] CreateNegotiateRequest()
        {
            // SMB2 Header
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_NEGOTIATE, 0);
            var smb2MessageList = new List<byte>(headerBytes);

            // Negotiate Request Body (fixed part)
            ushort[] SUPPORTED_DIALECTS = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };

            smb2MessageList.AddRange(BitConverter.GetBytes((ushort)36)); // StructureSize
            smb2MessageList.AddRange(BitConverter.GetBytes((ushort)SUPPORTED_DIALECTS.Length)); // DialectCount
            smb2MessageList.AddRange(BitConverter.GetBytes((ushort)0x0001)); // SecurityMode: Signing Enabled
            smb2MessageList.AddRange(ZERO_BYTES_2); // Reserved

            // Capabilities for SMB 3.1.1. The presence of a NegotiateContextList allows advertising these.
            uint clientCapabilities = 0x00000001; // DFS
            clientCapabilities |= 0x00000040; // Encryption
            smb2MessageList.AddRange(BitConverter.GetBytes(clientCapabilities));
            smb2MessageList.AddRange(Guid.NewGuid().ToByteArray()); // ClientGuid

            // Placeholders for Negotiate Contexts. Offset is calculated after dialects are added.
            int negotiateContextOffsetIndex = smb2MessageList.Count;
            smb2MessageList.AddRange(ZERO_BYTES_4); // Placeholder for NegotiateContextOffset
            smb2MessageList.AddRange(BitConverter.GetBytes((ushort)2)); // NegotiateContextCount = 2
            smb2MessageList.AddRange(ZERO_BYTES_2); // Reserved2

            // Dialects array
            foreach (var dialect in SUPPORTED_DIALECTS)
            {
                smb2MessageList.AddRange(BitConverter.GetBytes(dialect));
            }

            // Padding to align NegotiateContextList to an 8-byte boundary
            int paddingSize = (8 - (smb2MessageList.Count % 8)) % 8;
            smb2MessageList.AddRange(new byte[paddingSize]);

            // Now, calculate and write the real offset
            uint negotiateContextOffset = (uint)smb2MessageList.Count;
            byte[] offsetBytes = BitConverter.GetBytes(negotiateContextOffset);
            for (int i = 0; i < 4; i++) smb2MessageList[negotiateContextOffsetIndex + i] = offsetBytes[i];

            // --- NegotiateContextList ---

            // Context 1: Preauthentication Integrity
            {
                var contextData = new List<byte>();
                contextData.AddRange(BitConverter.GetBytes((ushort)1)); // HashAlgorithmCount = 1
                contextData.AddRange(BitConverter.GetBytes((ushort)32)); // SaltLength = 32
                contextData.AddRange(BitConverter.GetBytes((ushort)0x0001)); // HashAlgorithm: SHA-512
                contextData.AddRange(RandomNumberGenerator.GetBytes(32)); // Salt

                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)0x0001)); // ContextType: Preauth
                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)contextData.Count)); // DataLength
                smb2MessageList.AddRange(ZERO_BYTES_4); // Reserved
                smb2MessageList.AddRange(contextData);

                // Pad to next 8-byte boundary
                paddingSize = (8 - (smb2MessageList.Count % 8)) % 8;
                smb2MessageList.AddRange(new byte[paddingSize]);
            }

            // Context 2: Encryption Capabilities
            {
                var contextData = new List<byte>();
                contextData.AddRange(BitConverter.GetBytes((ushort)2)); // CipherCount = 2
                contextData.AddRange(BitConverter.GetBytes((ushort)0x0002)); // Cipher: AES-128-GCM
                contextData.AddRange(BitConverter.GetBytes((ushort)0x0001)); // Cipher: AES-128-CCM

                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)0x0002)); // ContextType: Encryption
                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)contextData.Count)); // DataLength
                smb2MessageList.AddRange(ZERO_BYTES_4); // Reserved
                smb2MessageList.AddRange(contextData);

                // Pad to next 8-byte boundary
                paddingSize = (8 - (smb2MessageList.Count % 8)) % 8;
                smb2MessageList.AddRange(new byte[paddingSize]);
            }

            return PrependDirectTCPHeader(smb2MessageList.ToArray());
        }

        // 2.2.5 SMB2 SESSION_SETUP Request
        public static byte[] CreateSessionSetupRequest(ulong messageId, string dialect)
        {
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_SESSION_SETUP, messageId);
            var message = new List<byte>(headerBytes);

            byte flags = 0;
            // For dialect 3.1.1, the BINDING flag is required for a new session setup.
            if (dialect == "3.1.1")
            {
                flags = 0x01; // SMB2_SESSION_FLAG_BINDING
            }

            // For anonymous/null session, we send an empty security blob.
            message.AddRange(BitConverter.GetBytes((ushort)25)); // StructureSize
            message.Add(flags); // Flags
            message.Add(1); // SecurityMode: SMB2_NEGOTIATE_SIGNING_ENABLED
            message.AddRange(BitConverter.GetBytes((uint)0)); // Capabilities
            message.AddRange(BitConverter.GetBytes((uint)0)); // Channel
            message.AddRange(BitConverter.GetBytes((ushort)(64 + 24))); // SecurityBufferOffset
            message.AddRange(BitConverter.GetBytes((ushort)0)); // SecurityBufferLength
            message.AddRange(ZERO_BYTES_8); // PreviousSessionId

            return PrependDirectTCPHeader(message.ToArray());
        }

        // 2.2.9 SMB2 TREE_CONNECT Request
        public static byte[] CreateTreeConnectRequest(string target, ulong messageId, ulong sessionId)
        {
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_TREE_CONNECT, messageId, 0, sessionId);
            var message = new List<byte>(headerBytes);

            string path = $@"\\{target}\IPC$";
            byte[] pathBytes = Encoding.Unicode.GetBytes(path);

            message.AddRange(BitConverter.GetBytes((ushort)9)); // StructureSize
            message.AddRange(ZERO_BYTES_2); // Reserved
            message.AddRange(BitConverter.GetBytes((ushort)(64 + 8))); // PathOffset
            message.AddRange(BitConverter.GetBytes((ushort)pathBytes.Length)); // PathLength
            message.AddRange(pathBytes);

            return PrependDirectTCPHeader(message.ToArray());
        }

        // 2.2.13 SMB2 CREATE Request
        public static byte[] CreateCreateRequest(string pipeName, ulong messageId, uint treeId, ulong sessionId)
        {
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_CREATE, messageId, treeId, sessionId);
            var message = new List<byte>(headerBytes);

            byte[] nameBytes = Encoding.Unicode.GetBytes(pipeName);

            message.AddRange(BitConverter.GetBytes((ushort)57)); // StructureSize
            message.Add(0); // SecurityFlags
            message.Add(0); // RequestedOplock
            message.AddRange(BitConverter.GetBytes((uint)0x0012019F)); // Desired Access (Generic All)
            message.AddRange(BitConverter.GetBytes((ulong)0)); // File Attributes
            message.AddRange(BitConverter.GetBytes((uint)0x00000007)); // Share Access (Read, Write, Delete)
            message.AddRange(BitConverter.GetBytes((uint)1)); // Create Disposition (FILE_OPEN)
            message.AddRange(BitConverter.GetBytes((uint)0)); // Create Options
            message.AddRange(BitConverter.GetBytes((ushort)(64 + 56))); // NameOffset
            message.AddRange(BitConverter.GetBytes((ushort)nameBytes.Length)); // NameLength
            message.AddRange(BitConverter.GetBytes((uint)0)); // CreateContextsOffset
            message.AddRange(BitConverter.GetBytes((uint)0)); // CreateContextsLength
            message.AddRange(nameBytes);

            return PrependDirectTCPHeader(message.ToArray());
        }

        public static byte[] ParseCreateResponse(byte[] data)
        {
            // The FileId is a 16-byte GUID-like structure
            return data.Skip(48).Take(16).ToArray();
        }

        // 2.2.19 SMB2 WRITE Request
        public static byte[] CreateWriteRequest(byte[] payload, byte[] fileId, ulong messageId, uint treeId, ulong sessionId)
        {
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_WRITE, messageId, treeId, sessionId);
            var message = new List<byte>(headerBytes);

            message.AddRange(BitConverter.GetBytes((ushort)49)); // StructureSize
            message.AddRange(BitConverter.GetBytes((ushort)(64 + 48))); // DataOffset
            message.AddRange(BitConverter.GetBytes((uint)payload.Length)); // Length
            message.AddRange(BitConverter.GetBytes((ulong)0)); // Offset
            message.AddRange(fileId); // FileId
            message.AddRange(ZERO_BYTES_4); // Channel
            message.AddRange(ZERO_BYTES_4); // RemainingBytes
            message.AddRange(ZERO_BYTES_2); // WriteChannelInfoOffset
            message.AddRange(ZERO_BYTES_2); // WriteChannelInfoLength
            message.Add(0); // Flags
            message.AddRange(payload);

            return PrependDirectTCPHeader(message.ToArray());
        }

        // 2.2.15 SMB2 READ Request
        public static byte[] CreateReadRequest(byte[] fileId, ulong messageId, uint treeId, ulong sessionId)
        {
            byte[] headerBytes = CreateHeader(SMB2_COMMAND_READ, messageId, treeId, sessionId);
            var message = new List<byte>(headerBytes);

            message.AddRange(BitConverter.GetBytes((ushort)49)); // StructureSize
            message.Add(8); // Padding
            message.Add(0); // Reserved
            message.AddRange(BitConverter.GetBytes((uint)0x1000)); // Length to read
            message.AddRange(BitConverter.GetBytes((ulong)0)); // Offset
            message.AddRange(fileId); // FileId
            message.AddRange(BitConverter.GetBytes((uint)1)); // MinimumCount
            message.AddRange(ZERO_BYTES_4); // Channel
            message.AddRange(ZERO_BYTES_4); // RemainingBytes
            message.AddRange(ZERO_BYTES_2); // ReadChannelInfoOffset
            message.AddRange(ZERO_BYTES_2); // ReadChannelInfoLength

            return PrependDirectTCPHeader(message.ToArray());
        }

        public static byte[] ParseReadResponse(byte[] data)
        {
            ushort dataOffset = BitConverter.ToUInt16(data, 0);
            uint dataLength = BitConverter.ToUInt32(data, 4);
            return data.Skip(dataOffset - 64).Take((int)dataLength).ToArray();
        }

        public class NegotiateResponse()
        {
            public string ClockSkew = "";
            public string DialectStr = "";
            public DateTime SystemTime = new DateTime();
            public string StartDate = "";
            public string SigningStatus = "";
        }

        // 2.2.4 SMB2 NEGOTIATE Response
        public static NegotiateResponse ParseNegotiateResponse(byte[] data)
        {
            // This response is composed of an SMB2 header, as specified in section 2.2.1, followed by this response structure.
            if (data.Length < 64)
            {
                Console.WriteLine("Response too short: " + data.Length + " bytes.");
                throw new Exception("Invalid SMB2 response");
            }
            
            // Don't really need to parse the header right now
            // List<byte> responseHeader = data.Take(64).ToList();
            // ParseSMBHeader(responseHeader.ToArray());
            data = data.Skip(64).ToArray();

            // SMB2 NEGOTIATE Response
            // Check response data StructureSize (should be 65 for Negotiate Response)
            ushort dataStructureSize = BitConverter.ToUInt16(data, 0);
            if (dataStructureSize != 65)
            {
                Console.WriteLine("Invalid response structure size: " + dataStructureSize);
                throw new Exception("Invalid SMB2 Negotiate Response structure size.");
            }

            // Extract and log fields
            ushort securityMode = BitConverter.ToUInt16(data, 2);
            ushort dialectRevision = BitConverter.ToUInt16(data, 4);
            long systemTimeFileTime = BitConverter.ToInt64(data, 40);
            long serverStartTimeFileTime = BitConverter.ToInt64(data, 48);

            DateTime systemTime = DateTime.FromFileTimeUtc(systemTimeFileTime);
            string startDate = serverStartTimeFileTime == 0 ? "N/A" :
                              DateTime.FromFileTimeUtc(serverStartTimeFileTime).ToString("yyyy-MM-ddTHH:mm:ss");

            TimeSpan skew = systemTime - DateTime.UtcNow;
            string skewStr = string.Format("{0}{1}h{2:D2}m{3:D2}s",
                                           skew < TimeSpan.Zero ? "-" : "",
                                           Math.Abs(skew.Days * 24 + skew.Hours),
                                           Math.Abs(skew.Minutes),
                                           Math.Abs(skew.Seconds));
            string dialectStr = dialectRevision switch
            {
                0x0202 => "2.0.2",
                0x0210 => "2.1",
                0x0300 => "3.0",
                0x0302 => "3.0.2",
                0x0311 => "3.1.1",
                _ => "Unknown"
            };
            
            // Process security mode
            string signingStatus = (securityMode & 0x0002) != 0 ? "Message signing enabled and required" :
                                  (securityMode & 0x0001) != 0 ? "Message signing enabled but not required" :
                                  "Message signing not enabled";

            NegotiateResponse response = new NegotiateResponse
            {
                ClockSkew = skewStr,
                DialectStr = dialectStr,
                SystemTime = systemTime,
                StartDate = startDate,
                SigningStatus = signingStatus
            };
            return response;
        }

        public static byte[] ReadResponse(NetworkStream stream)
        {
            byte[] lengthBytes = new byte[4];
            try
            {
                stream.ReadExactly(lengthBytes, 0, 4);
            }
            catch (EndOfStreamException)
            {
                throw new Exception("Connection closed");
            }

            if (lengthBytes[0] != 0)
            {
                throw new InvalidDataException("Not a Direct TCP packet.");
            }
            
            // :|
            uint length = (uint)((lengthBytes[1] << 16) | (lengthBytes[2] << 8) | lengthBytes[3]);

            byte[] response = new byte[length];
            int totalRead = 0;
            while (totalRead < length)
            {
                int read = stream.Read(response, totalRead, (int)length - totalRead);
                if (read == 0) throw new EndOfStreamException("Connection closed while reading response body.");
                totalRead += read;
            }
            return response;
        }
    }
}