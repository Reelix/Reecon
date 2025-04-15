using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Reecon
{
    // Beware
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/

    // Technically SMB2 AND SMB3 (They both have the same ProtocolID... Weird)
    public class SMB2_Protocol
    {
        private static readonly byte[] ZERO_BYTES_2 = { 0x00, 0x00 };
        private static readonly byte[] ZERO_BYTES_4 = Enumerable.Repeat((byte)0x00, 4).ToArray();
        private static readonly byte[] ZERO_BYTES_8 = Enumerable.Repeat((byte)0x00, 8).ToArray();
        private static readonly byte[] ZERO_BYTES_16 = Enumerable.Repeat((byte)0x00, 16).ToArray();

        // 2.2.1 SMB2 Packet Header
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052


        // [MS-SMB2] 2.2.1.2 SMB2 Packet Header - SYNC
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
        public static byte[] CreateHeader()
        {
            List<byte> smb2MessageHeader = new List<byte>();
            // ProtocolId
            smb2MessageHeader.AddRange(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' });
            // StructureSize
            ushort SMB2_HEADER_SIZE = 64;
            smb2MessageHeader.AddRange(BitConverter.GetBytes(SMB2_HEADER_SIZE));
            // CreditCharge
            smb2MessageHeader.AddRange(ZERO_BYTES_2);
            // Status/ChannelSequence/Reserved
            smb2MessageHeader.AddRange(ZERO_BYTES_4);

            // Command
            ushort SMB2_COMMAND_NEGOTIATE = 0x0000;
            smb2MessageHeader.AddRange(BitConverter.GetBytes(SMB2_COMMAND_NEGOTIATE));
            smb2MessageHeader.AddRange(BitConverter.GetBytes((ushort)1));                   // Credits Requested
            smb2MessageHeader.AddRange(ZERO_BYTES_4);                                        // Flags
            smb2MessageHeader.AddRange(ZERO_BYTES_4);                                        // NextCommand

            // MessageID (set to 0 initially)
            smb2MessageHeader.AddRange(ZERO_BYTES_8);

            // Reserved (PID High) / AsyncId[0-3]
            smb2MessageHeader.AddRange(ZERO_BYTES_4);

            // TreeId / AsyncId[4-7]
            smb2MessageHeader.AddRange(ZERO_BYTES_4);

            // SessionId
            smb2MessageHeader.AddRange(ZERO_BYTES_8);

            // Signature
            smb2MessageHeader.AddRange(ZERO_BYTES_16);

            if (smb2MessageHeader.Count != SMB2_HEADER_SIZE)
            {
                Console.WriteLine($"WARN: Header size mismatch. Expected {SMB2_HEADER_SIZE}, got {smb2MessageHeader.Count}");
            }
            byte[] returnBytes = smb2MessageHeader.ToArray();
            return returnBytes;
        }

        public static void ParseSMBHeader(byte[] response)
        {
            // This response is composed of an SMB2 header, as specified in section 2.2.1, followed by this response structure.
            // Log the Protocol ID (first 4 bytes)
            // Console.WriteLine("Protocol ID: " + BitConverter.ToString(response, 0, 4));

            // Check for SMB1 response
            if (response[0] == 0xFF)
            {
                Console.WriteLine("Server responded with SMB1.");
                throw new Exception("SMB1 response received");
            }

            // Verify SMB2 / SMB3 Protocol ID
            if (response[0] != 0xFE || response[1] != 'S' || response[2] != 'M' || response[3] != 'B')
            {
                Console.WriteLine("Invalid SMB2 protocol ID.");
                throw new Exception("Invalid SMB2 Negotiate Response");
            }

            // Log and check StructureSize (offset 4, 2 bytes)
            ushort structureSize = BitConverter.ToUInt16(response, 4);
            Console.WriteLine("StructureSize: " + structureSize);
            if (structureSize != 64)
            {
                Console.WriteLine("Invalid StructureSize: " + structureSize);
                throw new Exception("Invalid SMB2 Negotiate Response");
            }

            // Log and check Status (offset 8, 4 bytes)
            uint status = BitConverter.ToUInt32(response, 8);
            Console.WriteLine("Status: 0x" + status.ToString("X8"));
            if (status != 0)
            {
                Console.WriteLine("SMB2 Error: Status = 0x" + status.ToString("X8"));
                throw new Exception("SMB2 Negotiate failed with status " + status);
            }

            // Log and check Command (offset 12, 2 bytes)
            ushort command = BitConverter.ToUInt16(response, 12);
            // Console.WriteLine("Command: " + command);
            if (command != 0)
            {
                Console.WriteLine("Invalid Command: " + command);
                throw new Exception("Invalid SMB2 Negotiate Response");
            }

        }

        // 2.2.3 SMB2 NEGOTIATE Request - Creates a complete SMB2 NEGOTIATE request packet including Direct TCP framing.
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
        public static byte[] CreateNegotiateRequest()
        {
            // Initialize with a reasonable capacity
            List<byte> smb2MessageList = new List<byte>(200);

            // Header
            byte[] headerBytes = CreateHeader();
            smb2MessageList.AddRange(headerBytes);
            // [MS-SMB2] Section 2.2.3 - SMB2 NEGOTIATE Request

            // 1. StructureSize (2 bytes): MUST be 36
            ushort SMB2_NEGOTIATE_STRUCTURE_SIZE = 36;
            smb2MessageList.AddRange(BitConverter.GetBytes(SMB2_NEGOTIATE_STRUCTURE_SIZE));

            // 2. DialectCount (2 bytes)
            // TODO: 1.0... (3.1.1 was hell - Will that be any easaier? :p)
            ushort[] SUPPORTED_DIALECTS = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
            smb2MessageList.AddRange(BitConverter.GetBytes((ushort)SUPPORTED_DIALECTS.Length));

            // 3. SecurityMode (2 bytes)
            ushort SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;
            smb2MessageList.AddRange(BitConverter.GetBytes(SMB2_NEGOTIATE_SIGNING_ENABLED));

            // 4. Reserved (2 bytes): MUST be 0
            smb2MessageList.AddRange(ZERO_BYTES_2);

            // 5. Capabilities (4 bytes)
            uint SMB2_GLOBAL_CAP_DFS = 0x00000001;
            // uint SMB2_GLOBAL_CAP_LEASING = 0x00000002;
            uint SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004;
            uint SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008;
            uint SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040;
            uint clientCapabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_MULTI_CHANNEL | SMB2_GLOBAL_CAP_ENCRYPTION;
            smb2MessageList.AddRange(BitConverter.GetBytes(clientCapabilities));

            // 6. ClientGuid (16 bytes)
            Guid clientGuid = Guid.NewGuid();
            smb2MessageList.AddRange(clientGuid.ToByteArray());

            // 7. (NegotiateContextOffset, NegotiateContextCount, Reserved2) (8 bytes) - For SMB 3.1.1
            // --- Write Placeholders ---
            int negotiateContextOffsetIndex = smb2MessageList.Count; // Store index for later update
            smb2MessageList.AddRange(ZERO_BYTES_4); // Placeholder for NegotiateContextOffset
            int negotiateContextCountIndex = smb2MessageList.Count; // Store index for later update
            smb2MessageList.AddRange(ZERO_BYTES_2); // Placeholder for NegotiateContextCount
            smb2MessageList.AddRange(ZERO_BYTES_2); // Reserved2

            // --> End of fixed 36 bytes of Negotiate data (smb2MessageList.Count should be 64+36=100 here)

            // 8. Dialects (variable)
            foreach (var dialect in SUPPORTED_DIALECTS)
            {
                smb2MessageList.AddRange(BitConverter.GetBytes(dialect));
            }

            // 9. Padding (variable) - Align context list start
            int currentSizeBeforePadding = smb2MessageList.Count;
            int paddingSizeAfterDialects = (8 - (currentSizeBeforePadding % 8)) % 8;
            if (paddingSizeAfterDialects > 0)
            {
                smb2MessageList.AddRange(new byte[paddingSizeAfterDialects]);
            }

            // --> Context list starts here. Record the offset relative to HEADER start.
            uint calculatedContextOffsetValue = (uint)smb2MessageList.Count; // Offset is current size

            // Console.WriteLine($"Negotiate Data: ContextListStartsAt offset {calculatedContextOffsetValue} (0x{calculatedContextOffsetValue:X}) relative to header");

            // 10. NegotiateContextList (variable) [MS-SMB2] Section 2.2.3.1
            // --- Generate and Add Contexts Inline ---

            // Final context count
            ushort actualContextCount = 0;

            // Context 1: Preauthentication Integrity Capabilities
            {
                actualContextCount++;
                byte[] salt = RandomNumberGenerator.GetBytes(32);
                ushort hashCount = 1;
                ushort saltLength = (ushort)salt.Length;
                ushort SMB2_PREAUTH_INTEGRITY_HASH_ID_SHA512 = 0x0001;
                ushort[] hashes = { SMB2_PREAUTH_INTEGRITY_HASH_ID_SHA512 };

                List<byte> contextData = new List<byte>();
                contextData.AddRange(BitConverter.GetBytes(hashCount));
                contextData.AddRange(BitConverter.GetBytes(saltLength));
                foreach (var hash in hashes) { contextData.AddRange(BitConverter.GetBytes(hash)); }
                contextData.AddRange(salt);
                byte[] contextDataBytes = contextData.ToArray();

                int contextHeaderSize = 8;
                int totalContextSize = contextHeaderSize + contextDataBytes.Length;
                int paddingForThisContext = (8 - (totalContextSize % 8)) % 8;

                ushort SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001;
                smb2MessageList.AddRange(BitConverter.GetBytes(SMB2_PREAUTH_INTEGRITY_CAPABILITIES));
                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)contextDataBytes.Length));
                smb2MessageList.AddRange(ZERO_BYTES_4); // Reserved
                smb2MessageList.AddRange(contextDataBytes);
                if (paddingForThisContext > 0)
                {
                    smb2MessageList.AddRange(new byte[paddingForThisContext]);
                }
            }

            // Context 2: Encryption Capabilities
            {
                actualContextCount++;
                ushort SMB2_ENCRYPTION_CIPHER_ID_AES128_GCM = 0x0002;
                ushort SMB2_ENCRYPTION_CIPHER_ID_AES128_CCM = 0x0001;
                ushort[] ciphers = { SMB2_ENCRYPTION_CIPHER_ID_AES128_GCM, SMB2_ENCRYPTION_CIPHER_ID_AES128_CCM };
                ushort cipherCount = (ushort)ciphers.Length;

                List<byte> contextData = new List<byte>();
                contextData.AddRange(BitConverter.GetBytes(cipherCount));
                foreach (var cipher in ciphers)
                {
                    contextData.AddRange(BitConverter.GetBytes(cipher));
                }
                byte[] contextDataBytes = contextData.ToArray();

                int contextHeaderSize = 8;
                int totalContextSize = contextHeaderSize + contextDataBytes.Length;
                int paddingForThisContext = (8 - (totalContextSize % 8)) % 8;

                ushort SMB2_ENCRYPTION_CAPABILITIES = 0x0002;
                smb2MessageList.AddRange(BitConverter.GetBytes(SMB2_ENCRYPTION_CAPABILITIES));
                smb2MessageList.AddRange(BitConverter.GetBytes((ushort)contextDataBytes.Length));
                smb2MessageList.AddRange(ZERO_BYTES_4); // Reserved
                smb2MessageList.AddRange(contextDataBytes);
                if (paddingForThisContext > 0)
                {
                    smb2MessageList.AddRange(new byte[paddingForThisContext]);
                }
            }

            // --- Update Placeholders in the List ---
            // Note: Need to get bytes for the values first
            byte[] offsetBytes = BitConverter.GetBytes(calculatedContextOffsetValue);
            byte[] countBytes = BitConverter.GetBytes(actualContextCount);

            // Overwrite the bytes in the list
            for (int i = 0; i < 4; i++)
            {
                smb2MessageList[negotiateContextOffsetIndex + i] = offsetBytes[i];
            }
            for (int i = 0; i < 2; i++)
            {
                smb2MessageList[negotiateContextCountIndex + i] = countBytes[i];
            }

            // --- Convert List to final byte array ---
            byte[] smb2Message = smb2MessageList.ToArray();
            int smbMessageLength = smb2Message.Length;
            // Console.WriteLine($"Final SMB Message Length: {smbMessageLength} (0x{smbMessageLength:X})");

            // --- Prepend Direct TCP Transport Header ---
            uint streamLength = (uint)smbMessageLength;
            byte[] packet = new byte[4 + streamLength];
            packet[0] = 0x00; // Direct TCP marker
            packet[1] = (byte)(streamLength >> 16);
            packet[2] = (byte)(streamLength >> 8);
            packet[3] = (byte)streamLength;
            Buffer.BlockCopy(smb2Message, 0, packet, 4, smbMessageLength);

            // Console.WriteLine($"Final Packet Length: {packet.Length} bytes (Direct TCP Header: {ToHexString(packet, 4)}, Declared SMB Length: {streamLength})");
            // Console.WriteLine($"Full Request Hex Dump:\n{ToHexString(packet)}");

            return packet;
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
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
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
            // Console.WriteLine("Response Data StructureSize: " + dataStructureSize);
            if (dataStructureSize != 65)
            {
                Console.WriteLine("Invalid response structure size: " + dataStructureSize);
                throw new Exception("Invalid SMB2 Negotiate Response");
            }

            // Extract and log fields
            ushort securityMode = BitConverter.ToUInt16(data, 2);
            // Console.WriteLine("SecurityMode: 0x" + securityMode.ToString("X4"));

            ushort dialectRevision = BitConverter.ToUInt16(data, 4);
            // Console.WriteLine("DialectRevision: 0x" + dialectRevision.ToString("X4"));

            long systemTimeFileTime = BitConverter.ToInt64(data, 40);
            // Console.WriteLine("SystemTime (FILETIME): " + systemTimeFileTime);

            long serverStartTimeFileTime = BitConverter.ToInt64(data, 48);
            // Console.WriteLine("ServerStartTime (FILETIME): " + serverStartTimeFileTime);

            // Process times
            DateTime systemTime = DateTime.FromFileTimeUtc(systemTimeFileTime);
            string startDate = serverStartTimeFileTime == 0 ? "N/A" :
                              DateTime.FromFileTimeUtc(serverStartTimeFileTime).ToString("yyyy-MM-ddTHH:mm:ss");

            TimeSpan skew = systemTime - DateTime.UtcNow;
            string skewStr = string.Format("{0}{1}h{2:D2}m{3:D2}s",
                                           skew < TimeSpan.Zero ? "-" : "",
                                           Math.Abs(skew.Days * 24 + skew.Hours),
                                           Math.Abs(skew.Minutes),
                                           Math.Abs(skew.Seconds));

            // Process dialect
            string dialectStr;
            switch (dialectRevision)
            {
                case 0x0202:
                    dialectStr = "2:0:2";
                    break;
                case 0x0210:
                    dialectStr = "2:1";
                    break;
                case 0x0300:
                    dialectStr = "3:0";
                    break;
                case 0x0302:
                    dialectStr = "3:0:2";
                    break;
                case 0x0311:
                    dialectStr = "3:1:1";
                    break;
                default:
                    dialectStr = "Unknown";
                    break;
            }

            // Process security mode
            string signingStatus = (securityMode & 0x0002) != 0 ? "Message signing enabled and required" :
                                  (securityMode & 0x0001) != 0 ? "Message signing enabled but not required" :
                                  "Message signing not enabled";

            NegotiateResponse response = new NegotiateResponse();
            response.ClockSkew = skewStr;
            response.DialectStr = dialectStr;
            response.SystemTime = systemTime;
            response.StartDate = startDate;
            response.SigningStatus = signingStatus;
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

            // :|
            uint length = (uint)((lengthBytes[0] << 24) | (lengthBytes[1] << 16) | (lengthBytes[2] << 8) | lengthBytes[3]);

            byte[] response = new byte[length];
            try
            {
                stream.ReadExactly(response, 0, (int)length);
            }
            catch (EndOfStreamException)
            {
                throw new Exception("Connection closed");
            }
            return response;
        }
    }
}
