using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Reecon
{
    // Beware
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/
    public class SMB1_Protocol
    {
        public const int SMB1_HEADER_SIZE = 32;
        private static readonly byte[] ZERO_BYTES_2 = { 0, 0 };
        private static readonly byte[] ZERO_BYTES_4 = { 0, 0, 0, 0 };
        private static readonly byte[] ZERO_BYTES_8 = { 0, 0, 0, 0, 0, 0, 0, 0 };

        public static readonly string[] DIALECTS = new[] { "LANMAN1.0", "LM1.2X002", "NT LANMAN 1.0", "NT LM 0.12" };
        public static byte[] CreateSmbHeader(byte command, ushort userId, ushort treeId)
        {
            List<byte> header = new List<byte>(SMB1_HEADER_SIZE);
            header.AddRange(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }); header.Add(command);

            // 0x2000 (SMB_FLAGS2_PERMIT_READ_IF_EXECUTE) + 0x0800 (SMB_FLAGS2_EXTENDED_SECURITY) + 0x0001 (SMB_FLAGS2_KNOWS_EAS).
            ushort flags2 = 0x0128;
            header.AddRange(ZERO_BYTES_4);
            header.Add(0x18);
            header.AddRange(BitConverter.GetBytes(flags2));
            header.AddRange(ZERO_BYTES_2);
            header.AddRange(ZERO_BYTES_8);
            header.AddRange(ZERO_BYTES_2);
            header.AddRange(BitConverter.GetBytes(treeId));
            header.AddRange(ZERO_BYTES_2); // PID Low placeholder
            header.AddRange(BitConverter.GetBytes(userId));

            ushort MultiplexID_Negotiate = 49474;
            header.AddRange(BitConverter.GetBytes(MultiplexID_Negotiate));
            return header.ToArray();
        }

        /// <summary>
        /// Attempts to parse common fields from an SMBv1 header.
        /// </summary>
        /// <param name="smbData">Byte array containing the SMB message (starting with 0xFF SMB).</param>
        /// <param name="status">Output: NTStatus code from the header.</param>
        /// <param name="command">Output: SMB command code.</param>
        /// <param name="multiplexId">Output: Multiplex ID.</param>
        /// <param name="userId">Output: User ID.</param>
        /// <param name="treeId">Output: Tree ID.</param>
        /// <param name="flags2">Output: Flags2 field value.</param>
        /// <returns>True if header is valid and parsed successfully, False otherwise.</returns>
        public static bool TryParseSmbHeader(byte[] smbData, out uint status, out byte command, out ushort multiplexId, out ushort userId, out ushort treeId, out ushort flags2)
        {
            // Initialize output parameters to default/error values
            status = 0xFFFFFFFF;
            command = 0xFF;
            multiplexId = 0xFFFF;
            userId = 0xFFFF;
            treeId = 0xFFFF;
            flags2 = 0;

            // Basic validation
            if (smbData == null || smbData.Length < SMB1_HEADER_SIZE)
            {
                Console.WriteLine("DEBUG: TryParseSmbHeader - Input data null or too short.");
                return false;
            }

            try
            {
                // Verify SMB Magic Number (Protocol ID)
                if (!(smbData[0] == 0xFF && smbData[1] == (byte)'S' && smbData[2] == (byte)'M' && smbData[3] == (byte)'B'))
                {
                    Console.WriteLine("DEBUG: TryParseSmbHeader - Invalid SMB magic number.");
                    return false; // Not a valid SMB packet
                }

                // Extract fields using known offsets
                command = smbData[4];                       // Offset 4
                status = BitConverter.ToUInt32(smbData, 5); // Offset 5
                flags2 = BitConverter.ToUInt16(smbData, 10);// Offset 10
                treeId = BitConverter.ToUInt16(smbData, 24);   // Offset 24
                userId = BitConverter.ToUInt16(smbData, 28);   // Offset 28
                multiplexId = BitConverter.ToUInt16(smbData, 30);   // Offset 30

                return true; // Successfully parsed
            }
            catch (Exception ex) // Catch potential ArgumentOutOfRangeException etc.
            {
                Console.WriteLine($"DEBUG: TryParseSmbHeader - Exception during parsing: {ex.Message}");
                return false; // Parsing failed
            }
        }

        public static byte[] CreateNegotiateRequest()
        {
            // Use PingCastle specific constants
            ushort pidLow = 27972;
            string[] dialectsToOffer = DIALECTS;

            // Console.WriteLine("DEBUG: Creating Negotiate Request");

            // 1. Create the base SMB header
            //    MID used here is the fixed PingCastle MID for Negotiate. UID/TID are 0.
            byte SMB1_COMMAND_NEGOTIATE = 0x72;
            byte[] header = CreateSmbHeader(SMB1_COMMAND_NEGOTIATE, 0, 0);

            // 2. Set the specific low Process ID in the header (offset 26)
            byte[] pidBytes = BitConverter.GetBytes(pidLow);
            header[26] = pidBytes[0];
            header[27] = pidBytes[1];

            // 3. Build the message body starting with the header
            List<byte> message = new List<byte>(header);

            // 4. Add SMB parameters (WCT = 0 for Negotiate)
            message.Add(0x00); // Word Count (WCT) = 0

            // 5. Add placeholder for Byte Count (BCC)
            int bccIndex = message.Count;
            message.AddRange(ZERO_BYTES_2); // Placeholder [0x00, 0x00]

            // 6. Add SMB data (Dialect strings)
            List<byte> dialectData = new List<byte>();
            foreach (string dialect in dialectsToOffer)
            {
                dialectData.Add(0x02); // Format: 0x02 indicates a null-terminated string follows
                dialectData.AddRange(Encoding.ASCII.GetBytes(dialect)); // Dialect name in ASCII
                dialectData.Add(0x00); // Null terminator
            }
            // Ensure there's at least one byte if the list was empty (shouldn't happen)
            if (dialectData.Count == 0)
            {
                dialectData.Add(0x00);
            }
            message.AddRange(dialectData); // Add the constructed dialect bytes to the message

            // 7. Calculate and insert the actual Byte Count (BCC)
            //    BCC is the count of bytes *after* the BCC field itself (i.e., the dialect data).
            ushort bcc = (ushort)dialectData.Count;
            byte[] bccBytes = BitConverter.GetBytes(bcc);
            message[bccIndex] = bccBytes[0];      // Set Low byte of BCC
            message[bccIndex + 1] = bccBytes[1];  // Set High byte of BCC

            // 8. Prepend the NetBIOS Session Service header
            return PrependNbssHeader(message.ToArray());
        }

        public class NegotiateResponse
        {
            // --- SMB Header Info (Extracted for context) ---
            public uint NTStatus { get; set; } = 0xFFFFFFFF;
            public byte SmbFlags { get; set; }
            public ushort SmbFlags2 { get; set; }
            public ushort Mid { get; set; }
            public ushort Uid { get; set; }
            public ushort Tid { get; set; }

            // --- SMB_COM_NEGOTIATE Response Parameters (Words) ---
            public ushort DialectIndex { get; set; } = 0xFFFF;
            public string SelectedDialect { get; set; } = "N/A";
            public byte? SecurityMode { get; set; }
            public ushort? MaxMpxCount { get; set; }
            public ushort? MaxNumberVcs { get; set; }
            public uint? MaxBufferSize { get; set; } // Changed to uint based on spec
            public uint? MaxRawSize { get; set; }
            public uint? SessionKey { get; set; }
            public uint? Capabilities { get; set; }
            public long? SystemTimeRaw { get; set; }
            public short? ServerTimeZone { get; set; }
            public byte ChallengeLengthParam { get; set; } // Store the value from param block if needed

            // --- SMB_COM_NEGOTIATE Response Data (Bytes) ---
            public byte[]? SecurityBlob { get; set; }
            public byte[]? Challenge { get; set; } // Actual 8-byte challenge if applicable
            public string? DomainName { get; set; }
            public string? ServerName { get; set; }

            // --- Derived/Helper Properties ---
            public bool IsSuccessNegotiation => NTStatus == 0 || NTStatus == 0xC0000016;
            public bool SupportsExtendedSecurity => (SecurityMode.HasValue && (SecurityMode.Value & 0x08) != 0) || (Capabilities.HasValue && (Capabilities.Value & 0x80000000) != 0);
            public bool SupportsUnicode => (SmbFlags2 & 0x8000) != 0 || (Capabilities.HasValue && (Capabilities.Value & 0x00000004) != 0);

            public List<string> GetCapabilityList()
            {
                var caps = new List<string>();
                if (!Capabilities.HasValue) return caps;
                uint c = Capabilities.Value;
                if ((c & 0x00000001) != 0) caps.Add("RAW_MODE");
                if ((c & 0x00000002) != 0) caps.Add("READ_RAW");
                if ((c & 0x00000004) != 0) caps.Add("UNICODE");
                if ((c & 0x00000008) != 0) caps.Add("LARGE_FILES");
                if ((c & 0x00000010) != 0) caps.Add("NT_SMBS");
                if ((c & 0x00000020) != 0) caps.Add("RPC_REMOTE_APIS");
                if ((c & 0x00000040) != 0) caps.Add("NT_STATUS"); // STATUS32
                if ((c & 0x00000080) != 0) caps.Add("LEVEL_II_OPLOCKS");
                if ((c & 0x00000100) != 0) caps.Add("LOCK_AND_READ");
                if ((c & 0x00000200) != 0) caps.Add("NT_FIND");
                if ((c & 0x00001000) != 0) caps.Add("DFS");
                if ((c & 0x00004000) != 0) caps.Add("LARGE_READX");
                if ((c & 0x00008000) != 0) caps.Add("LARGE_WRITEX");
                if ((c & 0x00800000) != 0) caps.Add("UNIX");
                if ((c & 0x80000000) != 0) caps.Add("EXTENDED_SECURITY");
                return caps;
            }
            public string GetSecurityModeDescription()
            {
                if (!SecurityMode.HasValue) return "N/A";
                byte sm = SecurityMode.Value;
                var modes = new List<string>();
                modes.Add((sm & 0x01) != 0 ? "User-Level Security" : "Share-Level Security");
                if ((sm & 0x02) != 0) modes.Add("Encrypt Passwords");
                if ((sm & 0x08) != 0) modes.Add("Extended Security");
                return string.Join(", ", modes);
            }
        }

        public static NegotiateResponse ParseNegotiateResponse(byte[] smbData, string[] clientDialectsUsed)
        {
            if (smbData == null || smbData.Length == 0) throw new ArgumentException("Cannot parse null or empty SMB data array.");
            var response = new NegotiateResponse();
            if (!TryParseSmbHeader(smbData, out uint status, out byte command, out ushort mid, out ushort uid, out ushort tid, out ushort flags2))
            {
                throw new InvalidDataException("Invalid SMB Header in Negotiate Response");
            }

            response.NTStatus = status;
            response.SmbFlags = smbData.Length > 9 ? smbData[9] : (byte)0;
            response.SmbFlags2 = flags2;
            response.Mid = mid;
            response.Uid = uid;
            response.Tid = tid;

            byte SMB_CMD_NEGOTIATE = 0x72;
            if (command != SMB_CMD_NEGOTIATE)
            {
                Console.WriteLine($"WARN: Expected Command 0x72, got 0x{command:X2}");
                response.SelectedDialect = "FAILURE: Unexpected Command";
                response.DialectIndex = 0xFFFF; return response;
            }
            int offset = SMB1_HEADER_SIZE;
            if (offset >= smbData.Length)
            {
                Console.WriteLine("INFO: Header-only response");
                response.SelectedDialect = "FAILURE: Header-only response";
                response.DialectIndex = 0xFFFF; return response;
            }

            byte wordCount = smbData[offset++];
            int expectedParamBytes = CalculateParamBytes(wordCount);
            int pStart = offset; int pEnd = pStart + expectedParamBytes;
            if (pEnd > smbData.Length || pEnd + 2 > smbData.Length)
            {
                Console.WriteLine($"ERROR: Truncated parameters or BCC. WCT={wordCount}");
                response.SelectedDialect = "FAILURE: Truncated parameters/BCC";
                response.DialectIndex = 0xFFFF;
                return response;
            }

            if (wordCount > 0)
            {
                try
                {
                    ParseParameters(smbData, pStart, wordCount, response);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"ERROR parsing params: {ex.Message}");
                }
            }
            else
            {
                response.SelectedDialect = $"WARNING: WCT=0 Status=0x{response.NTStatus:X8}";
                response.DialectIndex = 0xFFFF;
            }

            // Set Dialect String
            if (response.DialectIndex != 0xFFFF)
            {
                if (clientDialectsUsed != null && response.DialectIndex < clientDialectsUsed.Length)
                {
                    response.SelectedDialect = clientDialectsUsed[response.DialectIndex];
                }
                else
                {
                    Console.WriteLine($"WARN: Invalid DialectIndex {response.DialectIndex}");
                    response.SelectedDialect = "FAILURE: Invalid DialectIndex";
                    response.DialectIndex = 0xFFFF;
                }
            }
            else if (string.IsNullOrEmpty(response.SelectedDialect) || response.SelectedDialect == "N/A")
            {
                response.SelectedDialect = "FAILURE: No common dialect";
            }

            offset = pEnd; // Ensure offset is after params
            ushort declaredBcc = BitConverter.ToUInt16(smbData, offset); offset += 2;
            int dataStart = offset; int remaining = smbData.Length - dataStart;
            ushort effectiveBcc = (ushort)Math.Min(declaredBcc, (ushort)remaining);
            if (declaredBcc > remaining && remaining > 0)
            {
                Console.WriteLine($"WARN: Declared BCC {declaredBcc} > remaining {remaining}. Using {effectiveBcc}.");
            }
            else if (declaredBcc > 0 && remaining == 0)
            {
                Console.WriteLine($"WARN: Declared BCC {declaredBcc} but no data follows."); effectiveBcc = 0;
            }


            if (effectiveBcc > 0)
            {
                ParseDataBlock(smbData, dataStart, effectiveBcc, wordCount, response);
            }
            return response;
        }

        private static void ParseDataBlock(byte[] d, int dataStartOffset, ushort count, byte wc, NegotiateResponse r)
        {
            int dataEndOffset = dataStartOffset + count;
            bool useExtSec = r.SupportsExtendedSecurity;
            bool useUnicode = r.SupportsUnicode;
            int currentOffset = dataStartOffset;

            // Console.WriteLine($"DEBUG: ParseDataBlock Start - Offset={currentOffset}, Count={count}, WCT={wc}, UseExtSec={useExtSec}, UseUnicode={useUnicode}");

            try
            {
                if (useExtSec)
                {
                    // Handle ExtSec Blob
                    if (count >= 16)
                    {
                        r.SecurityBlob = new byte[count]; Buffer.BlockCopy(d, currentOffset, r.SecurityBlob, 0, count);
                    }
                    else
                    {
                        Console.WriteLine($"WARN: ExtSec blob too short ({count} < 16).");
                    }
                    currentOffset = dataEndOffset; // Assume ExtSec consumes all data
                }
                else // Not Extended Security
                {
                    if (wc == 17)
                    {
                        int actualChallengeLength = 8; // Assume 8 bytes

                        // 1. Read Challenge
                        if (currentOffset + actualChallengeLength <= dataEndOffset)
                        {
                            r.Challenge = new byte[actualChallengeLength];
                            Buffer.BlockCopy(d, currentOffset, r.Challenge, 0, actualChallengeLength);
                            currentOffset += actualChallengeLength; // Move past challenge
                            // Console.WriteLine($"DEBUG: Read challenge ({actualChallengeLength} bytes assumed), new offset {currentOffset}");
                        }
                        else
                        {
                            Console.WriteLine($"WARN: Not enough data ({count}) for assumed 8-byte challenge. Skipping."); currentOffset = dataEndOffset;
                        }

                        // 2. Extract Strings if data remains
                        if (currentOffset < dataEndOffset)
                        {
                            int remainingDataLength = dataEndOffset - currentOffset;
                            // Console.WriteLine($"DEBUG: Attempting to extract strings from offset {currentOffset}, remaining length {remainingDataLength}");

                            // Extract all consecutive null-terminated strings
                            List<string> foundStrings = ExtractStrings(d, currentOffset, remainingDataLength, useUnicode);

                            if (foundStrings.Count > 0)
                            {
                                r.DomainName = foundStrings[0];
                                // Console.WriteLine($"DEBUG: Found Domain (String 1): '{r.DomainName}'");
                            }
                            else
                            {
                                Console.WriteLine($"WARN: Could not extract Domain Name string after offset {currentOffset}");
                            }

                            if (foundStrings.Count > 1)
                            {
                                r.ServerName = foundStrings[1];
                                // Console.WriteLine($"DEBUG: Found ServerName (String 2): '{r.ServerName}'");
                            }
                            else if (foundStrings.Count == 1) { Console.WriteLine($"WARN: Found Domain Name but could not extract Server Name string."); }

                            // We can't reliably know the exact end offset after string extraction due to padding variance
                            // For simplicity, just mark the rest of the block as conceptually consumed.
                            currentOffset = dataEndOffset;
                        }
                    }
                    else { Console.WriteLine($"WARN: Data block present (count={count}) but WCT={wc}!=17 and not ExtSec."); currentOffset = dataEndOffset; }
                } // End else (Not Extended Security)
            }
            catch (Exception ex) { Console.WriteLine($"ERROR parsing data block: {ex.Message}"); }

            // Final offset checks are less reliable now, maybe remove or adjust warning
            if (currentOffset < dataEndOffset && !(wc == 17 && !useExtSec)) { Console.WriteLine($"WARN: {dataEndOffset - currentOffset} bytes potentially remaining in data block after parsing (ExtSec or WCT!=17)."); }
            // else if (currentOffset > dataEndOffset) { Console.WriteLine($"ERROR: Parsed beyond data block boundary! Offset={currentOffset}, End={dataEndOffset}"); } // Should not happen
        }

        // --- Helper to find and extract consecutive strings ---
        private static List<string> ExtractStrings(byte[] buffer, int startIndex, int count, bool useUnicode)
        {
            var strings = new List<string>();
            int currentOffset = startIndex;
            int searchEndIndex = Math.Min(startIndex + count, buffer.Length);
            Encoding enc = useUnicode ? Encoding.Unicode : Encoding.ASCII;
            int inc = useUnicode ? 2 : 1;

            while (currentOffset < searchEndIndex)
            {
                // 1. Find the start of a potential string (first non-null character/pair)
                int stringStartIndex = -1;
                int scanOffset = currentOffset; // Use a separate offset for scanning padding
                while (scanOffset < searchEndIndex)
                {
                    if (inc == 2)
                    { // Unicode check
                        if (scanOffset + 1 < searchEndIndex)
                        {
                            if (buffer[scanOffset] != 0x00 || buffer[scanOffset + 1] != 0x00)
                            {
                                stringStartIndex = scanOffset; break;
                            } // Found start
                            scanOffset += inc; // Skip null pair
                        }
                        else
                        {
                            scanOffset = searchEndIndex; break;
                        } // End of buffer
                    }
                    else
                    { // ASCII check
                        if (buffer[scanOffset] != 0x00) { stringStartIndex = scanOffset; break; } // Found start
                        scanOffset += inc; // Skip null byte
                    }
                }

                if (stringStartIndex == -1)
                {
                    break; // No more non-null data found
                }

                // 2. Find the null terminator for this string
                int remaining = searchEndIndex - stringStartIndex;
                int stringEndIndex = FindNullTerminator(buffer, stringStartIndex, remaining, inc);

                if (stringEndIndex != -1)
                {
                    // 3. Extract the string
                    int stringLen = stringEndIndex - stringStartIndex;
                    if (stringLen > 0)
                    {
                        try
                        {
                            string extracted = enc.GetString(buffer, stringStartIndex, stringLen);
                            strings.Add(extracted);
                            // Console.WriteLine($"DEBUG ExtractStrings: Extracted '{extracted}' from {stringStartIndex} (len {stringLen})");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"ERROR ExtractStrings: Failed GetString from {stringStartIndex} (len {stringLen}): {ex.Message}");
                            // Optionally dump hex of the failing section
                            int dumpLen = Math.Min(stringLen + inc, buffer.Length - stringStartIndex);
                            Console.WriteLine($"ERROR ExtractStrings: Hex data - {BitConverter.ToString(buffer, stringStartIndex, dumpLen).Replace("-", "")}");
                            break; // Stop if decoding fails
                        }
                    }
                    else
                    {
                        Console.WriteLine($"DEBUG ExtractStrings: Found empty string at offset {stringStartIndex}");
                    }

                    currentOffset = stringEndIndex + inc; // Move past the found string and its terminator for the next iteration
                }
                else
                {
                    Console.WriteLine($"WARN ExtractStrings: String started at {stringStartIndex} but no null terminator found within remaining {remaining} bytes.");
                    break; // Stop searching
                }
            }
            return strings;
        }

        private static int FindNullTerminator(byte[] buffer, int startIndex, int count, int increment)
        {
            if (buffer == null || startIndex < 0 || count <= 0 || increment <= 0 || startIndex >= buffer.Length) return -1;
            int searchEndIndex = Math.Min(startIndex + count, buffer.Length); byte nullByte = 0x00;
            for (int i = startIndex; i < searchEndIndex; i += increment)
            {
                if (increment == 2)
                {
                    if (i + 1 < searchEndIndex)
                    {
                        if (buffer[i] == nullByte && buffer[i + 1] == nullByte)
                        {
                            return i;
                        }
                    }
                    else break;
                }
                else
                {
                    if (buffer[i] == nullByte)
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        private static void ParseParameters(byte[] d, int o, byte wc, NegotiateResponse r)
        {
            r.DialectIndex = BitConverter.ToUInt16(d, o); o += 2;

            if (wc >= 1)
            {
                r.SecurityMode = d[o]; o += 1;
            }
            if (wc >= 2)
            {
                r.MaxMpxCount = BitConverter.ToUInt16(d, o); o += 2;
            }
            if (wc >= 3)
            {
                r.MaxNumberVcs = BitConverter.ToUInt16(d, o); o += 2;
            }
            if (wc >= 5)
            {
                r.MaxBufferSize = BitConverter.ToUInt32(d, o); o += 4;
            }
            if (wc >= 7)
            {
                r.MaxRawSize = BitConverter.ToUInt32(d, o); o += 4;
            }
            if (wc >= 9)
            {
                r.SessionKey = BitConverter.ToUInt32(d, o); o += 4;
            }
            if (wc >= 11)
            {
                r.Capabilities = BitConverter.ToUInt32(d, o); o += 4;
            }
            if (wc == 17)
            {
                r.SystemTimeRaw = BitConverter.ToInt64(d, o); o += 8;
                r.ServerTimeZone = BitConverter.ToInt16(d, o); o += 2;
                r.ChallengeLengthParam = d[o]; o += 1;
            }
        }

        private static int CalculateParamBytes(byte wordCount)
        {
            if (wordCount == 0)
            {
                return 0;
            }
            int bytes = 0;
            // :(
            if (wordCount >= 1) bytes += 2;
            if (wordCount >= 1) bytes += 1;
            if (wordCount >= 2) bytes += 2;
            if (wordCount >= 3) bytes += 2;
            if (wordCount >= 5) bytes += 4;
            if (wordCount >= 7) bytes += 4;
            if (wordCount >= 9) bytes += 4;
            if (wordCount >= 11) bytes += 4;
            if (wordCount == 17) bytes = 34;
            else if (wordCount >= 12)
            {
                bytes = wordCount * 2;
            }
            return bytes;
        }

        /// <summary>
        /// Prepends a 4-byte NetBIOS Session Service header to an SMB message.
        /// Handles lengths up to 0x1FFFF bytes.
        /// </summary>
        /// <param name="smbMessage">The raw SMB message payload.</param>
        /// <returns>A new byte array containing the NBSS header followed by the SMB message.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if smbMessage length exceeds 0x1FFFF.</exception>
        public static byte[] PrependNbssHeader(byte[] smbMessage)
        {
            int length = smbMessage.Length;
            // Maximum length supported by the NBSS Session Message header (0x01FFFF)
            if (length > 0x1FFFF)
            {
                throw new ArgumentOutOfRangeException(nameof(smbMessage), $"SMB message length ({length}) exceeds NBSS maximum (0x1FFFF).");
            }

            // Create the final packet array (4 bytes header + SMB message length)
            byte[] packet = new byte[4 + length];

            // Set NBSS Header fields
            packet[0] = 0x00;                          // Type: Session Message
            packet[1] = (byte)((length >> 16) & 0x01); // Length MSB (only bit 17 used, rest are flags=0)
            packet[2] = (byte)((length >> 8) & 0xFF);  // Length Middle Byte
            packet[3] = (byte)(length & 0xFF);         // Length Low Byte

            // Copy the SMB message payload after the header
            Buffer.BlockCopy(smbMessage, 0, packet, 4, length);

            return packet;
        }

        /// <summary>
        /// Reads a complete SMB message preceded by an NBSS header from the network stream.
        /// Handles timeouts, partial reads, and NBSS Keep Alives.
        /// </summary>
        /// <param name="stream">The NetworkStream to read from.</param>
        /// <returns>Byte array containing the SMB message payload (NBSS header stripped).</returns>
        /// <exception cref="TimeoutException">Thrown if a timeout occurs during reading.</exception>
        /// <exception cref="IOException">Thrown for other network errors or premature connection closure.</exception>
        public static byte[] ReadResponse(NetworkStream stream)
        {
            byte[] nbssHeader = new byte[4];
            int headerBytesRead;

            // --- Read NBSS Header ---
            // Maybe split this out into its own method... ?
            try
            {
                int totalHeaderRead = 0;
                DateTime headerStartTime = DateTime.UtcNow;
                // Use half the read timeout for the header, or a default if timeout is 0/infinite
                TimeSpan headerTimeout = TimeSpan.FromMilliseconds(stream.ReadTimeout > 0 ? stream.ReadTimeout / 2 : 7500);

                while (totalHeaderRead < 4)
                {
                    if (DateTime.UtcNow - headerStartTime > headerTimeout)
                    {
                        throw new TimeoutException($"Timeout waiting for NBSS header (wanted 4, got {totalHeaderRead}).");
                    }
                    if (!stream.CanRead)
                    {
                        throw new IOException("Stream is not readable (NBSS header read).");
                    }

                    if (stream.DataAvailable) // Check if data is likely available before blocking read
                    {
                        int bytesReadThisCall = stream.Read(nbssHeader, totalHeaderRead, 4 - totalHeaderRead);
                        if (bytesReadThisCall == 0)
                        {
                            // Connection closed gracefully by peer before header fully sent
                            throw new IOException($"Connection closed prematurely reading NBSS header (got 0 bytes after {totalHeaderRead} received).");
                        }
                        totalHeaderRead += bytesReadThisCall;
                    }
                    else
                    {
                        // No data immediately available, yield CPU briefly
                        Thread.Sleep(25); // Small delay to prevent busy-waiting
                    }
                }
                headerBytesRead = totalHeaderRead; // Should be 4 if loop completes
            }
            catch (IOException ex) when (ex.InnerException is SocketException se && se.SocketErrorCode == SocketError.TimedOut)
            {
                // Catch specific timeout socket error during header read
                throw new TimeoutException("Socket timeout reading NBSS header.", ex);
            }
            catch (IOException ex)
            {
                // Catch other IO errors during header read
                Console.WriteLine($"DEBUG: IOException reading NBSS header: {ex.Message}");
                throw; // Re-throw for higher level handling
            }

            // Should be redundant due to loop, but defensive check
            if (headerBytesRead < 4)
            {
                throw new IOException($"Failed to read complete NBSS header. Only got {headerBytesRead} bytes.");
            }

            // --- Process NBSS Header ---
            if (nbssHeader[0] == 0x85) // NBSS Keep Alive
            {
                Console.WriteLine("WARN: Received NBSS Keep Alive (0x85). Ignoring and reading next packet.");
                return ReadResponse(stream); // Recursive call to read the actual response
            }
            if (nbssHeader[0] != 0x00) // NBSS Session Message
            {
                throw new IOException($"Received unexpected NBSS message type: 0x{nbssHeader[0]:X2}. Expected Session Message (0x00).");
            }

            // Calculate SMB message length from NBSS header
            int smbMessageLength = ((nbssHeader[1] & 0x01) << 16) | (nbssHeader[2] << 8) | nbssHeader[3];
            int declaredLengthForLogging = smbMessageLength;

            if (smbMessageLength < 0) // Should not happen with bitwise ops
            {
                throw new IOException($"Invalid negative SMB message length parsed from NBSS header: {smbMessageLength}");
            }
            if (smbMessageLength == 0)
            {
                Console.WriteLine($"WARN: Received NBSS Session Message with zero length payload.");
                return new byte[0]; // Return empty array, caller decides if this is ok
            }

            // Sanity check length
            const int MAX_REASONABLE_SMB_SIZE = 65535 + 4096; // Allow slightly over 64k
            if (smbMessageLength > MAX_REASONABLE_SMB_SIZE)
            {
                throw new IOException($"Declared SMB message length ({smbMessageLength}) in NBSS header seems excessively large (>{MAX_REASONABLE_SMB_SIZE}). Aborting read.");
            }
            if (smbMessageLength < SMB1_HEADER_SIZE)
            {
                Console.WriteLine($"WARN: Declared SMB length ({smbMessageLength}) is less than SMB header size ({SMB1_HEADER_SIZE}). Might be an error packet.");
            }

            // --- Read SMB Data Payload ---
            byte[] smbData = new byte[smbMessageLength];
            int totalBytesRead = 0;
            DateTime dataStartTime = DateTime.UtcNow;
            // Use the full configured read timeout for the data payload
            TimeSpan dataTimeout = TimeSpan.FromMilliseconds(stream.ReadTimeout > 0 ? stream.ReadTimeout : 15000);

            try
            {
                while (totalBytesRead < smbMessageLength)
                {
                    if (DateTime.UtcNow - dataStartTime > dataTimeout)
                    {
                        // Dump partial data if any was received before timeout
                        if (totalBytesRead > 0)
                        {
                            Console.WriteLine($"Partial Data Hex ({totalBytesRead} bytes): {BitConverter.ToString(smbData, 0, totalBytesRead).Replace("-", "")}");
                        }
                        throw new TimeoutException($"Timeout reading SMB data. Expected {smbMessageLength} bytes, received {totalBytesRead}.");
                    }
                    if (!stream.CanRead)
                    {
                        throw new IOException("Stream is not readable during SMB data read.");
                    }

                    if (stream.DataAvailable)
                    {
                        int currentRead = stream.Read(smbData, totalBytesRead, smbMessageLength - totalBytesRead);
                        if (currentRead == 0)
                        {
                            // Connection closed gracefully
                            if (totalBytesRead < smbMessageLength)
                            {
                                // Closed before all expected bytes received
                                Console.WriteLine($"WARN: Connection closed prematurely while reading SMB data. Expected {smbMessageLength}, got {totalBytesRead}. Returning partial data.");
                                Array.Resize(ref smbData, totalBytesRead); // Return what we got
                            }
                            // Else: full read completed just before close - this is okay
                            break; // Exit loop
                        }
                        totalBytesRead += currentRead;
                    }
                    else
                    {
                        // No data immediately available, yield CPU
                        Thread.Sleep(50); // Longer sleep for data payload reading
                    }
                }
            }
            // Catch specific timeout socket error during data read
            catch (IOException ex) when (ex.InnerException is SocketException se && se.SocketErrorCode == SocketError.TimedOut)
            {
                throw new TimeoutException($"Socket timeout during stream.Read for SMB data. Expected {smbMessageLength}, got {totalBytesRead}.", ex);
            }
            // Catch other IO errors like ConnectionReset
            catch (IOException ex)
            {
                Console.WriteLine($"WARN: IOException during SMB data read: {ex.Message}");
                if (totalBytesRead > 0 && totalBytesRead < smbMessageLength)
                {
                    // Return partial data if error occurred mid-read
                    Console.WriteLine($"Attempting to parse partially received data ({totalBytesRead}/{smbMessageLength}) due to IO error.");
                    Array.Resize(ref smbData, totalBytesRead);
                }
                else if (totalBytesRead == 0)
                {
                    // Rethrow if error happened before any data was read
                    throw;
                }
                // If full data was read despite error, proceed with it
            }

            // Final check in case loop exited unexpectedly (should be rare with above logic)
            if (totalBytesRead < smbMessageLength && !(smbData.Length == totalBytesRead)) // Check if resize already happened
            {
                Console.WriteLine($"WARN: Read ended with mismatch. Expected {smbMessageLength}, received {totalBytesRead}. Array size {smbData.Length}.");
                // Proceeding with potentially partial data if smbData was resized
            }

            // Console.WriteLine($"Received {smbData.Length} SMB bytes (Declared: {declaredLengthForLogging}).");
            return smbData;
        }

        // EternalBlue Stuff
        // --- Tree Connect AndX Request (PingCastle Style) ---
        /// <summary>
        /// Creates an SMBv1 Tree Connect AndX request packet, mimicking the style
        /// used in the PingCastle example code (connecting to IPC$).
        /// Header fields (TID, PID, UID, MID) are copied from the Session Setup response.
        /// </summary>
        /// <param name="sessionSetupResponseSmb">The SMB payload of the successful Session Setup AndX response.</param>
        /// <param name="targetComputerName">The target computer name or IP address.</param>
        /// <returns>Byte array containing the full NBSS + SMB Tree Connect request.</returns>
        public static byte[] CreateTreeConnect(byte[] sessionSetupResponseSmb, string targetComputerName)
        {
            // --- Define fixed parameters and structure elements ---
            const byte WCT = 4;             // Word Count for Tree Connect AndX
            const ushort passwordLength = 1; // Length for the single null-byte password (anonymous)
            string sharePath = $"\\\\{targetComputerName}\\IPC$"; // Target share path
            string serviceType = "?????";   // Service type used in PingCastle example (indicates any type)

            // Use MemoryStream for easier dynamic assembly
            using (var messageStream = new MemoryStream())
            {
                // 1. Write Header Template
                //    Uses fixed Flags2 (0x0128) and placeholders for MID, UID, TID copied later.
                //    PID Low placeholder will also be overwritten by CopySmbHeaderFields.
                byte SMB1_COMMAND_TREE_CONNECT_ANDX = 0x75;
                byte[] headerTemplate = CreateSmbHeader(SMB1_COMMAND_TREE_CONNECT_ANDX, 0, 0);
                messageStream.Write(headerTemplate, 0, headerTemplate.Length);

                // 2. Write Parameters (WCT=4) - 8 bytes
                messageStream.WriteByte(WCT);
                messageStream.WriteByte(0xFF); // AndXCommand: No further commands
                messageStream.WriteByte(0x00); // Reserved
                messageStream.Write(BitConverter.GetBytes((ushort)0), 0, 2); // AndXOffset: 0
                messageStream.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Flags: 0x0000
                messageStream.Write(BitConverter.GetBytes(passwordLength), 0, 2); // Password Length: 1

                // 3. Reserve space for BCC (Byte Count) - 2 bytes
                //    Record the position where BCC should be written later.
                long bccOffsetInStream = messageStream.Position;
                messageStream.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Placeholder BCC [0x00, 0x00]

                // 4. Write Data part (Bytes following the BCC field)
                //    - Password (1 byte null for anonymous)
                //    - Path (ASCII encoded, null terminated)
                //    - Service Type (ASCII encoded, null terminated)

                // Password (single null byte)
                messageStream.WriteByte(0x00);

                // Path (ASCII encoded)
                byte[] pathBytes = Encoding.ASCII.GetBytes(sharePath);
                messageStream.Write(pathBytes, 0, pathBytes.Length);
                messageStream.WriteByte(0x00); // Null terminator for path

                // Service Type (ASCII encoded)
                byte[] serviceBytes = Encoding.ASCII.GetBytes(serviceType);
                messageStream.Write(serviceBytes, 0, serviceBytes.Length);
                messageStream.WriteByte(0x00); // Null terminator for service

                // 5. Calculate actual data length written (which is the BCC value)
                long dataEndOffset = messageStream.Position;
                // BCC = (Position after data) - (Position after BCC field placeholder)
                long bccValueLong = dataEndOffset - (bccOffsetInStream + 2);
                ushort bccValue = (ushort)bccValueLong;

                // Check calculation against formula: 1 (pwd) + (2 ('\\') + nameLen + 6 ('\IPC$'+0)) + (5 ('?????') + 1 (0))
                int nameLen = Encoding.ASCII.GetByteCount(targetComputerName);
                ushort calculatedBcc = (ushort)(1 + 2 + nameLen + 6 + 5 + 1);
                if (bccValue != calculatedBcc)
                {
                    Console.WriteLine($"WARN: Calculated BCC mismatch! Stream calculation={bccValue}, Formula calculation={calculatedBcc}");
                    // Potentially use the formula calculation if more trusted: bccValue = calculatedBcc;
                }

                // 6. Convert stream to byte array
                byte[] smbPayload = messageStream.ToArray();

                // 7. Write the calculated BCC value at the correct offset in the array
                //    Offset = HeaderSize(32) + WCTByte(1) + Params(8) = 41
                long bccWriteOffset = SMB1_HEADER_SIZE + 1 + (WCT * 2); // Calculate offset robustly
                if (bccWriteOffset != bccOffsetInStream)
                {
                    Console.WriteLine($"WARN: BCC offset mismatch! StreamPos={bccOffsetInStream}, Calculated={bccWriteOffset}");
                    // Handle discrepancy if necessary, maybe trust calculated offset
                }
                byte[] bccBytes = BitConverter.GetBytes(bccValue);
                smbPayload[bccWriteOffset] = bccBytes[0];
                smbPayload[bccWriteOffset + 1] = bccBytes[1];

                // 8. Copy dynamic header fields (TID, PID, UID, MID) from previous response
                //    This overwrites the placeholders written in step 1.
                CopySmbHeaderFields(sessionSetupResponseSmb, smbPayload);

                // 9. Prepend NBSS Header and return
                return PrependNbssHeader(smbPayload);
            }
        }

        public static void CopySmbHeaderFields(byte[] responseSmb, byte[] requestSmb)
        {
            if (responseSmb == null || responseSmb.Length < SMB1_HEADER_SIZE || requestSmb == null || requestSmb.Length < SMB1_HEADER_SIZE)
            {
                Console.WriteLine("WARN: Cannot copy PingCastle header fields - invalid array size provided.");
                return;
            }

            // Copy Tree ID (TID) - Offset 24, Length 2
            requestSmb[24] = responseSmb[24];
            requestSmb[25] = responseSmb[25];

            // Copy Process ID Low (PID Low) - Offset 26, Length 2
            requestSmb[26] = responseSmb[26];
            requestSmb[27] = responseSmb[27];

            // Copy User ID (UID) - Offset 28, Length 2
            requestSmb[28] = responseSmb[28];
            requestSmb[29] = responseSmb[29];

            // Copy Multiplex ID (MID) - Offset 30, Length 2
            requestSmb[30] = responseSmb[30];
            requestSmb[31] = responseSmb[31];
        }
    }
}
