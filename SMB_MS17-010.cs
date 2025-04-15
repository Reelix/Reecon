using Reecon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;

namespace Reecon
{
    public class SMB1_MS17_010
    {
        public enum MS17010CheckResult { NotChecked, UnableToDetermine, LikelyPatched, LikelyVulnerable }

        public static MS17010CheckResult CheckIfVulnerable(byte[] negRespSmb, NetworkStream stream, string target)
        {
            SMB1_MS17_010.MS17010CheckResult vulnStatus = SMB1_MS17_010.MS17010CheckResult.NotChecked;
            vulnStatus = SMB1_MS17_010.MS17010CheckResult.UnableToDetermine;

            // --- Stage 2: Session Setup ---
            // Console.WriteLine("\n--- Stage 2: Sending Session Setup AndX Request ---");
            byte[] sessReq = SMB1_MS17_010.CreateSessionSetup(negRespSmb);
            stream.Write(sessReq, 0, sessReq.Length);
            stream.Flush();
            // Console.WriteLine("Session Setup request sent.");
            // Console.WriteLine("Waiting for Session Setup response...");
            byte[] sessRespSmb = SMB1_Protocol.ReadResponse(stream);
            if (sessRespSmb.Length < 32)
            {
                throw new InvalidDataException("Session Setup response too short.");
            }
            if (!SMB1_Protocol.TryParseSmbHeader(sessRespSmb, out uint ssStat, out _, out _, out _, out _, out _))
            {
                throw new InvalidDataException("Failed parse Session Setup resp hdr.");
            }
            // Console.WriteLine($"Session Setup Response: Status=0x{ssStat:X8}");
            if (ssStat != 0 && ssStat != 0xC0000016)
            {
                throw new InvalidOperationException($"Session Setup failed: 0x{ssStat:X8}");
            }
            // Console.WriteLine($"Session Setup successful.");
            // Console.WriteLine("---------------------------------");
            // --- Stage 3: Tree Connect ---
            // Console.WriteLine("\n--- Stage 3: Sending Tree Connect AndX Request (IPC$) ---");
            byte[] treeReq = SMB1_Protocol.CreateTreeConnect(sessRespSmb, target);
            stream.Write(treeReq, 0, treeReq.Length);
            stream.Flush();
            // Console.WriteLine("Tree Connect request sent.");
            // Console.WriteLine("Waiting for Tree Connect response...");
            byte[] treeRespSmb = SMB1_Protocol.ReadResponse(stream);
            if (treeRespSmb.Length < 32)
            {
                throw new InvalidDataException("Tree Connect response too short.");
            }
            if (!SMB1_Protocol.TryParseSmbHeader(treeRespSmb, out uint tcStat, out _, out _, out _, out _, out _))
            {
                throw new InvalidDataException("Failed parse Tree Connect resp hdr.");
            }
            // Console.WriteLine($"Tree Connect Response: Status=0x{tcStat:X8}");
            if (tcStat != 0)
            {
                throw new InvalidOperationException($"Tree Connect failed: 0x{tcStat:X8}");
            }
            // Console.WriteLine($"Tree Connect successful.");
            // Console.WriteLine("---------------------------------");

            // --- Stage 4: The Check Packet ---
            // Console.WriteLine("\n--- Stage 4: Sending PeekNamedPipe Check ---");
            byte[] checkReq = SMB1_MS17_010.CreatePeekNamedPipe(treeRespSmb);
            stream.Write(checkReq, 0, checkReq.Length);
            stream.Flush();
            // Console.WriteLine("Check request sent.");
            // Console.WriteLine("Waiting for Check response...");
            byte[]? checkRespSmb = null;
            uint checkNtStatus = 0xFFFFFFFF;
            try
            {
                /* ReadResponse */
                checkRespSmb = SMB1_Protocol.ReadResponse(stream);
                if (checkRespSmb != null && checkRespSmb.Length >= 32)
                {
                    if (SMB1_Protocol.TryParseSmbHeader(checkRespSmb, out checkNtStatus, out _, out _, out _, out _, out _))
                    {
                        // Nadda - All good!
                    }
                    else
                    {
                        checkNtStatus = 0xFFFFFFFE;
                    }
                }
                else { /* Short/Null response */ }
            }
            catch (TimeoutException)
            {
                Console.WriteLine("Timeout check response.");
                vulnStatus = MS17010CheckResult.UnableToDetermine;
            }
            catch (IOException ioEx) when (ioEx.InnerException is SocketException se && (se.SocketErrorCode == SocketError.ConnectionReset || se.SocketErrorCode == SocketError.ConnectionAborted))
            {
                Console.WriteLine($"Conn reset check ({se.SocketErrorCode})."); vulnStatus = MS17010CheckResult.UnableToDetermine;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error read/parse check: {ex.Message}");
                vulnStatus = MS17010CheckResult.UnableToDetermine;
                checkNtStatus = 0xFFFFFFFA;
            }
            // --- Analyze Status Code / Response ---
            if (vulnStatus == MS17010CheckResult.UnableToDetermine)
            {
                bool sigMatch = false;
                if (checkRespSmb != null && checkRespSmb.Length >= 9)
                {
                    byte cmd = checkRespSmb[4];
                    byte eC = checkRespSmb[5];
                    byte rsv = checkRespSmb[6];
                    byte eH = checkRespSmb[7];
                    byte eL = checkRespSmb[8];
                    // Console.WriteLine($"PC Check Bytes: Cmd=0x{cmd:X2}, ErrClass=0x{eC:X2}, Rsvd=0x{rsv:X2}, ErrHi=0x{eH:X2}, ErrLo=0x{eL:X2}");
                    if (cmd == 0x25 && eC == 0x05 && rsv == 0x02 && eH == 0x00 && eL == 0xC0)
                    {
                        sigMatch = true;
                    }
                }
                if (sigMatch)
                {
                    // Console.WriteLine("PC signature MATCH -> Vulnerable");
                    vulnStatus = MS17010CheckResult.LikelyVulnerable;
                }
                else
                {
                    Console.WriteLine($"PC signature NO MATCH. Status=0x{checkNtStatus:X8}");
                    vulnStatus = MS17010CheckResult.LikelyPatched;
                }
            }
            return vulnStatus;
            /*
            Console.WriteLine("---------------------------------");
            Console.ForegroundColor = vulnStatus switch { MS17010CheckResult.LikelyVulnerable => ConsoleColor.Red, MS17010CheckResult.LikelyPatched => ConsoleColor.Green, _ => ConsoleColor.Yellow };
            Console.WriteLine($"Result: {vulnStatus}"); Console.ResetColor();
            Console.WriteLine("Note: Based on specific PeekNamedPipe error signature.");
            Console.WriteLine("------------------------------------------------------------------");
            */
        }

        // 2.2.4.53 SMB_COM_SESSION_SETUP_ANDX (0x73)
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d902407c-e73b-46f5-8f9e-a2de2b6085a2
        public static byte[] CreateSessionSetup(byte[] negotiateResponseSmb)
        {
            // 1. Determine header fields needed (Flags2 is fixed, others from response)
            SMB1_Protocol.TryParseSmbHeader(negotiateResponseSmb, out _, out _, out ushort respMid, out ushort respUid, out ushort respTid, out _);
            ushort pidLow = 27972; // Keep fixed PID from example? Or copy respPid? PC code copied respPid.
            ushort treeId = respTid; // Will be 0 from negotiate response, but copy anyway
            ushort userId = respUid;

            // 2. Create the header dynamically 
            byte SMB1_COMMAND_SESSION_SETUP_ANDX = 0x73;
            byte[] header = SMB1_Protocol.CreateSmbHeader(SMB1_COMMAND_SESSION_SETUP_ANDX, userId, treeId);

            // Set PID Low (if needed, or if CreateSmbHeader doesn't handle it)
            byte[] pidBytes = BitConverter.GetBytes(pidLow);
            header[26] = pidBytes[0];
            header[27] = pidBytes[1];


            // 3. Define ONLY the hardcoded Parameters + Data part
            byte[] parametersAndData = new byte[] {
                0x0d, // WordCount (1 byte): The value of this field MUST be 0x0D. (0x0D == 13)
                // Words (26 bytes):
                0xff, // AndXCommand (1 byte): This field MUST be either the command code for the next SMB command in the packet or 0xFF.
                0x00, // AndXReserved (1 byte): A reserved field. This MUST be set to 0x00 when this request is sent, and the server MUST ignore this value.
                0x00, 0x00, // AndXOffset (2 bytes): This field is valid only if the AndXCommand field is not set to 0xFF. If AndXCommand is 0xFF, this field MUST be ignored by the server.
                0xdf, 0xff, // MaxBufferSize (2 bytes): The maximum size, in bytes, of the largest SMB message that the client can receive.
                0x02, 0x00, // MaxMpxCount (2 bytes): The maximum number of pending requests supported by the client.
                0x01, 0x00, // VcNumber (2 bytes): The number of this VC (virtual circuit) between the client and the server.
                0x00, 0x00, 0x00, 0x00, // SessionKey (4 bytes): The client MUST set this field to be equal to the SessionKey field in the SMB_COM_NEGOTIATE Response for this SMB connection.
                0x00, 0x00, // OEMPasswordLen (2 bytes): The length, in bytes, of the contents of the SMB_Data.OEMPassword field.
                0x00, 0x00, // UnicodePasswordLen (2 bytes): The length, in bytes, of the contents of the SMB_Data.UnicodePassword field.
                0x00, 0x00, 0x00, 0x00, // Reserved (4 bytes): Reserved. This field MUST be 0x00000000. The server MUST ignore the contents of this field.
                0x40, 0x00, 0x00, 0x00, // Capabilities (4 bytes): The client uses this field to report its own set of capabilities to the server. The client capabilities are a subset of the server capabilities
                0x26, 0x00, // ByteCount (2 bytes): The number of bytes in the SMB_Data.Bytes array, which follows. (In this case - 38)
                
                // Data - 38 bytes - Really need to document this properly some time...
                0x00, 0x2e, 0x00, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30,
                0x20, 0x32, 0x31, 0x39, 0x35, 0x00, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20,
                0x32, 0x30, 0x30, 0x30, 0x20, 0x35, 0x2e, 0x30, 0x00
            };

            // 4. Combine header and the rest
            List<byte> message = new List<byte>(header.Length + parametersAndData.Length);
            message.AddRange(header);
            message.AddRange(parametersAndData);

            // 5. Prepend NBSS header
            return SMB1_Protocol.PrependNbssHeader(message.ToArray());
        }

        /// <summary>
        /// Creates an SMBv1 TRANS request for PeekNamedPipe.
        /// This is the packet used for the MS17-010 vulnerability check in that style.
        /// Header fields (TID, PID, UID, MID) are copied from the Tree Connect response.
        /// </summary>
        /// <param name="treeConnectResponseSmb">The SMB payload of the successful Tree Connect AndX response.</param>
        /// <returns>Byte array containing the full NBSS + SMB TRANS PeekNamedPipe request.</returns>
        public static byte[] CreatePeekNamedPipe(byte[] treeConnectResponseSmb)
        {
            // 
            // 2.2.5.5.1 - TRANS_PEEK_NMPIPE Request - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/dbafe8f9-5269-472b-bff4-5c2d7f140e34
            //

            // 1. Extract necessary header fields from the Tree Connect response
            // The PID, MID, TID, and UID MUST be the same for all requests and responses that are part of the same transaction.
            // Really need to create a class for this....
            if (!SMB1_Protocol.TryParseSmbHeader(treeConnectResponseSmb, out _, out _, out ushort respMid, out ushort responseUserId, out ushort responseTreeId, out ushort respFlags2))
            {
                // Use defaults/fixed if parsing fails, though this indicates a problem
                Console.WriteLine("WARN: Failed to parse TreeConnect response header for PeekNamedPipe request. Using defaults/fixed values.");
                responseUserId = 0;
                responseTreeId = 0; // This will likely cause the request to fail anyway
            }
            // Need PID low from the response as well (offset 26)
            ushort pidLow = BitConverter.ToUInt16(treeConnectResponseSmb, 26);

            ushort treeId = responseTreeId; // This SHOULD be the actual TID from TreeConnect
            ushort userId = responseUserId;

            // Console.WriteLine($"DEBUG: Creating PeekNamedPipe Request - TID={treeId}, UID={userId}, PIDLow={pidLow}");

            // 2. Create the header dynamically
            // 2.2.4.33.1 - SMB_COM_TRANSACTION Request - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/57bfc115-fe29-4482-a0fe-a935757e0a4f
            byte SMB1_COMMAND_TRANS = 0x25;
            byte[] header = SMB1_Protocol.CreateSmbHeader(SMB1_COMMAND_TRANS, userId, treeId);
            // Set the specific PID Low copied from the response
            byte[] pidBytes = BitConverter.GetBytes(pidLow);
            header[26] = pidBytes[0];
            header[27] = pidBytes[1];

            // 3. Define the hardcoded Parameters + Data part for PeekNamedPipe
            //    This starts *after* the 32-byte header.
            byte[] parametersAndData = new byte[] {
            
            0x10, // Word Count (1 byte): This field MUST be set to 0x10. (0x10 == 16)
            // Words (32 bytes)
            0x00,0x00, // TotalParameterCount (2 bytes): This field MUST be set to 0x0000.
            0x00,0x00, // TotalDataCount (2 bytes): This field MUST be set to 0x0000.
            0xff,0xff, // MaxParameterCount (2 bytes): The maximum number of SMB_Data.Trans_Parameters bytes that the client accepts in the transaction response.
            0xff,0xff, // MaxDataCount (2 bytes): The maximum number of SMB_Data.Trans_Data bytes that the client accepts in the transaction response.
            0x00, // MaxSetupCount (1 byte): This field SHOULD be 0x00.
            0x00, // Reserved1 (1 byte): A padding byte. This field MUST be 0x00.
            0x00,0x00, // Flags (2 bytes): This field SHOULD be set to 0x0000 for this request.
            0x00,0x00,0x00,0x00, // Timeout (4 bytes): The client SHOULD set this field to 0x00000000 to indicate that no time-out is expected. 
            0x00,0x00, // Reserved2 (2 bytes): Reserved. This field MUST be 0x0000 in the client request.
            0x00,0x00, // ParameterCount (2 bytes): This field MUST be set to 0x0000.
            0x4a,0x00, // Parameter Offset: 74 (Relative to SMB Header Start) - This field MUST contain the number of bytes from the start of the SMB Header to the start of the SMB_Data.Trans_Parameters field. 
            0x00,0x00, // DataCount (2 bytes): This field MUST be set to 0x0000.
            0x4a,0x00, // Data Offset: 74 (Relative to SMB Header Start)
            0x02, // SetupCount (1 byte): This field MUST be the number of setup words that are included in the transaction request. This field MUST be set to 0x02 for TRANS_PEEK_NMPIPE
            0x00, // Reserved3 (1 byte): A padding byte. This field MUST be 0x00.
            // Setup Words (4 bytes total)
            0x23,0x00, // Subcommand (2 bytes): This field MUST be set to the transaction subcommand of TRANS_PEEK_NMPIPE (0x0023).
            0x00,0x00, // FID (2 bytes): This field is the FID for the named pipe to read.

            // And back to 2.2.4.33.1
            0x07,0x00, // ByteCount (2 bytes): The number of bytes in the Bytes array that follows. (7 in this case)
            // Data - 7 bytes
            0x5c,0x50,0x49,0x50,0x45,0x5c,0x00 // Transaction Name: \PIPE\ (Null Terminated ASCII)
        };

            // 4. Combine header and the rest
            List<byte> message = new List<byte>(header.Length + parametersAndData.Length);
            message.AddRange(header);
            message.AddRange(parametersAndData);

            // 5. Prepend NBSS header
            return SMB1_Protocol.PrependNbssHeader(message.ToArray());
        }
    }
}