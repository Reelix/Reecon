using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Reecon
{
    internal static class Smb //445
    {
        public static (string PortName, string PortData) GetInfo(string target, int port)
        {
            // if smb2
            // if 2008
            // if 2008 before r2 -- CVE-2009-3103
            string toReturn = "";

            // SMB1
            if (General.SMBv1)
            {
                try
                {
                    toReturn += "- SMBv1 Response" + Environment.NewLine;
                    // Console.WriteLine($"Attempting to connect to {target}:{port}...");
                    using (TcpClient client = new())
                    {
                        client.SendTimeout = 5000;
                        client.ReceiveTimeout = 15000;
                        Task cT = client.ConnectAsync(target, 445);
                        if (!cT.Wait(TimeSpan.FromSeconds(5)))
                        {
                            /* Timeout */
                        }

                        cT.GetAwaiter().GetResult();
                        // Console.WriteLine("Connection successful.");
                        NetworkStream stream = client.GetStream();

                        // --- Stage 1: Negotiate ---
                        // Console.WriteLine("\n--- Stage 1: Sending Negotiate Request ---");
                        byte[] negReq = Smb1_Protocol.CreateNegotiateRequest();
                        stream.Write(negReq, 0, negReq.Length);
                        stream.Flush();
                        // Console.WriteLine("Negotiate request sent.");
                        // Console.WriteLine("Waiting for Negotiate response...");
                        byte[] negotiateResponse = Smb1_Protocol.ReadResponse(stream);
                        if (negotiateResponse.Length < 32)
                        {
                            throw new InvalidDataException("Negotiate response too short.");
                        }

                        if (!(negotiateResponse[4] == 0x72 && negotiateResponse[5] == 0))
                        {
                            uint s = BitConverter.ToUInt32(negotiateResponse, 5);
                            throw new InvalidOperationException($"Negotiate failed: 0x{s:X8}");
                        }

                        // Console.WriteLine("Negotiate successful (basic check).");
                        // Console.WriteLine("---------------------------------");
                        // Console.WriteLine("\n--- PARSED NEGOTIATE RESPONSE (Info Mode) ---");
                        // toReturn += $"-- Negotiate Response Hex ({negotiateResponse.Length} bytes): {BitConverter.ToString(negotiateResponse).Replace("-", "")}" + Environment.NewLine;
                        Smb1_Protocol.NegotiateResponse pResp = Smb1_Protocol.ParseNegotiateResponse(negotiateResponse, Smb1_Protocol.DIALECTS);

                        // Display pResp fields...
                        // toReturn += $"-- MID: {pResp.Mid}" + Environment.NewLine;
                        toReturn += $"-- NTStatus: 0x{pResp.NTStatus:X8} ({(pResp.IsSuccessNegotiation ? "Success/MoreProcessing" : "Failure")})" + Environment.NewLine;
                        toReturn += $"-- Selected Dialect: {pResp.SelectedDialect} (Index: {(pResp.DialectIndex == 0xFFFF ? "N/A" : pResp.DialectIndex.ToString())})" +
                                    Environment.NewLine;
                        // toReturn += $"-- Server Flags2: 0x{pResp.SmbFlags2:X4} (Unicode Supported by Server: {pResp.SupportsUnicode})" + Environment.NewLine; // Use property here
                        toReturn += $"-- Security Mode: {pResp.GetSecurityModeDescription()} (Raw: {pResp.SecurityMode?.ToString("X2") ?? "N/A"})" + Environment.NewLine;
                        // toReturn += $"-- Capabilities: Raw=0x{pResp.Capabilities ?? 0:X8}, ExtSec={pResp.SupportsExtendedSecurity}" + Environment.NewLine;
                        var caps = pResp.GetCapabilityList();
                        if (caps.Count > 0)
                        {
                            toReturn += $"-- Capabilities List: {string.Join(", ", caps)}" + Environment.NewLine;
                        }

                        if (pResp.MaxBufferSize.HasValue)
                        {
                            // toReturn += $"-- Max Buffer Size: {pResp.MaxBufferSize}" + Environment.NewLine;
                        }

                        if (pResp.MaxMpxCount.HasValue)
                        {
                            // toReturn += $"-- Max Mpx Count: {pResp.MaxMpxCount}" + Environment.NewLine;
                        }

                        if (pResp.Challenge != null)
                        {
                            if (pResp.Challenge.Length != 8)
                            {
                                toReturn += $"-- Challenge Length: {pResp.Challenge.Length} (Assumed 8 bytes... But it's not?)" + Environment.NewLine;
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Challenge: Not Present");
                        }

                        if (!string.IsNullOrEmpty(pResp.DomainName))
                        {
                            toReturn += $"-- " + $"Domain Name: {pResp.DomainName}".Recolor(Color.Orange) + Environment.NewLine;
                        }
                        else
                        {
                            Console.WriteLine($"Domain Name: Not Found");
                        }

                        if (!string.IsNullOrEmpty(pResp.ServerName))
                        {
                            toReturn += "-- " + $"Server Name: {pResp.ServerName}".Recolor(Color.Orange) + Environment.NewLine;
                        }
                        else
                        {
                            Console.WriteLine($"Server Name: Not Found");
                        }

                        SMB1_MS17_010.MS17010CheckResult checkResult = SMB1_MS17_010.CheckIfVulnerable(negotiateResponse, stream, target);
                        if (checkResult == SMB1_MS17_010.MS17010CheckResult.LikelyVulnerable)
                        {
                            toReturn += "-- " + "Vulnerable to MS17-010 (Eternal Blue) !".Recolor(Color.Orange) + Environment.NewLine;
                        }
                        else
                        {
                            toReturn += "-- MS17-010 (Eternal Blue) (Nope): " + nameof(SMB1_MS17_010.MS17010CheckResult) + Environment.NewLine;
                        }
                    }
                }
                catch (TimeoutException tex)
                {
                    if (tex.Message == "Parsing an SMB1 Header" || tex.Message.StartsWith("Timeout waiting for NBSS header"))
                    {
                        toReturn += "-- SMBv1 Timed Out" + Environment.NewLine;
                    }
                    else
                    {
                        toReturn += "-- SMBv1 Timed Out in a weird placed: " + tex.Message + Environment.NewLine;
                    }
                    //Console.WriteLine("Error in SMB.cs (Parsing an SMB1 Header): " + ex.Message + "(" + exType + ")");
                }
                catch (Exception ex)
                {
                    string exType = ex.GetType().Name;
                    Console.WriteLine("Error in SMB.cs (Parsing an SMBv1 Header?): " + ex.Message + "(" + exType + ")");
                }
            }

            // SMB2
            try
            {
                using (TcpClient client = new TcpClient(target, 445))
                {
                    NetworkStream stream = client.GetStream();
                    byte[] request = Smb2_Protocol.CreateNegotiateRequest();
                    stream.Write(request, 0, request.Length);
                    byte[] response = Smb2_Protocol.ReadResponse(stream);

                    Smb2_Protocol.NegotiateResponse negotiateResponse = Smb2_Protocol.ParseNegotiateResponse(response.ToArray());
                    
                    // For a nice faketime layout
                    string clockSkew = negotiateResponse.ClockSkew;
                    TimeSpan skewedTimeSpan;
                    bool negativeSkew = clockSkew.StartsWith('-');
                    if (negativeSkew)
                    {
                        // Remove the '-' sign for parsing, then apply it to the TimeSpan
                        string positiveTimeString = clockSkew.Substring(1);
                        // The format still needs to match the structure after the sign
                        string format = @"h\hmm\ms\s";
                        TimeSpan parsedPositive = TimeSpan.ParseExact(positiveTimeString, format, null);
                        skewedTimeSpan = -parsedPositive; // Apply the negative sign
                    }
                    else
                    {
                        // For positive strings, parse directly
                        string format = @"h\hmm\ms\s";
                        skewedTimeSpan = TimeSpan.ParseExact(clockSkew, format, null);
                    }

                    DateTime skewAdjustedDate = DateTime.Now + skewedTimeSpan;
                    
                    
                    // Output format as per nmap :p
                    toReturn += "- SMBv2 Response" + Environment.NewLine;
                    toReturn += "-- Clock Skew: " + negotiateResponse.ClockSkew + Environment.NewLine;
                    toReturn += "-- Date: " + negotiateResponse.SystemTime.ToString("yyyy-MM-ddTHH:mm:ss") + Environment.NewLine;
                    toReturn += "-- Skew Adjusted Date (faketime): " + skewAdjustedDate.ToString("yyyy-MM-ddTHH:mm:ss") + Environment.NewLine;
                    toReturn += "-- Start Date: " + negotiateResponse.StartDate + Environment.NewLine;
                    toReturn += "-- Dialect (Mode): " + negotiateResponse.DialectStr + Environment.NewLine;
                    toReturn += "-- Security Signing: " + negotiateResponse.SigningStatus + Environment.NewLine;
                }
            }
            catch (Exception ex)
            {
                string exType = ex.GetType().Name;
                toReturn += $"- Error in SMB.cs ({exType}): {ex.Message}" + Environment.NewLine;
            }

            if (General.GetOperatingSystem() == General.OperatingSystem.Linux)
            {
                toReturn += Smb.TestAnonymousAccess_Linux(target);
            }
            else
            {
                toReturn += "- Reecon currently lacks testing anonymous SMB Access on Windows (Ironic, I know)";
            }
            toReturn = toReturn.Trim(Environment.NewLine.ToCharArray());
            return ("SMB", toReturn);
        }

        private static string TestAnonymousAccess_Linux(string target)
        {
            if (General.IsInstalledOnLinux("smbclient", "/usr/bin/smbclient"))
            {
                string smbClientItems = "";
                List<string> processResults = General.GetProcessOutput("smbclient", $" -L {target} --no-pass -g"); // null auth
                if (processResults.Count == 1 && processResults[0].Contains("NT_STATUS_ACCESS_DENIED"))
                {
                    return "- No Anonymous Access";
                }
                else if (processResults.Count == 1 && processResults[0].Contains("session setup failed: NT_STATUS_NOT_SUPPORTED"))
                {
                    return "- NTLM Authentication not supported (Probably need some Kerberos Authentication later)";
                }
                else if (processResults.Count == 1 && processResults[0].Contains("NT_STATUS_CONNECTION_DISCONNECTED"))
                {
                    return "- It connected, but instantly disconnected you";
                }
                else if (processResults.Count == 2 && processResults[0] == "Anonymous login successful" && processResults[1] == "SMB1 disabled -- no workgroup available")
                {
                    return "- Anonymous Access Allowed - But No Shares Found";
                }
                else if (processResults.Count >= 1 && processResults[0].Contains("NT_STATUS_IO_TIMEOUT"))
                {
                    return "- Timed out :(";
                }
                foreach (string item in processResults)
                {
                    // type|name|comment
                    if (item.Trim() != "SMB1 disabled -- no workgroup available" && item.Trim() != "Anonymous login successful")
                    {
                        try
                        {
                            string itemType = item.Split('|')[0];
                            string itemName = item.Split('|')[1];
                            string itemComment = item.Split('|')[2];
                            smbClientItems += "- " + itemType + ": " + itemName + " " + (itemComment == "" ? "" : "(" + itemComment.Trim() + ")") + Environment.NewLine;
                            List<string> subProcessResults = General.GetProcessOutput("smbclient", $"//{target}/{itemName} --no-pass -c \"ls\"");
                            if (subProcessResults.Count > 1 && !subProcessResults.Any(x => x.Contains("NT_STATUS_ACCESS_DENIED") || x.Contains("NT_STATUS_OBJECT_NAME_NOT_FOUND")))
                            {
                                smbClientItems += "-- " + $"{itemName} has ls perms - {subProcessResults.Count} items found! -> smbclient //{target}/{itemName} --no-pass".Recolor(Color.Orange) + Environment.NewLine;
                                smbClientItems += "--- To download the entire contents, add -c \"recurse; prompt; mget *\"" + Environment.NewLine;
                            }
                            if (itemType == "IPC" && itemName == "IPC$")
                            {
                                if (itemComment.Contains("Samba Server"))
                                {
                                    smbClientItems += "-- Samba Detected".Recolor(Color.Orange) + Environment.NewLine;
                                    smbClientItems += "-- If version Samba 3.5.0 < 4.4.14/4.5.10/4.6.4, https://www.exploit-db.com/exploits/42084 / msfconsole -x \"use /exploit/linux/samba/is_known_pipename\"" + Environment.NewLine;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            if (ex.Message.Contains("NT_STATUS_IO_TIMEOUT"))
                            {
                                smbClientItems = "-- Timeout - Try later :(" + Environment.NewLine;
                            }
                            else
                            {
                                Console.WriteLine($"SMB.cs - TestAnonymousAccess_Linux - Error: {ex.Message} - Invalid item: {item} - Bug Reelix!");
                            }
                        }
                    }
                }
                return smbClientItems.Trim(Environment.NewLine.ToCharArray());
            }
            else
            {
                return "- Error: Cannot find /usr/bin/smbclient - Please install it".Recolor(Color.Red);
            }
        }

        // https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py
    }
}
