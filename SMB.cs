using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class SMB //445
    {
        public static string GetInfo(string target, int port)
        {
            string toReturn = "";
            toReturn += GetOSDetails(target);
            if (SMB_MS17_010.IsVulnerable(target))
            {
                toReturn += "----> VULNERABLE TO ETERNAL BLUE (MS10-017) <-----" + Environment.NewLine;
            }
            if (General.GetOS() == General.OS.Linux)
            {
                toReturn += SMB.TestAnonymousAccess_Linux(target);
            }
            else
            {
                toReturn += "- Reecon currently lacks SMB Support on Windows (Ironic, I know)";
            }
            return toReturn.Trim(Environment.NewLine.ToCharArray());
        }

        // Taken from: https://github.com/TeskeVirtualSystem/MS17010Test
        private static string GetOSDetails(string target)
        {
            string osDetails = "";
            byte[] negotiateBytes = negotiateProtoRequest();
            byte[] sessionBytes = sessionSetupAndxRequest();
            List<byte[]> bytesToSend = new List<byte[]>() { negotiateBytes, sessionBytes };
            byte[] byteResult = General.BannerGrabBytes(target, 445, bytesToSend);
            var sessionSetupAndxResponse = byteResult.Skip(36).ToArray();
            var nativeOsB = sessionSetupAndxResponse.Skip(9).ToArray();
            var osData = Encoding.ASCII.GetString(nativeOsB).Split('\x00');
            if (osData[0] != "et by peer") // Invalid response that was cut off
            {
                osDetails += "- OS Name: " + osData[0] + Environment.NewLine;
                if (osData.Count() >= 3)
                {
                    osDetails += "- OS Build: " + osData[1] + Environment.NewLine;
                    osDetails += "- OS Workgroup: " + osData[2] + Environment.NewLine;
                }
            }
            return osDetails;
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
                else if (processResults.Count == 2 && processResults[0] == "Anonymous login successful" && processResults[1] == "SMB1 disabled -- no workgroup available")
                {
                    return "- Anonymous Access Allowed - But No Shares Found";
                }
                foreach (string item in processResults)
                {
                    // type|name|comment
                    if (!item.StartsWith("SMB1 disabled"))
                    {
                        string itemType = item.Split('|')[0];
                        string itemName = item.Split('|')[1];
                        string itemComment = item.Split('|')[2];
                        smbClientItems += "- " + itemType + ": " + itemName + " " + (itemComment == "" ? "" : "(" + itemComment + ")") + Environment.NewLine;
                        List<string> subProcessResults = General.GetProcessOutput("smbclient", $"//{target}/{itemName} --no-pass -c \"ls\"");
                        if (subProcessResults.Count > 1)
                        {
                            smbClientItems += $"-- {itemName} has ls perms! -> smbclient //{target}/{itemName} --no-pass" + Environment.NewLine;
                        }
                    }
                }
                return smbClientItems.Trim(Environment.NewLine.ToCharArray());
            }
            else
            {
                return "- Cannot find smbclient :<";
            }
        }

        public static void SMBBrute(string[] args)
        {
            // TODO: This still shows "Success" if:
            // - The username doesn't exist
            // - There is a space in the password
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Console.WriteLine("SMB Brute only currently works in Linux - Heh :p");
                return;
            }
            if (args.Length != 4)
            {
                Console.WriteLine("SMB Brute Usage: reecon -smb-brute IP Userfile Passfile");
                return;
            }
            string ip = args[1];
            string userFile = args[2];
            string passFile = args[3];
            if (!File.Exists(userFile))
            {
                Console.WriteLine("Unable to find UserFile: " + userFile);
                return;
            }
            if (!File.Exists(passFile))
            {
                Console.WriteLine("Unable to find Passfile: " + passFile);
                return;
            }
            List<string> userList = File.ReadAllLines(userFile).ToList();
            List<string> passList = File.ReadAllLines(passFile).ToList();
            foreach (string user in userList)
            {
                foreach (string pass in passList)
                {
                    List<string> outputResult = General.GetProcessOutput("smbclient", @"-L \\\\" + ip + " -U" + user + "%" + pass);
                    outputResult.RemoveAll(x => x.Equals("Unable to initialize messaging context"));
                    string resultItem = outputResult[0];
                    if (resultItem.Contains("NT_STATUS_HOST_UNREACHABLE"))
                    {
                        Console.WriteLine("Error - Unable to contact \\\\" + ip);
                        return;
                    }
                    else if (resultItem.Contains("NT_STATUS_LOGON_FAILURE"))
                    {
                        Console.WriteLine(user + ":" + pass + " - Failed");
                    }
                    else if (resultItem.Contains("NT_STATUS_UNSUCCESSFUL"))
                    {
                        Console.WriteLine("Fatal Error: " + resultItem);
                        return;
                    }
                    else
                    {
                        Console.WriteLine(user + ":" + pass + " - Success!");
                        return;
                    }
                }
            }
            // smbclient -L \\\\10.10.10.172 -USABatchJobs%SABatchJobs

        }

        // https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py
        private static byte[] negotiateProtoRequest()
        {
            byte[] netbios = new byte[]
            {
                0x00, // Message Type
                0x00, 0x00, 0x54 // Length
            };

            byte[] smbHeader = new byte[]
            {
                0xFF, 0x53, 0x4D, 0x42, // 'server_component': .SMB
                0x72,                   // 'smb_command': Negotiate Protocol
                0x00, 0x00, 0x00, 0x00, // 'nt_status'
                0x18,                   // 'flags'
                0x01, 0x28,             // 'flags2'
                0x00, 0x00,             // 'process_id_high'
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 'signature'
                0x00, 0x00,             // 'reserved'
                0x00, 0x00,             // 'tree_id'
                0x2F, 0x4B,             // 'process_id'
                0x00, 0x00,             // 'user_id'
                0xC5, 0x5E              // 'multiplex_id'
            };

            byte[] negotiateProtoRequest = new byte[]
            {
                0x00, // 'word_count'
                0x31, 0x00, // 'byte_count'
                
                // Requested Dialects
                0x02, // 'dialet_buffer_format'
                0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, // 'dialet_name': LANMAN1.0
                
                0x02, // 'dialet_buffer_format'
                0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // 'dialet_name': LM1.2X002

                0x02, // 'dialet_buffer_format'
                0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00, // 'dialet_name3': NT LANMAN 1.0
                
                0x02, // 'dialet_buffer_format'
                0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00 // 'dialet_name4': NT LM 0.12
            };

            return netbios.Concat(smbHeader).Concat(negotiateProtoRequest).ToArray();
        }

        public static byte[] sessionSetupAndxRequest()
        {
            byte[] netbios = new byte[] { 0x00, 0x00, 0x00, 0x63 };
            byte[] smbHeader = new byte[]
            {
                0xFF, 0x53, 0x4D, 0x42,
                0x73,
                0x00, 0x00, 0x00, 0x00,
                0x18,
                0x01, 0x20,
                0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x2F, 0x4B,
                0x00, 0x00,
                0xC5, 0x5E
            };

            byte[] setupAndxRequest = new byte[]
            {
                0x0D,
                0xFF,
                0x00,
                0x00, 0x00,
                0xDF, 0xFF,
                0x02, 0x00,
                0x01, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00,
                0x26, 0x00,
                0x00,
                0x2e, 0x00,
                0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20, 0x32, 0x31, 0x39, 0x35, 0x00,
                0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20, 0x35, 0x2e, 0x30, 0x00,
            };

            return netbios.Concat(smbHeader).Concat(setupAndxRequest).ToArray();
        }
    }
}
