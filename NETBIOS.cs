using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class NETBIOS
    {
        public static string GetInfo(string ip)
        {
            string dnsInfo = GetDNSHostEntry(ip);
            string rpcInfo = GetRPCInfo(ip);
            return dnsInfo + Environment.NewLine + rpcInfo + Environment.NewLine + "- nmap -sC -sV may have some additional information for this port";
        }

        private static string GetDNSHostEntry(string ip)
        {
            string dnsInfo = "";
            // TODO: https://dzone.com/articles/practical-fun-with-netbios-name-service-and-comput
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ip);
                if (entry != null)
                {
                    if (!string.IsNullOrEmpty(entry.HostName))
                    {
                        dnsInfo = "- HostName: " + entry.HostName;
                    }
                    else
                    {
                        dnsInfo = "- Unknown Path GetDNSHostEntry.emptyHostName - Bug Reelix";
                    }
                }
                else
                {
                    dnsInfo = "- Unknown Path GetDNSHostEntry.nullEntry - Bug Reelix";
                }
            }
            catch (Exception ex)
            {
                dnsInfo += "- Unable to get GNSHostEntry: " + ex.Message + Environment.NewLine;
            }
            return dnsInfo;
        }

        private static string GetRPCInfo(string ip)
        {
            string rpcInfo = "";
            if (General.GetOS() == General.OS.Linux)
            {
                if (General.IsInstalledOnLinux("rpcclient", "/usr/bin/rpcclient"))
                {
                    // https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions
                    List<string> enumdomusersList = General.GetProcessOutput("rpcclient", $"-U \"\"%\"\" {ip} -c \"enumdomusers\"");
                    if (enumdomusersList.Count == 0)
                    {
                        rpcInfo = "- Possible anonymous access but no enumdomusers output" + Environment.NewLine;
                        rpcInfo += $"-> rpcclient -U \"\"%\"\" {ip}";
                    }
                    else if (enumdomusersList.Count == 1 && (enumdomusersList[0].Trim() == "result was NT_STATUS_ACCESS_DENIED" || enumdomusersList[0].Trim() == "Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED"))
                    {
                        rpcInfo = "- No Anonamous RPC Access" + Environment.NewLine;
                        // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                        rpcInfo += "-- If you get access -> enumdomusers / queryuser usernameHere / setuserinfo2 userNameHere 23 'newPasswordHere'";
                    }
                    else if (enumdomusersList.Count == 1 && enumdomusersList[0].Trim() == "Cannot connect to server.  Error was NT_STATUS_RESOURCE_NAME_NOT_FOUND")
                    {
                        rpcInfo = "- Cannot connect - Are you sure it's up?";
                    }
                    else if (enumdomusersList.Count > 3)
                    {
                        Console.WriteLine("Found a lot of useful RPC info - Output may take a few seconds longer than expected");
                        rpcInfo = "- User Listing" + Environment.NewLine;
                        foreach (string user in enumdomusersList)
                        {
                            // Console.WriteLine("Debug Output: " + user);
                            // user:[Guest] rid:[0x1f5]
                            string userName = user.Remove(0, user.IndexOf("[") + 1);
                            userName = userName.Substring(0, userName.IndexOf("]"));

                            rpcInfo += "-- " + userName + Environment.NewLine;

                            List<string> infoList = General.GetProcessOutput("rpcclient", $"-U \"\"%\"\" {ip} -c \"queryuser " + userName + "\"");
                            foreach (string info in infoList)
                            {
                                // padding1[0..7]...
                                // logon_hrs[0..21]..
                                if (!info.Contains(":"))
                                {
                                    continue;
                                }
                                string description = info.Substring(0, info.IndexOf(":"));
                                description = description.Trim();
                                string value = info.Remove(0, info.IndexOf(":") + 1);
                                value = value.Trim();
                                if (description == "Full Name" || description == "Home Drive" || description == "Comment" || description == "Description")
                                {
                                    if (value != "")
                                    {
                                        rpcInfo += "--- " + description + ": " + value + Environment.NewLine;
                                    }
                                }
                            }

                        }
                        rpcInfo += "--> rpcclient -> queryuser usernameHere" + Environment.NewLine;
                        // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                        rpcInfo += "--> rpcclient -> setuserinfo2 userNameHere 23 'newPasswordHere'";
                    }
                    else
                    {
                        foreach (string item in enumdomusersList)
                        {
                            Console.WriteLine("Debug Info item: " + item);
                        }
                        rpcInfo = "- Unknown Path GetRPCInfo.smallReturnCount - Bug Reelix";
                    }
                }
                else
                {
                    rpcInfo = " - Cannot find /usr/bin/rpcclient - Please install it";
                }
            }
            else
            {
                rpcInfo = " - No RPC Info - Try run on Linux (rpcclient)";
            }
            return rpcInfo;
        }
    }
}
