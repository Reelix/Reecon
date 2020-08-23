using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class NETBIOS // 139 (TCP + UDP)
    {
        public static string GetInfo(string ip)
        {
            string toReturn = "";
            toReturn += GetNBStatInfo(ip);
            toReturn += GetDNSHostEntry(ip);
            toReturn += GetRPCInfo(ip);
            toReturn += "- nmap -sC -sV may have some additional information for this port";
            return toReturn;
        }

        public static string GetNBStatInfo(string ip)
        {
            // This code is messy as heck and needs to be cleaned
            // MAC was here, but got nuked
            string toReturn = "";
            byte[] bs = new byte[] { 0x0, 0x00, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x0, 0x0, 0x21, 0x0, 0x1 };
            byte[] Buf = new byte[500];
            string str = "", strHost = "", Host = "", Group = "", User = "", strHex = "";
            int receive;

            try
            {
                IPEndPoint senderTest = new IPEndPoint(IPAddress.Any, 137);
                EndPoint Remote = (EndPoint)senderTest;

                IPEndPoint ipep = new IPEndPoint(IPAddress.Parse(ip), 137);

                Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                // server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout,);
                server.SendTo(bs, bs.Length, SocketFlags.None, ipep);
                server.ReceiveTimeout = 5000;
                receive = server.ReceiveFrom(Buf, ref Remote);
                server.Close();
                string buffStr = ASCIIEncoding.ASCII.GetString(Buf);
                int tem = 0, num = 0;
                bool bAdd = true;
                for (int i = 57; i < 500; i++) //57-72   
                {
                    //end   
                    if (Buf[i] == 0xcc)
                        break;

                    if (Buf[i] == 0x20)
                        bAdd = false;
                    if (bAdd)
                    {
                        str = ((char)Buf[i]).ToString();
                        if (Buf[i] >= ' ') strHost += str;

                        str = ((char)Buf[i]).ToString();
                        strHex += str;
                    }

                    if ((++tem) % 18 == 0)
                    {
                        bAdd = true;
                        if (strHost == "")
                        {
                            num++;
                            break;
                        }

                        if (num == 0 && strHost != "")
                        {
                            Host = strHost;
                            toReturn += "- NETBIOS Name: " + Host + Environment.NewLine;
                            num++;
                        }
                        else
                        {
                            if (Host != strHost && num == 1 && strHost != "")
                            {
                                Group = strHost;
                                toReturn += "- Group: " + Group + Environment.NewLine;
                                num++;
                            }
                            else
                            {
                                if (strHost != Host && strHost != Group && num == 2 && strHost != "")
                                {
                                    User = strHost;
                                    if (User != "__MSBROWSE__")
                                    {
                                        toReturn += "- User: " + User + Environment.NewLine;
                                        num++;
                                    }
                                }
                            }

                        }

                        strHost = "";
                        strHex = "";

                    }

                }
            }
            catch (SocketException ex)
            {
                // Windows                                                                                                                                            // Mono
                if (!ex.Message.StartsWith("A connection attempt failed because the connected party did not properly respond after a period of time") && ex.Message != "Connection timed out")
                //Console.WriteLine(ex.Message);
                {
                    return "Error: " + ex.Message;
                }
            }
            return toReturn;
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
                        dnsInfo = "- HostName: " + entry.HostName + Environment.NewLine;
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
                    else if (enumdomusersList.Count == 1)
                    {
                        string firstItem = enumdomusersList[0];
                        if (firstItem.Contains("user:") && firstItem.Contains("rid:"))
                        {
                            rpcInfo = "- User Listing" + Environment.NewLine;
                            rpcInfo += QueryEnumDomUser(ip, firstItem);
                            // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                            rpcInfo += "- Might as well try a password reset: rpcclient -> setuserinfo2 usernameHere 23 'newPasswordHere'" + Environment.NewLine;
                        }
                        else if (firstItem == "result was NT_STATUS_ACCESS_DENIED" || firstItem == "Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED")
                        {
                            rpcInfo = "- No Anonamous RPC Access" + Environment.NewLine;
                            // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                            rpcInfo += "-- If you get access -> enumdomusers / queryuser usernameHere / setuserinfo2 userNameHere 23 'newPasswordHere'" + Environment.NewLine;
                        }
                        else if (firstItem == "Cannot connect to server.  Error was NT_STATUS_RESOURCE_NAME_NOT_FOUND")
                        {
                            rpcInfo = "- Cannot connect - Are you sure it's up?" + Environment.NewLine;
                        }
                        else if (firstItem == "Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT")
                        {
                            rpcInfo = "- Cannot connect - It timed out :<" + Environment.NewLine;
                        }
                        else
                        {
                            Console.WriteLine("Unknown Path GetRPCInfo.Count1Unknown - Debug Info item: " + enumdomusersList[0].Trim());
                        }
                    }
                    else if (enumdomusersList.Count == 2 || enumdomusersList.Count == 3)
                    {
                        foreach (string item in enumdomusersList)
                        {
                            Console.WriteLine("Debug Info item: " + item);
                        }
                        rpcInfo = "- Unknown Path GetRPCInfo.smallReturnCount - Bug Reelix";
                    }
                    else if (enumdomusersList.Count > 3)
                    {
                        Console.WriteLine("Found a lot of useful RPC info - Output may take a few seconds longer than expected");
                        rpcInfo = "- User Listing" + Environment.NewLine;
                        foreach (string user in enumdomusersList)
                        {
                            rpcInfo += QueryEnumDomUser(ip, user);
                        }
                        // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                        rpcInfo += "--> rpcclient -> setuserinfo2 userNameHere 23 'newPasswordHere'" + Environment.NewLine;
                    }
                    else
                    {
                        Console.WriteLine("GetRPCInfo.FatalError - How'd it even get here???");
                    }
                }
                else
                {
                    rpcInfo = "- Cannot find /usr/bin/rpcclient - Please install it" + Environment.NewLine;
                }
            }
            else
            {
                rpcInfo = "- No RPC Info - Try run on Linux (rpcclient)" + Environment.NewLine;
            }
            return rpcInfo;
        }

        private static string QueryEnumDomUser(string ip, string user)
        {
            string returnInfo = "";
            // Console.WriteLine("Debug Output: " + user);
            // user:[Guest] rid:[0x1f5]
            string userName = user.Remove(0, user.IndexOf("[") + 1);
            userName = userName.Substring(0, userName.IndexOf("]"));

            returnInfo += "-- " + userName + Environment.NewLine;

            List<string> infoList = General.GetProcessOutput("rpcclient", $"-U \"\"%\"\" {ip} -c \"queryuser " + userName + "\"");
            foreach (string info in infoList)
            {
                // padding1[0..7]...
                // logon_hrs[0..21]..
                if (!info.Contains(":"))
                {
                    return returnInfo;
                }
                string description = info.Substring(0, info.IndexOf(":"));
                description = description.Trim();
                string value = info.Remove(0, info.IndexOf(":") + 1);
                value = value.Trim();
                if (description == "Full Name" || description == "Home Drive" || description == "Comment" || description == "Description")
                {
                    if (value != "")
                    {
                        returnInfo += "--- " + description + ": " + value + Environment.NewLine;
                    }
                }
            }
            return returnInfo.Trim(Environment.NewLine.ToCharArray());
        }
    }
}
