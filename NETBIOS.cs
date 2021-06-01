using Pastel;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Reecon
{
    class NETBIOS // TCP 139
    {
        public static string GetInfo(string target, int port)
        {
            string toReturn = "";
            // Console.WriteLine("Running: GetNBStatInfo");
            toReturn += GetNBStatInfo(target); // Uses UDP Port 137
            // Console.WriteLine("Running: GetDNSHostEntry");
            toReturn += GetDNSHostEntry(target);
            // https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
            // The standard (well-known) TCP port number for an SMB/CIFS server is 139, which is the default.
            // Console.WriteLine("Running: GetRPCInfo");
            toReturn += GetRPCInfo(target);
            toReturn += $"- nmap -sC -sV may have some additional information for port {port}";
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
                IPEndPoint senderTest = new(IPAddress.Any, 137);
                EndPoint Remote = (EndPoint)senderTest;

                IPEndPoint ipep = new(IPAddress.Parse(ip), 137);

                Socket server = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

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
                                // This character is invisible and completely breaks layouts on Linux - And I have no idea why
                                Group = Group.Replace(Convert.ToChar(132).ToString(), "");
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
                if (ex.Message != "Name or service not known")
                {
                    dnsInfo += "- Unable to get DNS Host Entry: " + ex.Message + Environment.NewLine;
                }
            }
            return dnsInfo;
        }

        private static string GetRPCInfo(string ip)
        {
            // Beware!
            string rpcInfo = "";
            bool anonAccess = false;
            bool signing = true;
            if (General.GetOS() == General.OS.Linux)
            {
                if (General.IsInstalledOnLinux("rpcclient", "/usr/bin/rpcclient"))
                {
                    // Find the Domain Name
                    // Console.WriteLine("RPC - lsaquery");
                    List<string> domainNameList = rpcclient.GetLsaqueryOutput(ip);
                    domainNameList.RemoveAll(x => !x.StartsWith("Domain Name:"));
                    if (domainNameList.Count == 1)
                    {
                        anonAccess = true;
                        rpcInfo += "- " + domainNameList[0] + Environment.NewLine;
                    }

                    // Server info
                    // Console.WriteLine("RPC - srvinfo");
                    List<string> srvinfoList = rpcclient.GetSrvinfoOutput(ip);
                    bool setNoSigning = false;
                    // If it's denied the first time - Try the no-signing backup
                    if (srvinfoList.Count != 0 && srvinfoList[0].Contains("NT_STATUS_ACCESS_DENIED"))
                    {
                        // noSigning backup!
                        // Console.WriteLine("RPC - srvinfo - noSigning Backup");
                        srvinfoList = rpcclient.GetSrvinfoOutput(ip, false);
                        setNoSigning = true;
                    }
                    if (srvinfoList.Count != 0 && !srvinfoList[0].Contains("NT_STATUS_ACCESS_DENIED") && !srvinfoList[0].Contains("NT_STATUS_LOGON_FAILURE"))
                    {
                        // If it only worked with the no-signing backup - Yay!
                        if (setNoSigning)
                        {
                            Console.WriteLine("Sneaky access found with RPC - This might take a bit longer than planned (Up to 3 minutes)");
                            signing = false;
                        }
                        anonAccess = true;
                        /*
                            MOTUNUI        Wk Sv PrQ Unx NT SNT motunui server (Samba, Ubuntu)
                            platform_id     :       500
                            os version      :       6.1
                            server type     :       0x809a03
                        */
                        rpcInfo += "- srvinfo: " + srvinfoList[0] + Environment.NewLine;
                        // https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
                        if (srvinfoList.Count == 4)
                        {
                            if (srvinfoList[2].Trim().StartsWith("os version"))
                            {
                                string osVersion = srvinfoList[2];
                                osVersion = osVersion.Split(':')[1];
                                osVersion = osVersion.Trim();
                                if (osVersion == "6.1")
                                {
                                    rpcInfo += "- srvinfo (OS): Windows 7 OR Windows Server 2008 (One of the two)" + Environment.NewLine;
                                }
                                else if (osVersion == "6.2")
                                {
                                    rpcInfo += "- srvinfo (OS): Windows 8 OR Windows Server 2012 (One of the two)" + Environment.NewLine;
                                }
                                else if (osVersion == "10.0")
                                {
                                    rpcInfo += "- srvinfo (OS): Windows 10 OR Windows Server 2016 OR Windows Server 2019 (10.0 is very vague)" + Environment.NewLine;
                                }
                                else
                                {
                                    rpcInfo += "- srvinfo (OS): Unknown - ID: " + osVersion + " - Bug Reelix!" + Environment.NewLine;
                                }
                            }
                            else
                            {
                                rpcInfo += "- Weird srvinfo return - Bug Reelix!";
                            }
                        }
                    }

                    // Console.WriteLine("RPC - enumdomusers");
                    List<string> enumdomusersList = rpcclient.GetEnumdomusersOutput(ip, signing);
                    if (enumdomusersList.Count == 0 // Allowed - But no results
                        || enumdomusersList.Count == 1 && enumdomusersList[0].Contains("NT_STATUS_ACCESS_DENIED"))
                    {
                        // Find public SIDs with lsaenumsid
                        // Console.WriteLine("RPC - lsaenumid");
                        List<string> sidList = rpcclient.GetLsaenumsidOutput(ip, signing);
                        if (sidList.Count != 0)
                        {
                            anonAccess = true;
                            rpcInfo += "- Found SIDs" + Environment.NewLine;

                            List<string> sidResolution = rpcclient.GetLookupsidsOutput(ip, sidList, signing);
                            if (sidResolution.Count != 0)
                            {
                                foreach (string result in sidResolution)
                                {
                                    rpcInfo += "-- " + result + Environment.NewLine;
                                }
                            }
                        }

                        // Find sneaky SIDs
                        // Console.WriteLine("RPC - lookupnames");
                        List<string> sneakyNameLookup = rpcclient.GetLookupnamesOutput(ip, "administrator guest krbtgt root bin none", signing);
                        sneakyNameLookup.RemoveAll(x => !x.Contains("(User: "));
                        if (sneakyNameLookup.Count != 0)
                        {
                            anonAccess = true;
                            List<string> sneakySIDBaseList = new();
                            foreach (string name in sneakyNameLookup)
                            {
                                string sneakySID = name.Split(' ')[1];
                                if (!sidList.Contains(sneakySID))
                                {
                                    // Just add the base - We lookup later
                                    string sneakySIDBase = sneakySID.Substring(0, sneakySID.LastIndexOf("-") + 1);
                                    if (!sneakySIDBaseList.Contains(sneakySIDBase))
                                    {
                                        sneakySIDBaseList.Add(sneakySIDBase);
                                    }
                                }
                            }

                            // Needs the base SID to enumerate
                            if (sneakySIDBaseList.Count != 0)
                            {
                                List<string> sneakySIDList = new();
                                foreach (string sneakyBase in sneakySIDBaseList)
                                {
                                    // Low ones are just system names - Can ignore them - Proper ones start from 1000
                                    for (int j = 1000; j <= 1015; j++)
                                    {
                                        sneakySIDList.Add(sneakyBase + j);
                                    }
                                    // Some sneakier ones hiding from 1100 instead
                                    for (int j = 1100; j <= 1115; j++)
                                    {
                                        sneakySIDList.Add(sneakyBase + j);
                                    }
                                    List<string> sneakySIDLookup = rpcclient.GetLookupsidsOutput(ip, sneakySIDList, signing);
                                    if (sneakySIDLookup.Count != 0)
                                    {
                                        // Remove non-users
                                        sneakySIDLookup.RemoveAll(x => !x.Trim().EndsWith("(1)"));
                                        foreach (string lookupResult in sneakySIDLookup)
                                        {
                                            string name = lookupResult.Substring(0, lookupResult.LastIndexOf(" (1)"));

                                            name = name.Remove(0, name.LastIndexOf("\\") + 1);

                                            // Some invalid ones simply have the number itself instead of the name
                                            // A bit hacky, but it works
                                            if (!int.TryParse(name, out int toIgnore))
                                            {
                                                rpcInfo += "-- " + $"Sneaky Username Found: {name}".Pastel(Color.Orange) + Environment.NewLine;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else // Count > 0
                    {
                        string firstItem = enumdomusersList[0];
                        if (firstItem.Contains("user:") && firstItem.Contains("rid:"))
                        {
                            // All is fine
                            if (enumdomusersList.Count >= 3)
                            {
                                Console.WriteLine("Found a lot of useful RPC info - Output may take a few seconds longer than expected");
                            }
                            rpcInfo += "- User Listing" + Environment.NewLine;
                            List<string> usernames = new List<string>();
                            foreach (string user in enumdomusersList)
                            {
                                // user:[fox] rid:[0x3e8]
                                string username = user.Remove(0, user.IndexOf("[") + 1);
                                username = username.Substring(0, username.IndexOf("]"));
                                usernames.Add(username);
                                rpcInfo += rpcclient.GetQueryuserInfo(ip, username);
                            }

                            // See if there are any we're missing

                            // Get the default names list
                            var defaultNames = rpcclient.LookupNames(ip, "administrator guest krbtgt root bin none", signing);

                            // Filter them to only get the users
                            defaultNames = defaultNames.Where(x => x.Type.Contains("User")).ToList();

                            // Get the users SIDs
                            List<string> defaultNameSids = defaultNames.Select(x => x.SID).ToList();

                            // Sneaky sid lookup by the sids
                            var sneakySids = rpcclient.GetSneakySids(ip, defaultNameSids, signing);

                            // Remove the names we already have
                            sneakySids.RemoveAll(x => usernames.Contains(x.Name));

                            // Rest are missed!
                            foreach (var item in sneakySids)
                            {
                                rpcInfo += "-- " + $"Sneaky Username Found: {item.Name}".Pastel(Color.Orange) + Environment.NewLine;
                            }
                            // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                            rpcInfo += "--> rpcclient -> setuserinfo2 userNameHere 23 'newPasswordHere'" + Environment.NewLine;
                        }
                        else if (firstItem == "Cannot connect to server.  Error was NT_STATUS_RESOURCE_NAME_NOT_FOUND")
                        {
                            rpcInfo = "- Cannot connect - Are you sure it's up?" + Environment.NewLine;
                        }
                        else if (firstItem == "Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT")
                        {
                            rpcInfo = "- Cannot connect - It timed out :<" + Environment.NewLine;
                        }
                        else if (firstItem == "Cannot connect to server.  Error was NT_STATUS_CONNECTION_DISCONNECTED")
                        {
                            rpcInfo = "- Cannot connect - It kicks you out instantly" + Environment.NewLine;
                        }
                        else if (firstItem.Contains("was NT_STATUS_ACCESS_DENIED"))
                        {
                            rpcInfo += "- enumdomusers is denied - Probably can't get anything useful" + Environment.NewLine;
                        }
                        else
                        {
                            foreach (string item in enumdomusersList)
                            {
                                Console.WriteLine("Debug Info item: " + item);
                            }
                            rpcInfo = "- Unknown items in NETBIOS.GetRPCInfo - Bug Reelix (Check Debug Info Item output)" + Environment.NewLine;
                        }
                    }
                    if (anonAccess == true)
                    {
                        rpcInfo += "- " + $"Anonymous access permitted! -> rpcclient -U \"\"%\"\" {ip}".Pastel(Color.Orange) + Environment.NewLine;
                    }
                    else
                    {
                        rpcInfo += "- No anonymous RPC access" + Environment.NewLine;
                        // 23 -> https://room362.com/post/2017/reset-ad-user-password-with-linux/
                        rpcInfo += "-- If you get access -> enumdomusers / queryuser usernameHere / setuserinfo2 userNameHere 23 'newPasswordHere'" + Environment.NewLine;
                    }
                }
                else
                {
                    rpcInfo = "- Error: Cannot find /usr/bin/rpcclient - Please install smbclient (Includes it)".Pastel(Color.Red) + Environment.NewLine;
                }
            }
            else
            {
                rpcInfo = "- No RPC Info - Try run on Linux (rpcclient)" + Environment.NewLine;
            }
            return rpcInfo;
        }
    }
}
