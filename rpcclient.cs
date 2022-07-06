using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class rpcclient
    {
        private static List<string> RunCommand(string ip, string command, bool signing)
        {
            List<string> processOutput = new List<string>();
            if (signing)
            {
                processOutput = General.GetProcessOutput("rpcclient", $"-U \"\"%\"\" {ip} -c \"{command}\"");
            }
            else
            {
                // Xenial = -S
                // processOutput = General.GetProcessOutput("rpcclient", $"-S off -U \"anonymous\"%\"\" {ip} -c \"{command}\"");
                // Jammy = --option=clientsigning=off
                processOutput = General.GetProcessOutput("rpcclient", $"--option=clientsigning=off -U \"anonymous\"%\"\" {ip} -c \"{command}\"");
            }
            return processOutput;
        }


        public static List<string> GetEnumdomusersOutput(string ip, bool signing = true)
        {
            List<string> processOutput = RunCommand(ip, "enumdomusers", signing);
            return processOutput;
        }

        public static List<string> GetLsaenumsidOutput(string ip, bool signing = true)
        {
            List<string> processOutput = RunCommand(ip, "lsaenumsid", signing);
            return processOutput;
        }

        public static List<string> GetLsaqueryOutput(string ip)
        {
            List<string> processOutput = RunCommand(ip, "lsaquery", false);
            return processOutput;
        }

        // Lookupnames

        public class LookupName
        {
            public string Name;
            public string SID;
            public string Type;
        }

        public static List<LookupName> LookupNames(string ip, string namesList, bool signing)
        {
            List<LookupName> lookupList = new List<LookupName>();
            List<string> proccessOutput = GetLookupnamesOutput(ip, namesList, signing);
            foreach (string item in proccessOutput)
            {
                LookupName lookupName = new LookupName();
                lookupName.Name = item.Split(' ')[0];
                lookupName.SID = item.Split(' ')[1];
                lookupName.Type = item.Split(' ')[2];
                lookupList.Add(lookupName);
            }
            return lookupList;
        }

        public static List<string> GetLookupnamesOutput(string ip, string names, bool signing)
        {
            /*
               administrator S-0-0 (UNKNOWN: 8)
               guest S-0-0 (UNKNOWN: 8)
               krbtgt S-0-0 (UNKNOWN: 8)
               root S-1-22-1-0 (User: 1)
               bin S-1-22-1-2 (User: 1)
               none S-1-5-21-978893743-2663913856-222388731-513 (Domain Group: 2)
            */
            List<string> proccessOutput = RunCommand(ip, $"lookupnames {names}", signing);
            return proccessOutput;
        }

        // Lookupsids

        public class LookupSid
        {
            public string SID;
            public string Name;
            public string Type;
        }

        public static List<LookupSid> LookupSids(string ip, List<string> sidList, bool signing)
        {
            List<LookupSid> lookupList = new List<LookupSid>();
            List<string> proccessOutput = GetLookupsidsOutput(ip, sidList, signing);
            foreach (string item in proccessOutput)
            {
                // S-1-22-1-1000 Unix User\fox (1)
                LookupSid lookupSid = new LookupSid();
                lookupSid.SID = item.Split(' ')[0];
                string name = item.Split(' ')[2];
                lookupSid.Name = name.Remove(0, name.LastIndexOf("\\") + 1);
                lookupSid.Type = item.Split(' ')[3].Replace("(", "").Replace(")", "");
                lookupList.Add(lookupSid);
            }
            return lookupList;
        }

        public static List<string> GetLookupsidsOutput(string ip, List<string> sidList, bool signing)
        {
            // Remove invalid sid info from previous commands
            sidList.RemoveAll(x => x.StartsWith("found "));

            // Remove blanks
            sidList.RemoveAll(x => string.IsNullOrEmpty(x));

            string sidListString = string.Join(' ', sidList);
            List<string> proccessOutput = RunCommand(ip, $"lookupsids {sidListString}", signing);

            return proccessOutput;
        }

        public static List<LookupSid> GetSneakySids(string ip, List<string> userSidList, bool signing)
        {
            // Get the unique bases from the users
            List<LookupSid> returnList = new List<LookupSid>();
            List<string> sneakySIDBaseList = new();
            foreach (string sid in userSidList)
            {
                string sneakySIDBase = sid.Substring(0, sid.LastIndexOf("-") + 1);
                if (!sneakySIDBaseList.Contains(sneakySIDBase))
                {
                    sneakySIDBaseList.Add(sneakySIDBase);
                }
            }

            // Generate a sneakySidList from the bases
            List<string> sneakySIDList = new List<string>();
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
                List<LookupSid> sneakySIDLookup = rpcclient.LookupSids(ip, sneakySIDList, signing);
                if (sneakySIDLookup.Count != 0)
                {
                    // Remove non-users
                    sneakySIDLookup.RemoveAll(x => x.Type != "1");
                    foreach (LookupSid sid in sneakySIDLookup)
                    {
                        // Some invalid ones simply have the number itself instead of the name
                        // A bit hacky, but it works
                        if (!int.TryParse(sid.Name, out int toIgnore))
                        {
                            returnList.Add(sid);
                        }
                    }
                }
            }
            return returnList;
        }

        public static List<string> GetSrvinfoOutput(string ip, bool signing = true)
        {
            List<string> processOutput = RunCommand(ip, "srvinfo", signing);
            return processOutput;
        }

        public static string GetQueryuserInfo(string ip, string username)
        {
            string returnInfo = "";
            // Console.WriteLine("Debug Output: " + user);
            // user:[Guest] rid:[0x1f5]
            returnInfo += "-- " + username + Environment.NewLine;

            List<string> infoList = RunCommand(ip, $"queryuser {username}", false);
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
