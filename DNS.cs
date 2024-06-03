using System;
using System.Collections.Generic;

namespace Reecon
{
    class DNS // Port 53
    {
        public static (string, string) GetInfo(string ip, int port)
        {
            // https://raymii.org/s/tutorials/Get_DNS_server_version_and_hide_it_in_BIND.html
            string dnsInfo = "";
            List<string> outputLines = General.GetProcessOutput("nslookup", $"-type=txt -class=chaos version.bind {ip}");
            if (outputLines.Count > 0 && outputLines[0].Trim() == "*** Request to UnKnown timed-out")
            {
                dnsInfo = "- No Info Available";
            }
            else
            {
                bool hasServer = false;
                foreach (string line in outputLines)
                {
                    if (line.StartsWith("Server:"))
                    {
                        dnsInfo += $"- {line}" + Environment.NewLine;
                        hasServer = true;
                    }
                    else if (line.StartsWith("Address:"))
                    {
                        dnsInfo += $"- {line}" + Environment.NewLine;
                    }
                    else if (
                        // Terrible formatting, I know
                        !(line.Trim().Equals("DNS request timed out."))
                        && !(line.Trim().Contains("timeout was") && line.Trim().Contains("seconds"))
                        && !(line.StartsWith("*** Request to") && line.Trim().EndsWith("timed-out"))
                        )
                    {
                        dnsInfo += $"- {line}" + Environment.NewLine;
                    }
                }
                if (hasServer)
                {
                    dnsInfo += $"- Try the following" + Environment.NewLine
                        + "-- nslookup" + Environment.NewLine
                        + "-- server 1.2.3.4 (Address from above)" + Environment.NewLine
                        + "-- set type=any" + Environment.NewLine
                        + "-- ls -d bla.com (Domain from above)" + Environment.NewLine;
                }
            }
            dnsInfo = dnsInfo.Trim(Environment.NewLine.ToCharArray());
            return ("DNS", dnsInfo);
        }
    }
}
