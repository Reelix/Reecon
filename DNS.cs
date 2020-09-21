using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class DNS
    {
        public static string GetInfo(string ip, int port)
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
                foreach (string line in outputLines)
                {
                    dnsInfo += $"- {line}" + Environment.NewLine;
                }
            }
            dnsInfo = dnsInfo.Trim(Environment.NewLine.ToCharArray());
            return dnsInfo;
        }
    }
}
