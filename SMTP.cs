using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class SMTP
    {
        public static string GetInfo(string ip, int port)
        {
            string theBanner = General.BannerGrab(ip, port);
            string info = ParseBanner(theBanner);
            return info;
        }

        public static string ParseBanner(string smtpBanner)
        {
            string parsedData = "";
            // 220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 19 Oct 2019 16:02:49 +0200
            if (smtpBanner.StartsWith("220") && smtpBanner.Contains("ESMTP"))
            {
                smtpBanner = smtpBanner.Remove(0, 4);
                string serverName = smtpBanner.Substring(0, smtpBanner.IndexOf(" ESMTP"));
                string nameAndDate = smtpBanner.Remove(0, smtpBanner.IndexOf(" ESMTP") + 7); // Remove the space afterwards
                parsedData = "- Server: " + serverName + Environment.NewLine + "- Name And Date: " + nameAndDate;
                return parsedData;
            }
            else
            {
                parsedData = "- Unknown Banner: " + smtpBanner;
            }
            return parsedData;
        }
    }
}
