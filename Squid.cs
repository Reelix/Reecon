using System;

namespace Reecon
{
    class Squid // Port 3128
    {
        public static (string Service, string PortInfo) GetInfo(string ip, int port)
        {
            string returnInfo = "";
            string bannerResult = General.BannerGrab(ip, port, "GET cache_object://" + ip + "/menu HTTP/1.0\r\n\r\n");

            // Get the version
            if (bannerResult.Contains("Server: squid"))
            {
                string versionInfo = bannerResult.Remove(0, bannerResult.IndexOf("Server: "));
                // Some use \r\n, Some just use \n
                versionInfo = versionInfo.Substring(0, versionInfo.IndexOf("\n")).Replace("\r", "").Remove(0, 8);
                returnInfo += "- Version: " + versionInfo + Environment.NewLine;
            }
            else
            {
                returnInfo += "- Version: Unknown" + Environment.NewLine;
            }

            // Get useful info
            if (bannerResult.StartsWith("HTTP/1.1 401 Unauthorized") && bannerResult.Contains("ERR_CACHE_MGR_ACCESS_DENIED"))
            {
                returnInfo += "- Password authentication is enabled and a password is required";
            }
            else if (bannerResult.StartsWith("HTTP/1.1 403 Forbidden"))
            {
                returnInfo += "- No unauthorized Cache Manager access" + Environment.NewLine;
            }
            else if (bannerResult.Contains("Cache Manager Interface"))
            {
                returnInfo += "- Unauthorized Cache Mananger Menu access! Bug Reelix to update this!";
            }
            else
            {
                returnInfo += "- Malformed return info - Bug Reelix to update this" + Environment.NewLine + "-- " + bannerResult;
            }
            returnInfo = returnInfo.Trim(Environment.NewLine.ToCharArray());
            return ("Squid", returnInfo);
        }
    }
}
