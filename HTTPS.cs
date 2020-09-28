using System;

namespace Reecon
{
    class HTTPS // 443
    {
        public static string GetInfo(string target, int port)
        {
            string url = $"https://{target}:{port}/";
            // Console.WriteLine("GetInfo - GetHTTPInfo");
            var httpInfo = Web.GetHTTPInfo(url);
            if (httpInfo.AdditionalInfo == "Timeout")
            {
                return "- Timeout";
            }
            if (httpInfo == (0, null, null, null, null, null, null))
            {
                return "";
            }
            string portData = Web.FormatHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
            // Console.WriteLine("GetInfo - FindCommonFiles");
            string commonFiles = Web.FindCommonFiles(url);
            if (commonFiles != "")
            {
                portData += Environment.NewLine + commonFiles;
            }
            // Console.WriteLine("GetInfo - TestBaseLF");
            string baseLFI = Web.TestBaseLFI(target, port);
            if (baseLFI != "")
            {
                portData += Environment.NewLine + baseLFI + Environment.NewLine;
            }
            if (portData == "")
            {
                portData = "- No Info Found";
            }
            return portData;
        }
    }
}
