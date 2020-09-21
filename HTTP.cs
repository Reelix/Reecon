using System;

namespace Reecon
{
    class HTTP //80 / 8080 / 8000
    {
        public static string GetInfo(string target, int port)
        {
            try
            {
                string url = $"http://{target}:{port}/";
                var httpInfo = Web.GetHTTPInfo(url);
                if (httpInfo.AdditionalInfo == "Timeout")
                {
                    return "- Timeout";
                }
                else if (httpInfo == (0, null, null, null, null, null, null))
                {
                    return "";
                }
                string portData = Web.FormatHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert);
                string commonFiles = Web.FindCommonFiles(url);
                if (commonFiles != "")
                {
                    portData += Environment.NewLine + commonFiles;
                }
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
            catch (Exception ex)
            {
                Console.WriteLine("Critical HTTP.GetInfo Error: " + ex.Message);
                return "";
            }
        }
    }
}
