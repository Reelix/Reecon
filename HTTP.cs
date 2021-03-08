using System;

namespace Reecon
{
    class HTTP //80 / 8080 / 8000 (Also used for 443, HTTPS)
    {
        public static string GetInfo(string target, int port)
        {
            string result = GetInfoMain(target, port, false);
            return result;
        }

        public static string GetInfoMain(string target, int port, bool isHTTPS)
        {
            try
            {
                string url = "";
                if (isHTTPS)
                {
                    if (port == 443)
                    {
                        url = $"https://{target}/";
                    }
                    else
                    {
                        url = $"https://{target}:{port}/";
                    }
                }
                else
                {
                    if (port == 80)
                    {
                        url = $"http://{target}/";
                    }
                    else
                    {
                        url = $"http://{target}:{port}/";
                    }
                }
                var httpInfo = Web.GetHTTPInfo(url);
                if (httpInfo.AdditionalInfo == "Timeout")
                {
                    return "- Timeout";
                }
                else if (httpInfo == (0, null, null, null, null, null, null, null))
                {
                    return "";
                }
                string portData = Web.FormatHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert, httpInfo.URL);

                if (httpInfo.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    portData += "- Skipping file enumeration due to unauthorized result";
                }
                else
                {
                    string commonFiles = Web.FindCommonFiles(url);
                    if (commonFiles != "")
                    {
                        portData += Environment.NewLine + commonFiles;
                    }
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
