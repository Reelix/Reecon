using System;

namespace Reecon
{
    class HTTP //80 / 8080 / 8000 (Also used for 443, HTTPS)
    {
        public static string GetInfo(string target, int port)
        {
            string result = GetInfoMain(target, port, false);
            if (result.Contains("Page Text: Client sent an HTTP request to an HTTPS server."))
            {
                // Whoops - HTTPS Server!
                // TODO: This still returns as HTTP instead of HTTPS though - Need to find a way to change it...
                Console.WriteLine("Whoops - HTTPS Server - Not HTTP - Bug Reelix to update this in General.MultiBannerGrab!");
                result = GetInfoMain(target, port, true);
            }
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
                string portData = Web.ParseHTTPInfo(httpInfo.StatusCode, httpInfo.PageTitle, httpInfo.PageText, httpInfo.DNS, httpInfo.Headers, httpInfo.SSLCert, httpInfo.URL);

                // The final Environment.NewLine is stripped from portData, so we need to re-add it
                if (httpInfo.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    portData += Environment.NewLine + "- Skipping file enumeration due to unauthorized result" + Environment.NewLine;
                    portData += $"-- hydra -L users.txt -P passwords.txt -s {port} -f {target} http-get /" + Environment.NewLine;
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
                return portData.TrimEnd(Environment.NewLine.ToCharArray());
            }
            catch (Exception ex)
            {
                Console.WriteLine("Critical HTTP.GetInfo Error: " + ex.Message);
                return "";
            }
        }
    }
}
